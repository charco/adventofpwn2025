# Challenge 4

## Description

```
Every Christmas Eve, Santa’s reindeer take to the skies—but not through holiday
magic. Their whole flight control stack runs on pure eBPF, uplinked straight
into the North Pole, a massive kprobe the reindeer feed telemetry into
mid-flight. The ever-vigilant eBPF verifier rejects anything even slightly
questionable, which is why the elves spend most of December hunched over
terminals, running llvm-objdump on sleigh binaries and praying nothing in the
control path gets inlined into oblivion again. It’s all very festive, in a
high-performance-kernel-engineering sort of way. Ho ho .ko!
```

## Analysis

In this challenge, there's a background program running, it installs a kprobe
bpf trace to run when the `linkat` syscall is used:

```c
#define _GNU_SOURCE
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <stdbool.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

static volatile sig_atomic_t stop;

static void handle_sigint(int sig)
{
    (void)sig;
    stop = 1;
}

static int libbpf_print_fn(enum libbpf_print_level level,
                           const char *fmt, va_list args)
{
    return vfprintf(stderr, fmt, args);
}

static void broadcast_cheer(void)
{
    libbpf_set_print(libbpf_print_fn);
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    DIR *d = opendir("/dev/pts");
    struct dirent *de;
    char path[64];
    char flag[256];
    char banner[512];
    ssize_t n;

    if (!d)
        return;

    int ffd = open("/flag", O_RDONLY | O_CLOEXEC);
    if (ffd >= 0) {
        n = read(ffd, flag, sizeof(flag) - 1);
        if (n >= 0)
            flag[n] = '\0';
        close(ffd);
    } else {
        strcpy(flag, "no-flag\n");
    }

    snprintf(
        banner,
        sizeof(banner),
        "🎅 🎄 🎁 \x1b[1;31mHo Ho Ho\x1b[0m, \x1b[1;32mMerry Christmas!\x1b[0m\n"
        "%s",
        flag);

    while ((de = readdir(d)) != NULL) {
        const char *name = de->d_name;
        size_t len = strlen(name);
        bool all_digits = true;

        if (len == 0 || name[0] == '.')
            continue;
        if (strcmp(name, "ptmx") == 0)
            continue;

        for (size_t i = 0; i < len; i++) {
            if (!isdigit((unsigned char)name[i])) {
                all_digits = false;
                break;
            }
        }
        if (!all_digits)
            continue;

        snprintf(path, sizeof(path), "/dev/pts/%s", name);
        int fd = open(path, O_WRONLY | O_NOCTTY | O_CLOEXEC);
        if (fd < 0)
            continue;
        write(fd, "\x1b[2J\x1b[H", 7);
        write(fd, banner, strlen(banner));
        close(fd);
    }

    closedir(d);
}

int main(void)
{
    struct bpf_object *obj = NULL;
    struct bpf_program *prog = NULL;
    struct bpf_link *link = NULL;
    struct bpf_map *success = NULL;
    int map_fd;
    __u32 key0 = 0;
    int err;
    int should_broadcast = 0;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    setvbuf(stdout, NULL, _IONBF, 0);

    obj = bpf_object__open_file("/challenge/tracker.bpf.o", NULL);
    if (!obj) {
        fprintf(stderr, "Failed to open BPF object: %s\n", strerror(errno));
        return 1;
    }

    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Failed to load BPF object: %s\n", strerror(-err));
        goto cleanup;
    }

    prog = bpf_object__find_program_by_name(obj, "handle_do_linkat");
    if (!prog) {
        fprintf(stderr, "Could not find BPF program handle_do_linkat\n");
        goto cleanup;
    }

    link = bpf_program__attach_kprobe(prog, false, "__x64_sys_linkat");
    if (!link) {
        fprintf(stderr, "Failed to attach kprobe __x64_sys_linkat: %s\n", strerror(errno));
        goto cleanup;
    }

    signal(SIGINT, handle_sigint);
    signal(SIGTERM, handle_sigint);

    success = bpf_object__find_map_by_name(obj, "success");
    if (!success) {
        fprintf(stderr, "Failed to find success map\n");
        goto cleanup;
    }
    map_fd = bpf_map__fd(success);

    printf("Attached. Press Ctrl-C to quit.\n");
    fflush(stdout);
    while (!stop) {
        __u32 v = 0;
        if (bpf_map_lookup_elem(map_fd, &key0, &v) == 0 && v != 0) {
            should_broadcast = 1;
            stop = 1;
            break;
        }
        usleep(100000);
    }

    if (should_broadcast)
        broadcast_cheer();

cleanup:
    if (link)
        bpf_link__destroy(link);
    if (obj)
        bpf_object__close(obj);
    return err ? 1 : 0;
}
```

The challenge will periodically check in a bpf map for the `success` variable,
and will print the flag in all terminals if it is found with a non-zero value.

The bpf program that's installed can be decompiled with `llvm-objdump`.


This is the `linkat` signature:

```c
int linkat(int olddirfd, const char *oldpath,
                  int newdirfd, const char *newpath, int flags);
```

The bpfprobe will be installed in `__x64_sys_linkat`, which takes a `pt_regs*`
argument with all the syscall arguments and then calls `do_linkat`.

bpf function numbers and documentation can be found in
[`include/uapi/linux/bpf.h`](https://elixir.bootlin.com/linux/v6.18/source/include/uapi/linux/bpf.h#L5870)
and in the [`bpf-helpers` man
page](https://man7.org/linux/man-pages/man7/bpf-helpers.7.html)

```bash
$ llvm-objdump -d --no-show-raw-insn /challenge/tracker.bpf.o | head -n 30

/challenge/tracker.bpf.o:       file format elf64-bpf

Disassembly of section kprobe/__x64_sys_linkat:

0000000000000000 <handle_do_linkat>:
       0:       r6 = *(u64 *)(r1 + 0x70)
       1:       r1 = 0x0
       2:       *(u64 *)(r10 - 0x30) = r1
       3:       *(u64 *)(r10 - 0x38) = r1
       4:       if r6 == 0x0 goto +0x10e <handle_do_linkat+0x898>
       5:       r3 = r6
       6:       r3 += 0x68
       7:       r1 = r10
       8:       r1 += -0x30
       9:       r2 = 0x8
      10:       call 0x71
      11:       r6 += 0x38
      12:       r1 = r10
      13:       r1 += -0x38
      14:       r2 = 0x8
      15:       r3 = r6
      16:       call 0x71
      17:       r3 = *(u64 *)(r10 - 0x30)
      18:       if r3 == 0x0 goto +0x100 <handle_do_linkat+0x898>
      19:       r1 = *(u64 *)(r10 - 0x38)
      20:       if r1 == 0x0 goto +0xfe <handle_do_linkat+0x898>
      21:       r1 = r10
      22:       r1 += -0x28
      23:       r2 = 0x10
```

With this it is possible to reverse-engineer the bpf program. I was a bit
annoyed by the fact that the jmp offsets did not match the instruction numbers,
so I fixed those offsets in python (see
[`fix_challenge4_offsets.py`](./fix_challenge4_offsets.py))

Now, let's analyze the program structure:

```
0000000000000000 <handle_do_linkat>:
       0:       r6 = *(u64 *)(r1 + 0x70)
       1:       r1 = 0x0
       2:       *(u64 *)(r10 - 0x30) = r1
       3:       *(u64 *)(r10 - 0x38) = r1
       4:       if r6 == 0x0 goto +0x10e <handle_do_linkat+0x898> GOTO 275
       5:       r3 = r6
       6:       r3 += 0x68
       7:       r1 = r10
       8:       r1 += -0x30
       9:       r2 = 0x8
      10:       call 0x71
      11:       r6 += 0x38
      12:       r1 = r10
      13:       r1 += -0x38
      14:       r2 = 0x8
      15:       r3 = r6
      16:       call 0x71
```

`r1` is a pointer to a `pt_regs`, and the program reads offset `0x70`. **Note
that this is not the `pt_regs` used by the syscall**. That pointer is in
`rdi`.

`r10` points to the stack, so we clear two eightbytes in the stack.

`rdi` points to the `pt_regs` from the syscall, so the registers will match the
ones from the syscall signature. The call places pointers `0x68` and `0x38`
into the stack variables, by performing a `call 0x71`, which resolves to
`probe_read_kernel`.

These values correspond to the pointers to the userspace strings `oldpath`
(`rsi`) and `newpath` (`r10`), respectively.

Following with the code:

```
      17:       r3 = *(u64 *)(r10 - 0x30)
      18:       if r3 == 0x0 goto +0x100 <handle_do_linkat+0x898> GOTO 275
      19:       r1 = *(u64 *)(r10 - 0x38)
      20:       if r1 == 0x0 goto +0xfe <handle_do_linkat+0x898> GOTO 275
      21:       r1 = r10
      22:       r1 += -0x28
      23:       r2 = 0x10
      24:       call 0x72
      25:       r0 <<= 0x20
      26:       r0 s>>= 0x20
      27:       r1 = 0x1
      28:       if r1 s> r0 goto +0xf6 <handle_do_linkat+0x898> GOTO 275
      29:       r3 = *(u64 *)(r10 - 0x30)
      30:       r1 = r10
      31:       r1 += -0x10
      32:       r2 = 0x10
      33:       call 0x72
      34:       r0 <<= 0x20
      35:       r0 >>= 0x20
      36:       if r0 != 0x7 goto +0xee <handle_do_linkat+0x898> GOTO 275
      37:       r1 = *(u8 *)(r10 - 0x10)
      38:       if r1 != 0x73 goto +0xec <handle_do_linkat+0x898> GOTO 275
      39:       r1 = *(u8 *)(r10 - 0xf)
      40:       if r1 != 0x6c goto +0xea <handle_do_linkat+0x898> GOTO 275
      41:       r1 = *(u8 *)(r10 - 0xe)
      42:       if r1 != 0x65 goto +0xe8 <handle_do_linkat+0x898> GOTO 275
      43:       r1 = *(u8 *)(r10 - 0xd)
      44:       if r1 != 0x69 goto +0xe6 <handle_do_linkat+0x898> GOTO 275
      45:       r1 = *(u8 *)(r10 - 0xc)
      46:       if r1 != 0x67 goto +0xe4 <handle_do_linkat+0x898> GOTO 275
      47:       r1 = *(u8 *)(r10 - 0xb)
      48:       if r1 != 0x68 goto +0xe2 <handle_do_linkat+0x898> GOTO 275
```

The code does a call to `0x72` which is `probe_read_user_str`, reading both
pointers into the stack, at offsets `-0x28` and `-0x10`, respectively.

Afterwards, we compare each byte from the second string with a specific one,
and if we fail, we bail out.

There are multiple comparisons with bytes, and with
[`parse_challenge4_comparisons.py`](./parse_challenge4_comparisons.py) we can
extract that list from the disassembly.

```
['sleigh', 'dasher', 'vixen', 'cupid', 'blitzen', 'dancer', 'comet', 'donner', 'prancer']
```

We get "sleigh` and the name of the reindeers. Following through the
disassembly code you can see that the code jumps around but checks them in
order, increasing a state variable each time. Once we get to the last one, it
signals success.

The order of the reindeers is: Dasher, Dancer, Prancer, Vixen, Comet, Cupid,
Donner, and Blitzen.

```c++
#include <stdint.h>
#include <stdlib.h>
#include <sys/syscall.h> /* Definition of SYS_* constants */
#include <unistd.h>

#include <string>
#include <vector>

int main(void) {
  std::vector<std::string> reindeers = {"dasher", "dancer", "prancer",
                                        "vixen",  "comet",  "cupid",
                                        "donner", "blitzen"};
  for (const auto& reindeer : reindeers) {
          uintptr_t addr = 0;
          syscall(SYS_linkat, addr, "sleigh", addr, reindeer.c_str(), addr);
  }

  return 0;
}
```

Solution can be found in [`./challenge4.cc`](./challenge4.cc)
