#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

constexpr size_t kBufSz = 8192;
char flag_buffer[kBufSz]{0};

char inotify_buffer[kBufSz]
    __attribute__((aligned(__alignof__(struct inotify_event))));

int main(void) {
    int stocking_fd = open("/stocking", O_RDONLY);
    if (stocking_fd == -1) {
        err(EXIT_FAILURE, "open");
    }

    int inotify_fd = inotify_init();
    if (inotify_fd == -1) {
        err(EXIT_FAILURE, "inotify_init");
    }

    // Get notified when the file is closed after writing.
    if (inotify_add_watch(inotify_fd, "/stocking", IN_CLOSE_WRITE) == -1) {
        err(EXIT_FAILURE, "inotify_add_watch");
    }

    // Change our name to "sleep"
    if (prctl(PR_SET_NAME, "sleep") == -1) {
        err(EXIT_FAILURE, "prctl(PR_SET_NAME)");
    }

    // Set niceness to 1
    pid_t pid = getpid();
    if (setpriority(PRIO_PROCESS, pid, 1) == -1) {
        err(EXIT_FAILURE, "setpriority");
    }

    // Wait up to 10 seconds for the file to be written to.
    constexpr size_t kTimeoutMs = 10 * 1000;

    struct pollfd poll_fd{};
    poll_fd.fd = inotify_fd;
    poll_fd.events = POLLIN;

    int poll_ret = poll(&poll_fd, 1, kTimeoutMs);
    if (poll_ret == -1) {
        err(EXIT_FAILURE, "poll");
    }

    if (poll_ret == 0) {
        fprintf(stderr, "Timed out\n");
        exit(EXIT_FAILURE);
    }

    // Read stocking contents.
    ssize_t n = read(stocking_fd, flag_buffer, kBufSz - 1);
    if (n == -1) {
        err(EXIT_FAILURE, "read");
    }
    printf("%s\n", flag_buffer);

    close(stocking_fd);
    close(inotify_fd);

    return 0;
}
