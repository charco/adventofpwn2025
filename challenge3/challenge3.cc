#include <err.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

constexpr size_t kBufSz = 8192;
char buf[kBufSz]{0};

int main(void) {
  int fd = open("/stocking", O_RDONLY);
  if (fd == -1) {
    err(EXIT_FAILURE, "open");
  }

  system("nice --adjustment=1 sleep 5");

  ssize_t n = read(fd, buf, kBufSz - 1);
  if (n == -1) {
    err(EXIT_FAILURE, "read");
  }
  printf("%s\n", buf);

  close(fd);
  return 0;
}
