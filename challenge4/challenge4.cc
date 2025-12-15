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
