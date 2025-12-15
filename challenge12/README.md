# Challenge 12

## Description

```
Earlier this season, you pulled off a holiday miracle by helping Santa compute the legendary Naughty-or-Nice List from scratch.
With Christmas approaching, Santa sat down to perform his time-honored ritual:
check the list once, then check it again.

But this year, both checks led to the same unsettling result.

Instead of the tidy columns of names and verdicts he expected, Santa found the list filled with unreadable, unintelligible… stuff.
Not names. Not classifications. Not even coal-worthy scribbles.
Just sheer, bewildering nonsense.

The elves are whispering about misaligned enchantments.
Rudolph blames a “data blizzard.”
Santa insists he followed the procedure correctly, which only raises more questions.

One thing’s clear:

🎅 The list you computed is there — it’s just not making sense to anyone yet.

Now it’s up to you to dig into the underlying structure, figure out what the list should say, and help Santa restore order before the sleigh leaves the hangar.

Because if Santa checks it a third time and it’s still nonsense…
Christmas may get cancelled this year.

Only you can save Christmas!
```

## Analysis

This challenge is similar to [Challenge 1](../challenge1), except that it has a
bit more complexity and extra steps.

First, the code runs in a VM, we pass it a folder path and it treats all the
files in those folders as inputs to binaries. The binaries come from
`/challenge/naughty-or-nice`, where each challenge is a binary similar to the
one in challenge1, except they use AVX instructions to make modifications in
blocks of 32 bytes.

Here is the `run` script, the flag is only printed if all the binaries return 0
(basically if we provide the right input for all of them):

```bash
#!/usr/bin/exec-suid -- /bin/bash -p

set -euo pipefail
umask 077

if [ "$#" -ne 1 ]; then
    echo "usage: $0 <list>" >&2
    exit 1
fi

LIST_SRC="$1"
if [ ! -d "$LIST_SRC" ]; then
    echo "error: list must be a directory" >&2
    exit 1
fi

LOG_FILE="$(mktemp)"
cleanup() { rm -f "$LOG_FILE"; }
trap cleanup EXIT

if ! qemu-system-x86_64 \
    -machine accel=tcg \
    -cpu max \
    -m 512M \
    -nographic \
    -no-reboot \
    -kernel /boot/vmlinuz \
    -initrd /boot/initramfs.cpio.gz \
    -append "console=ttyS0 quiet panic=-1 rdinit=/init" \
    -fsdev local,id=list_fs,path="$LIST_SRC",security_model=none \
    -device virtio-9p-pci,fsdev=list_fs,mount_tag=list \
    -serial stdio \
    -monitor none | tee "$LOG_FILE"; then
    echo "error: VM execution failed" >&2
    exit 1
fi

if grep -q "NAUGHTY" "$LOG_FILE"; then
    exit 1
fi

if ! grep -q "NICE" "$LOG_FILE"; then
    exit 1
fi

cat /flag
```

Let's look at the disassembly of one of these binaries

```
/challenge/naughty-or-nice/003b1327b890496084b50be689fb88b9818f1d220060fb98f549dec133afc353:     file format elf64-x86-64


Disassembly of section .text:

<.text>:
        mov    rbp,rsp
        sub    rsp,0x200
        mov    eax,0x0
        mov    edi,0x0
        lea    rsi,[rbp-0x100]
        mov    edx,0x100
        syscall ; input is 0x100 bytes
        vmovdqu ymm0,YMMWORD PTR [rbp-0x80]
        vmovdqu ymm1,YMMWORD PTR [rip+0x91e9]
        vpaddb ymm2,ymm0,ymm1
        vmovdqu YMMWORD PTR [rbp-0x80],ymm2
        vmovdqu ymm0,YMMWORD PTR [rbp-0x100]
        vpbroadcastb ymm1,BYTE PTR [rip+0xffda]
        vpsubb ymm2,ymm0,ymm1
        vmovdqu YMMWORD PTR [rbp-0x100],ymm2
        vmovdqu ymm0,YMMWORD PTR [rbp-0x100]
        vpbroadcastb ymm1,BYTE PTR [rip+0x12d34]
        vpsubb ymm2,ymm0,ymm1
        vmovdqu YMMWORD PTR [rbp-0x100],ymm2
        vmovdqu ymm0,YMMWORD PTR [rbp-0xe0]
...
        vmovdqu ymm0,YMMWORD PTR [rbp-0x100]
        vmovdqu ymm1,YMMWORD PTR [rip+0x8b2b]
        vpsubb ymm2,ymm0,ymm1
        vmovdqu ymm3,YMMWORD PTR [rip+0x1698f]
        vpblendvb ymm0,ymm0,ymm2,ymm3
...
        vmovdqu YMMWORD PTR [rbp-0x40],ymm2
        vmovdqu ymm0,YMMWORD PTR [rbp-0x100]
        vpcmpeqb ymm1,ymm0,YMMWORD PTR [rip+0x3da]        # 
        vpmovmskb eax,ymm1
        cmp    eax,0xffffffff
        jne ; jump to fail

```

The main operations are: load 32 bytes from the input into a register, load 32
bytes from memory into a register, perform an operation and store the result
back in the input area.

Some variations with respect to challenge 1:

* Instead of using immediate operands, the operands come from memory.
* `vpaddb` and `vpsubb` for add and sub in the entire register.
* `vpbroadcastb` which just takes 1 byte and broadcasts it to the entire register.
* `vpblendvb` which decides which byte to take from either before or after the operation.
* `vpcmpeqb` to compare the register against a given value.

## Solution

We can adapt our first day script (the capstone one) to handle all these cases.

### Memory Acceses.

For challenge1 we already loaded the program into memory, but we didn't provide
a rich API to access individual addresses.

Something like this should work:

```python3
class Memory:
    def __init__(self, initial_memory):
        self._memory = initial_memory

    def read8(self, addr):
        for base, mem in self._memory.items():
            if base <= addr < base+len(mem):
                offset = addr - base
                return mem[offset]

    def readN(self, addr, size):
        res = []
        for i in range(size):
            res.append(self.read8(addr+i))
        return res
```

That said, memory accesses are rip-relative in this challenge, so we need to
keep track of the current rip as we iterate through the instructions.

### Keeping Track of the state.

If we assume that our input memory will _only_ interact with program memory, we
can keep track of all the operations and simplify them as they come.

If we also assume that the memory will only be operated in chunks of 32 bytes
without mixing them, we can have one object to track each 32-byte chunk.

This `Value` class can keep track of which input value it came from, and which
operations are being applied to it.

```python
    class Value:
        def __init__(self, value, index):
            self._value = value
            self._index = index

        def add(self, x):
            data = self._value.copy()
            for i in range(len(x)):
                data[i] += x[i]
            return Value(data, self._index)

        def sub(self, x):
            data = self._value.copy()
            for i in range(len(x)):
                data[i] -= x[i]
            return Value(data, self._index)

        def blend(self, v1, x):
            data = self._value.copy()
            for i in range(len(x)):
                if (x[i]>>7) == 1:
                    data[i] = v1._value[i]

            return Value(data, self._index)


        def cmp(self, x):
            data = self._value.copy()
            for i in range(len(x)):
                data[i] = (x[i] - data[i]) & 0xFF
            return (self._index, data)

indexes = [-0x20, -0x40, -0x60, -0x80, -0xa0, -0xc0, -0xe0, -0x100]
values = {key: Value([0]*32, key) for key in indexes}
```

We can also keep track of what value is in each register. It can either be an
object of type `Value`, or an array of bytes.

Finally, when we perform a comparison, we also keep track of that.

### Reading and Writing Data
For example, when we encounter a `vmovdqu` instructions, we can handle it this way:

```python
            case "vmovdqu":
                (op0, op1) = inst.operands
                if op0.type == X86_OP_MEM:
                    # Writing data to memory.
                    assert op0.mem.base == X86_REG_RBP
                    assert op1.type == X86_OP_REG
                    offset = op0.mem.disp
                    values[offset] = registers[op1.reg]
                elif op0.type == X86_OP_REG:
                    register = op0.reg
                    assert op1.type == X86_OP_MEM
                    offset = op1.mem.disp
                    if op1.mem.base == X86_REG_RBP:
                        registers[register] = values[offset]
                    elif op1.mem.base == X86_REG_RIP:
                        addr = next_rip + offset
                        data = memory.readN(addr, 32)
                        registers[register] = data
                    else:
                        raise ValueError("Unreachable")
                else:
                    raise ValueError("Unreachable")
```

If we are writing to memory, we update the `values` array to have the contents
of the register we are writing. If we are reading from memory, we either read a
`Value` object from `values`, or we read a byte array from the main memory.

The broadcasts are also handled in a similar way.

```python
            case "vpbroadcastb":
                op0, op1 = inst.operands
                assert op0.type == X86_OP_REG
                assert op1.type == X86_OP_MEM
                assert op1.mem.base == X86_REG_RIP
                offset = op1.mem.disp
                dst = op0.reg
                address = next_rip + offset
                data = [memory.read8(address)] * 32
                registers[dst] = data
```

### Additions, Substractions and Blends.
Doing additions and substractions is trivial now:

```python
            case "vpsubb":
                assert all([op.type == X86_OP_REG for op in inst.operands])
                op0, op1, op2 = inst.operands
                registers[op0.reg] = registers[op1.reg].sub(registers[op2.reg])
            case "vpaddb":
                assert all([op.type == X86_OP_REG for op in inst.operands])
                op0, op1, op2 = inst.operands
                registers[op0.reg] = registers[op1.reg].add(registers[op2.reg])
```

We just update the appropriate register with the result of performing the
operation in the given value. This will crash if we ever try to perform an
addition into something that is not a `Value`.

Blends are also easy to track, we just need to store the result of the
operation in the corresponding register:

```python
            case "vpblendvb":
                assert all([op.type == X86_OP_REG for op in inst.operands])
                op0, op1, op2, op3 = inst.operands
                reg0, reg1, reg2, reg3 = op0.reg, op1.reg, op2.reg, op3.reg
                registers[reg0] = registers[reg1].blend(registers[reg2], registers[reg3])
```

### Comparisons

Comparisons always happen between one register that holds a `Value` and one
memory operand, we just perform the comparison (which solves the equation) and
store that in our comparisons dictionary.

```python
            case "vpcmpeqb":
                op0, op1, op2 = inst.operands
                assert op0.type == X86_OP_REG
                assert op1.type == X86_OP_REG
                assert op2.type == X86_OP_MEM
                assert op2.mem.base == X86_REG_RIP
                offset = op2.mem.disp
                address = next_rip + offset
                data = memory.readN(address, 32)
                index, data = registers[op1.reg].cmp(data)
                comparisons[index] = data
```

### Payload

At the end, we iterate over all the comparisons that we stored and use that to emit the payload

```python
    payload = bytearray()
    for index in sorted(indexes):
        data = bytearray(comparisons[index])
        payload += data

    payload_path.write_bytes(payload)
```

The full file can be found in [`./challenge12_capstone.py`](./challenge12_capstone.py)

### Running it for all files

We can download all the files from the server, and run this script in parallel
for each of them, naming the payload file with the same name as the challenge
binary that we are solving. After that, we put everything in a folder and mount
that folder for the VM to validate.

When this runs, each of the challenges prints the name of a member that
participated in Advent of Pwn 2025 :)
