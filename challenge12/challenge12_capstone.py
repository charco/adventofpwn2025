from absl import app
from absl import flags
from absl import logging

from pathlib import Path

import lief
import capstone
from capstone.x86 import *

FLAGS = flags.FLAGS
flags.DEFINE_string("binary_path", None, "Path to the challenge binary")
flags.DEFINE_string("output_path", "output", "Directory path where to store the payload")

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

def load_binary(binary: lief.ELF):
    phdrs = binary.segments
    result = {}
    for phdr in phdrs:
        size = phdr.physical_size
        vaddr = phdr.virtual_address
        logging.info("[#] Loading 0x%06x - 0x%06x", vaddr, vaddr+size)
        result[vaddr] = bytes(phdr.content)
    return result


def main(argv):
    del argv
    binary_path = Path(FLAGS.binary_path)
    output_path = Path(FLAGS.output_path)
    if not output_path.exists():
        output_path.mkdir(parents=True, exist_ok=True)
    payload_path = output_path / binary_path.name
    if payload_path.exists():
        print("Solution already exists, leaving")
        return

    elf = lief.ELF.parse(binary_path)
    loaded_segments = load_binary(elf)
    memory = Memory(loaded_segments)

    logging.info("ELF entrypoint: 0x%016x", elf.entrypoint)

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True

    values = {}
    want = {}
    _IGNORED_INSTRS = ("add", "sub", "mov", "syscall", "lea", "cmp", "jne")
    _ALLOWED_INSTRS = ("vmovdqu", "vpsubb", "vpaddb", "vpbroadcastb", "vpblendvb", "vpmovmskb", "vpcmpeqb")
    ip = elf.entrypoint

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
    registers = {}
    comparisons = {}

    for inst in md.disasm(loaded_segments[elf.entrypoint], elf.entrypoint):
        next_rip = ip + inst.size
        if inst.mnemonic in _IGNORED_INSTRS:
            ip = next_rip
            continue

        if not inst.mnemonic in _ALLOWED_INSTRS:
            raise ValueError()

        match inst.mnemonic:
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
            case "vpsubb":
                assert all([op.type == X86_OP_REG for op in inst.operands])
                op0, op1, op2 = inst.operands
                registers[op0.reg] = registers[op1.reg].sub(registers[op2.reg])
            case "vpaddb":
                assert all([op.type == X86_OP_REG for op in inst.operands])
                op0, op1, op2 = inst.operands
                registers[op0.reg] = registers[op1.reg].add(registers[op2.reg])
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
            case "vpblendvb":
                assert all([op.type == X86_OP_REG for op in inst.operands])
                op0, op1, op2, op3 = inst.operands
                reg0, reg1, reg2, reg3 = op0.reg, op1.reg, op2.reg, op3.reg
                registers[reg0] = registers[reg1].blend(registers[reg2], registers[reg3])
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
            case "vpmovmskb":
                op0, op1 = inst.operands
                assert op0.type == X86_OP_REG
                assert op1.type == X86_OP_REG
                assert op0.reg == X86_REG_EAX
            case _:
                raise ValueError("Unhandled Instruction")
        ip = next_rip

    payload = bytearray()
    for index in sorted(indexes):
        data = bytearray(comparisons[index])
        payload += data

    payload_path.write_bytes(payload)


if __name__ == "__main__":
    app.run(main)
