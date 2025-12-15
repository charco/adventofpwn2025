from absl import app
from absl import logging

from pathlib import Path

import lief
import capstone
from capstone.x86 import X86_OP_MEM, X86_REG_RBP, X86_OP_IMM

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
    binary_path = Path("./check-list")
    elf = lief.ELF.parse(binary_path)
    memory = load_binary(elf)
    logging.info("ELF entrypoint: 0x%016x", elf.entrypoint)
    assert elf.entrypoint in memory

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True

    values = {}
    want = {}
    logging.info("Disassembling instuctions...")
    for inst in md.disasm(memory[elf.entrypoint], elf.entrypoint):
        if inst.mnemonic not in ("add", "sub", "cmp"):
            continue

        if len(inst.operands) != 2:
            continue

        (op0, op1) = inst.operands

        if op0.type != X86_OP_MEM:
            continue
        if op0.mem.base != X86_REG_RBP:
            continue
        if op1.type != X86_OP_IMM:
            continue

        offset = op0.mem.disp
        value = op1.imm
        insn = inst.mnemonic

        if offset not in values:
            values[offset] = 0

        match inst.mnemonic:
            case "add":
                values[offset] += value
            case "sub":
                values[offset] -= value
            case "cmp":
                want[offset] = value


    # Test: no offsets are missing.
    assert len(values.keys()) == 0x400
    assert abs(max(values.keys()) - min(values.keys()) + 1) == 0x400

    payload = bytearray()

    logging.info("Solving constraints")
    for offset in sorted(values.keys()):
        original_value = (want[offset] - values[offset]) & 0xff
        logging.info("values[%d] | X + %d == %d (mod 256). Solution: %d", offset, values[offset], want[offset], original_value)

        payload.append(original_value)

    logging.info("Writing payload")
    with open("payload", "wb") as f:
        f.write(payload)

if __name__ == "__main__":
    app.run(main)
