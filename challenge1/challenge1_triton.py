from absl import app
from absl import logging

from triton import TritonContext, ARCH, Instruction, MemoryAccess, CPUSIZE, MODE, EXCEPTION
import lief
from pathlib import Path

_SYSCALL_OPCODE = b"\x0f\x05"
_JNE_OPCODE = b"\x0f\x85"

# Address where all fail jumps go, extracted from the binary.
_FAIL_ADDR = 0xaa476a

# Threshold for triggering simplifications.
_MAX_NODE_DEPTH = 250

def load_binary(ctx: "TritonContext", binary: lief.ELF):
    phdrs = binary.segments
    for phdr in phdrs:
        size = phdr.physical_size
        vaddr = phdr.virtual_address
        logging.info("[#] Loading 0x%06x - 0x%06x", vaddr, vaddr+size)
        ctx.setConcreteMemoryAreaValue(vaddr, list(phdr.content))

def initialize_state(ctx: TritonContext):
    ctx.concretizeAllMemory()
    ctx.concretizeAllRegister()
    ctx.setConcreteRegisterValue(ctx.registers.rsp, 0x1000000)
    ctx.setConcreteRegisterValue(ctx.registers.rbp, 0x1000000)


def emulate(ctx: TritonContext, pc: int):
    ctx.setConcreteRegisterValue(ctx.registers.rip, pc)
    astCtx = ctx.getAstContext()
    constraints = set()
    seen_constraints = set()
    inst_count = 0
    simplifications = 0
    label2offset = {}
    buffer_size = 0

    while pc:
        pc = ctx.getConcreteRegisterValue(ctx.registers.rip)

        inst = Instruction()
        opcode = ctx.getConcreteMemoryAreaValue(pc, 16)
        # Is it a system call?
        if opcode[:2] == _SYSCALL_OPCODE:
            rax = ctx.getConcreteRegisterValue(ctx.registers.rax)
            rdi = ctx.getConcreteRegisterValue(ctx.registers.rdi)
            rsi = ctx.getConcreteRegisterValue(ctx.registers.rsi)
            rdx = ctx.getConcreteRegisterValue(ctx.registers.rdx)

            # Is it a read syscall from stdin?
            if rax == 0 and rdi == 0:
                base, size = rsi, rdx
                buffer_size = size
                logging.info("Read from stdin into 0x%016x %x bytes", base, size)
                # Mark the memory as symbolic and move on.
                logging.info("Symbolizing range: 0x%016x - 0x%016x", base, base+size)
                for i in range(size):
                    label = f"m[{i}]"
                    ctx.symbolizeMemory(MemoryAccess(base + i, CPUSIZE.BYTE), label)
                    label2offset[label] = i

                ctx.setConcreteRegisterValue(ctx.registers.rip, pc+len(_SYSCALL_OPCODE))
                continue
            # Is it an exit syscall?
            if rax == 0x3c:
                break

        inst.setOpcode(opcode)
        inst.setAddress(pc)
        inst_count += 1

        if inst_count % 3000 == 0:
            logging.info("Processed %d instructions, simplified %d times", inst_count, simplifications)

        res = ctx.processing(inst)
        if res != EXCEPTION.NO_FAULT:
            logging.error("Invalid response %s", res)
            raise ValueError()

        # Is this instruction a JNE?
        if opcode[:2] == _JNE_OPCODE:
            path_constraints = ctx.getPathConstraints()
            for path_constraint in path_constraints:
                srcAddr = path_constraint.getSourceAddress()
                if srcAddr in seen_constraints:
                    continue
                seen_constraints.add(srcAddr)
                assert path_constraint.isMultipleBranches(), "not multiple branches?"

                for branch in path_constraint.getBranchConstraints():
                    if branch["dstAddr"] == _FAIL_ADDR:
                        continue

                    constraints.add(branch["constraint"])
                    ctx.setConcreteRegisterValue(ctx.registers.rip, branch["dstAddr"])
                    logging.info("Branching to: 0x%016x", branch["dstAddr"])
            continue

        # If this is a memory write to our symbolized area, see if we need to simplify it.
        if inst.isMemoryWrite:
            for access in inst.getStoreAccess():
                access = access[0]
                addr = access.getAddress()
                size = access.getSize()
                if size != 1:
                    continue

                sym_expr = ctx.getSymbolicMemory(addr)
                assert sym_expr is not None

                node = sym_expr.getAst()
                if node.getLevel() > _MAX_NODE_DEPTH:
                    opt_node = ctx.simplify(node, solver=True, llvm=False)
                    expr = ctx.newSymbolicExpression(opt_node)
                    ctx.assignSymbolicExpressionToMemory(expr, MemoryAccess(addr, CPUSIZE.BYTE))
                    simplifications += 1

    logging.info("Emulation finished, getting a model")
    models = ctx.getModel(astCtx.land(list(constraints)))
    logging.info("models: %s", models)

    logging.info("Converting solution to payload")
    payload = bytearray([0]) * buffer_size
    for k, v in list(models.items()):
        symVar = ctx.getSymbolicVariable(k)
        value = v.getValue()
        offset = label2offset[symVar.getAlias()]
        payload[offset] = value

    logging.info("Writing payload")
    with open("payload", "wb") as f:
        f.write(payload)


def main(argv):
    del argv
    ctx = TritonContext()

    ctx.setArchitecture(ARCH.X86_64)
    ctx.setMode(MODE.ALIGNED_MEMORY, True)

    binary_path = Path("./check-list")
    binary = lief.parse(binary_path)
    load_binary(ctx, binary)
    initialize_state(ctx)
    emulate(ctx, binary.entrypoint)

if __name__ == "__main__":
    app.run(main)
