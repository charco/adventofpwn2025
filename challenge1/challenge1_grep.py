from absl import app
from absl import logging

from pathlib import Path
import subprocess
import re

_OBJDUMP="objdump"
_PATTERN = r"^\s*(add|cmp|sub)\s*.*PTR\s*\[rbp(-.*)\],(.*)$"

def main(argv):
    del argv
    binary_path = Path("./check-list")

    logging.info("Disassembling the binary %s", binary_path.as_posix())
    res = subprocess.run([_OBJDUMP, "-d", "-Mintel", "--no-addresses", "--no-show-raw-insn", binary_path.as_posix()], check=True, capture_output=True)

    values = {}
    want = {}

    logging.info("Filtering instructions")
    for line in res.stdout.decode().splitlines():
        match = re.search(_PATTERN, line)
        if not match:
            continue

        insn = match.group(1)
        offset = int(match.group(2), 16)
        value = int(match.group(3), 16)

        if offset not in values:
            values[offset] = 0
        
        if insn == "add":
            values[offset] += value
        elif insn == "sub":
            values[offset] -= value
        elif insn == "cmp":
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
