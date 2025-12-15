#!/usr/bin/python3

import re
import subprocess

_PATTERN=r"^\s*([0-9]+):.*goto \+(0x[0-9a-f]+).*$"

res = subprocess.run(["llvm-objdump", "-d", "--no-show-raw-insn", "/challenge/tracker.bpf.o"], check=True, capture_output=True)
lines = res.stdout.decode().splitlines()
comparisons = []
word = []
for line in lines:
    m = re.match(_PATTERN, line)
    goto = ""
    if m is not None:
        line_num = int(m.groups(1)[0])
        offset = int(m.groups(1)[1], 16)
        goto = f" GOTO {line_num + 1 + offset}"
    print(line + goto)
