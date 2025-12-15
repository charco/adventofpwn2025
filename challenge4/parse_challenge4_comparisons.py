hacker@2025~day-04:~$ cat parse_comparisons.py 
#!/usr/bin/python3

import re
import subprocess

_PATTERN=r".*if r1 != (0x[0-9a-f]{2}) goto.*"
_READ_STR_PATTERN=r".*call 0x72.*"

res = subprocess.run(["llvm-objdump", "-d", "--no-show-raw-insn", "/challenge/tracker.bpf.o"], check=True, capture_output=True)
lines = res.stdout.decode().splitlines()
comparisons = []
word = []
for line in lines:
    m = re.match(_READ_STR_PATTERN, line)
    if m is not None:
        if len(word) == 0:
            continue

        comparisons.append("".join(word))
        word = []
        continue

    m = re.match(_PATTERN, line)
    if m is not None:
        c = chr(int(m.groups(1)[0], 16))
        word.append(c)

if word:
    comparisons.append("".join(word))
    word = []

print(comparisons)
