#!/usr/bin/python3

import py_compile
from pathlib import Path

py_file = Path("hello_world.py")
pyc_file = Path("hello_world.pyc")
py_compile.compile(py_file, cfile=pyc_file)

data = pyc_file.read_bytes()

print("uint8_t payload[] = {" + ", ".join(f"0x{b:02x}" for b in data) + "};")
print(f"unsigned int payload_len = {len(data)};")
