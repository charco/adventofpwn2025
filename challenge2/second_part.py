
from pathlib import Path
import re

_PATTERN = rb"pwn\.college{[a-zA-Z0-9_.-]+}"

def main():
    coal_path = Path("./coal")
    assert coal_path.exists()

    regex = re.compile(_PATTERN)
    core_dump = coal_path.read_bytes()
    for match in regex.finditer(core_dump):
        print(match.group().decode())

if __name__ == "__main__":
    main()
