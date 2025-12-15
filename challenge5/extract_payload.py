import pwn
from pathlib import Path
from absl import app
from absl import flags

FLAGS = flags.FLAGS

flags.DEFINE_string("binary", "./hello_world", "Path to ELF file")

def main(argv):
    del argv
    pwn.context.arch = "amd64"
    pwn.context.log_level = "error"

    binary_path = Path(FLAGS.binary)
    elf = pwn.ELF(binary_path)
    payload = elf.get_section_by_name(".text.entry").data()
    nopsled = b"\x90" * 100

    with open("payload", "wb") as f:
        f.write(nopsled)
        f.write(payload)

if __name__ == "__main__":
    app.run(main)
