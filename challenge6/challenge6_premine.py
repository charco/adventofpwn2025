import hashlib
import json
import string
import random

def hash_block(block):
    block_str = json.dumps(block, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(block_str.encode()).hexdigest()

genesis = {
    "index": 0,
    "prev_hash": "0" * 64,
    "nonce": "",
    "txs": [],
    "nice": None,
}
genesis_hash = hash_block(genesis)


def mine_block(target_block):
    while True:
        current_hash = hash_block(target_block)
        if current_hash.startswith("0000"):
            print(f"[+] Nonce found: {target_block['nonce']}")
            print(f"[+] Hash: {current_hash}")
            print(json.dumps(target_block, indent=2))
            break
        target_block["nonce"] += 1
    return target_block, current_hash

chain = []

# pre-mine blocks with us as nice.
prev_hash = genesis_hash
for i in range(1, 11):
    target_block = {
        "index": i,
        "prev_hash": prev_hash,
        "nonce": 0,
        "txs": [],
        "nice": "hacker",
    }

    target_block, block_hash = mine_block(target_block)
    prev_hash = block_hash
    chain.append(target_block)

# pre-mine regular blocks to make sure we are on top.
for i in range(11, 800):
    target_block = {
        "index": i,
        "prev_hash": prev_hash,
        "nonce": 0,
        "txs": [],
        "nice": None,
    }

    target_block, block_hash = mine_block(target_block)
    prev_hash = block_hash
    chain.append(target_block)

with open("blocks", "wt") as f:
    json.dump(chain, f, indent=2)
