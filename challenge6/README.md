# Challenge 6

## Description

```
🎄 **North-Poole: The Decentralized Spirit of Christmas** 🎄  

For centuries, Santa ruled the holidays with a single, all-powerful Naughty-or-Nice list. One workshop. One sleigh. **One very centralized source of truth.**  

But after years of “mislabeled” children, delayed gifts, and at least one entire village receiving nothing but the string **"AAAAAAAAAA"** due to an unfortunate buffer overflow in the Letter Sorting Department, global trust has melted faster than a snowman in July. The kids are done relying on a jolly single point of failure.  

Now introducing…  

🎁 **NiceCoin™ — the world’s first decentralized, elf-mined, holly-backed virtue token.**  
*Mint your cheer. Secure your joy. Put holiday spirit on the blockchain.*  

Elves now mine blocks recording verified Nice deeds and mint NiceCoins. Children send signed, on-chain letters to request presents, and Santa—bound by transparent, immutable consensus—must follow the ledger. The workshop is running on proof-of-work, mempools, and a very fragile attempt at “trustless” Christmas cheer.  

Ho-ho-hope you’re ready. 🎅🔥
```

## Analysis

The sixth challenge has a bunch of scripts:

```
elf.py
santa.py
north_poole.py
children.py
keys/...
```

The system resembles a crypto blockchain.

`north_poole.py` is a serves as the main node in the blockchain. It has
endpoints to query the current latest block, a block by hash, the transaction
pool and to submit transactions.

`santa.py` is the script that accesses the flag. It looks for all blocks that
have more than 5 confirmations in the blockchain and look at the transactions
in each of them. The transactions of type "letter" contain requests for gifts.
There's a secret password that can be used to request the flag, and you can
requests individual letters of this password with a transaction. There's a
`niceness` score for each person, and you can only receive gifts if you have a
positive niceness score. The score is tracked in the blockchain.

`elf.py` mine blocks with transactions (letters for example), and sometimes
when they mine a block they add 1 niceness to one of the children. There's a
limit of 10 blocks with niceness for a given person.

`children.py` submit transactions to get gifts.

`keys` is a directory that contains private and public keys for verifying
transactions. We have read access to only one set of keys, for the person
`hacker`.

Transactions are signed with a private key (generated upon challenge startup).
They can be submitted directly to the pool, or they can be added to blocks.

The genesis block is static and well-know, it doesn't change upon challenge
restarts. Mining blocks does not require you to sign anything. In order for a
block to be accepted, its hash has to start with 4 zeroes, so it is not that
hard to mine. When you submit a chain, if your chain is larger than other
chains, yours will take priority, and it will replace all the other stuff
(niceness scores for example).

By having the genesis block static, we can pre-mine chains of any length before
starting the challenge. However, we can't add any transactions, as they would
not be signed.

A way to solve the challenge is to send transactions to santa requesting
individual letters from the secret message required to get the flag, and after
collecting the 32 characters, send a letter with that message to request the
flag.

Given the niceness limitations, we can't add niceness to ourselves more than 10
times, however, we can always change the active chain by presenting a longer
chain, recalculating the niceness scores.

So an idea to solve this would be:

* Add 10 niceness for our user.
* Send a message requesting one letter of the secret, and 5 blocks to get confirmations.
* Submit a chain that is longer than that one, but without that block.
* Repeat until leaking all the characters.
* Send a message requesting the flag, plus 5 blocks to get confirmations..

Doing this individually would be super slow as we would have to run with all
the elfs mining as well and adding on top of the main chain (basically, we need
to mine faster than all of them).

However, given that the genesis block is static, and that we don't need our
private keys to mine blocks, we can _pre mine_ all the blocks that we need to
get long chains without issues, and then just submit parts of that long chain
and work on top of it.

### Solution

These are roughly the steps:

* Pre-mine 10 blocks adding niceness to us.
* Pre-mine 1000 blocks on top of them and store them to disk.
* Start the challenge, get our private key.
* Mine on top of block 100 a block with our transaction requesting a single letter + 5 blocks.
* Mine on top of block 110 a block with our transaction requesting a single letter + 5 blocks.
* ... Repeat for all letters.
* Submit blocks 1 .. 100 (now we have the longest chain)
* Submit blocks 101 106 from the new ones created (now we have our first transaction confirmed)
* Wait for santa to add the letter into the transaction pool.
* Submit blocks 101 .. 110 from the original chain (no we have the longest chain again)
* Submit blocks 111 .. 116 from the new ones created (now we have our second transaction confirmed).
* Wait for santa to add the letter into transaction pool.
* ... Repeat for all letters.
* Once we leak the entire secret letter, we can mine on top of a block further up the chain and do the same thing to get the flag.

Luckily, we can reuse the code in the script to do most of the stuff that we need.

The pre-miner can be found in
[`challenge6_premine.py`](./challenge6_premine.py) and the solver can be found
in [`./challenge6.py`](./challenge6.py)

### Optimizations

The above code could be refactored so we leak more than one letter per chain
(we can probably leak 8 letters safely, leaving us up with just 4 chains).
