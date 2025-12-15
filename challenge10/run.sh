#!/bin/bash

set -e

clang -Wall -Wextra -pedantic -std=c2x \
	-Oz -g3 -gdwarf-5 \
	-fno-builtin -fno-builtin-memset \
	-fpie -mno-sse -fno-jump-tables \
	challenge10.c -o challenge10

clang -Wall -Wextra -pedantic -std=c23 \
	-Oz -g3 -gdwarf-5 \
	-fno-builtin -fno-builtin-memset \
	-ffreestanding -fpie -nostdlib \
	-mno-sse -fno-jump-tables \
	-Wl,--unique=.text.entry \
	challenge10_payload.c   -o challenge10_payload

objcopy --only-section=.text.entry -O binary ./challenge10_payload ./payload

./challenge10 < payload
