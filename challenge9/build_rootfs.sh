#!/bin/bash

set -e
make challenge9

pushd initramfs_work
cp ../challenge9 .
chmod +x ./challenge9
find . | cpio -o -H newc | gzip > ../rootfs_patched.cpio.gz
popd

scp rootfs_patched.cpio.gz hacker@dojo.pwn.college:~/challenge9/rootfs_patched.cpio.gz
scp ./challenge9 hacker@dojo.pwn.college:~/challenge9
