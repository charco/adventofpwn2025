# Challenge 1

## Description

```
Every year, Santa maintains the legendary Naughty-or-Nice list, and despite the
rumors, there’s no magic behind it at all—it’s pure, meticulous byte-level
bookkeeping. Your job is to apply every tiny change exactly and confirm the
final list matches perfectly—check it once, check it twice, because Santa does
not tolerate even a single incorrect byte. At the North Pole, it’s all just
static analysis anyway: even a simple objdump | grep naughty goes a long way.
```

## Analysis

```
$ file /challenge/check-list 
/challenge/check-list: setuid ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, BuildID[sha1]=bec7b06ce41d2387ff43f204bc4e91193111b83a, stripped
```

Binary is statically linked and stripped.

It starts with:

```
(gdb) x /20i $rip
=> 0x401000:    mov    rbp,rsp
   0x401003:    sub    rsp,0x500
   0x40100a:    mov    eax,0x0
   0x40100f:    mov    edi,0x0
   0x401014:    lea    rsi,[rbp-0x400]
   0x40101b:    mov    edx,0x400
   0x401020:    syscall
   0x401022:    sub    BYTE PTR [rbp-0x49],0xc0
   0x401026:    add    BYTE PTR [rbp-0x1cb],0xa
   0x40102d:    add    BYTE PTR [rbp-0x1d0],0xb7
   (...)
```

It's a read system call, reading `0x400` bytes into the stack, and then a
series of operations onto those bytes.

If we call it with a random input, we get the following message:

```
 echo "asdasd"  | /challenge/check-list 
🚫 Wrong: Santa told you to check that list twice!
```

We should identify where in the disasm the modifications stop, and where we get
what we need to compare with what.

```
  aa143f:       80 85 36 fc ff ff c4    add    BYTE PTR [rbp-0x3ca],0xc4
  aa1446:       80 ad 0c ff ff ff d7    sub    BYTE PTR [rbp-0xf4],0xd7
  aa144d:       80 ad b6 fc ff ff 2a    sub    BYTE PTR [rbp-0x34a],0x2a
  aa1454:       80 bd 00 fc ff ff 2b    cmp    BYTE PTR [rbp-0x400],0x2b
  aa145b:       0f 85 09 33 00 00       jne    0xaa476a
  aa1461:       80 bd 01 fc ff ff 8f    cmp    BYTE PTR [rbp-0x3ff],0x8f
  aa1468:       0f 85 fc 32 00 00       jne    0xaa476a
  aa146e:       80 bd 02 fc ff ff 22    cmp    BYTE PTR [rbp-0x3fe],0x22
  aa1475:       0f 85 ef 32 00 00       jne    0xaa476a
  aa147b:       80 bd 03 fc ff ff af    cmp    BYTE PTR [rbp-0x3fd],0xaf
  aa1482:       0f 85 e2 32 00 00       jne    0xaa476a
```

At some point, we start getting a lot of comparisons, which end up printing the error message.

Our goal is to pass all those comparisons and get to here:

```
  aa46ca:       80 7d ff 29             cmp    BYTE PTR [rbp-0x1],0x29
  aa46ce:       0f 85 96 00 00 00       jne    0xaa476a
  aa46d4:       48 c7 c0 01 00 00 00    mov    rax,0x1
  aa46db:       48 c7 c7 01 00 00 00    mov    rdi,0x1
  aa46e2:       48 8d 35 1d 09 00 00    lea    rsi,[rip+0x91d]        # 0xaa5006
  aa46e9:       48 c7 c2 31 00 00 00    mov    rdx,0x31
  aa46f0:       0f 05                   syscall
  aa46f2:       b8 02 00 00 00          mov    eax,0x2
  aa46f7:       48 8d 3d 02 09 00 00    lea    rdi,[rip+0x902]        # 0xaa5000
  aa46fe:       be 00 00 00 00          mov    esi,0x0
  aa4703:       ba 00 00 00 00          mov    edx,0x0
  aa4708:       0f 05                   syscall
  aa470a:       48 83 f8 00             cmp    rax,0x0
  aa470e:       7c 4e                   jl     0xaa475e
  aa4710:       49 89 c4                mov    r12,rax
  aa4713:       b8 00 00 00 00          mov    eax,0x0
  aa4718:       4c 89 e7                mov    rdi,r12
  aa471b:       48 8d b5 00 fb ff ff    lea    rsi,[rbp-0x500]
  aa4722:       ba 00 01 00 00          mov    edx,0x100
  aa4727:       0f 05                   syscall
  aa4729:       48 83 f8 00             cmp    rax,0x0
  aa472d:       7e 2f                   jle    0xaa475e
  aa472f:       48 89 c1                mov    rcx,rax
  aa4732:       48 c7 c0 01 00 00 00    mov    rax,0x1
  aa4739:       48 c7 c7 01 00 00 00    mov    rdi,0x1
  aa4740:       48 8d b5 00 fb ff ff    lea    rsi,[rbp-0x500]
  aa4747:       48 89 ca                mov    rdx,rcx
  aa474a:       0f 05                   syscall
  aa474c:       48 83 f8 00             cmp    rax,0x0
  aa4750:       7c 0c                   jl     0xaa475e
  aa4752:       b8 3c 00 00 00          mov    eax,0x3c
  aa4757:       bf 00 00 00 00          mov    edi,0x0
  aa475c:       0f 05                   syscall
  aa475e:       b8 3c 00 00 00          mov    eax,0x3c
  aa4763:       bf 00 00 00 00          mov    edi,0x0
  aa4768:       0f 05                   syscall
```

## Ideas

### Solve the equations from the disassembly.

This basically boils down to: Parse all the relevant instructions in the
objdump disassembly, maybe using a regexp to capture INST, OFFSET, VALUE, and
apply them. Then we will end up with N equations in the form of:

```
Xi + Ci = Ki mod 256
```

#### Parsing `objdump` output.

We can use a simple regexp to parse the output of objdump and keep only the
instructions that we care about.

By invoking `objdump` with `-Mintel`, `--no-addresses` and
`--no-show-raw-insn`, we get rid of a lot of noise, then:

```
^\s*(add|cmp|sub)\s*.*PTR\s*\[rbp(-.*)\],(.*)$
```

Should capture 3 groups, one for the instruction if it's `add`, `cmp`, or
`sub`, one for the displacement relative to `rbp`, and one with the value in
the operation.

Solution is in [`challenge1_grep.py`](./challenge1_grep.py)

### Use a disassembler library to parse the instructions.

Something maybe more generic would be to use a library like `capstone` to
disassemble the file and parse the instructions manually, doing something
similar than the previous solution.

The idea is the same as with grep, just with a cleaner (and slower) way of
parsing the instructions.

Solution is in [`challenge1_capstone.py`](./challenge1_capstone.py)

### Use a symbolic execution engine.

We can use Triton to single-step the entire execution. When we get the first
`read`, we mark all the memory as symbolic. Then, each time we get to a new
branch, you make sure to not take the one that leads to the failure path. Add
the path constrain for that branch to a global list, and then at the end get a
model that solves all that.

One problem is that there are many operations over each memory address, so the
symbolic state grows a lot. A way to solve this is to call `simplify` to run
the model on the `AstNode` associated with the symbolic expression for a given
memory address once it grows to something like 300 nodes (you don't want to run
it often because it is too slow, but if you let it grow it might lead to OOM).

Solution is in [`chalenge1_triton.py`](./challenge1_triton.py)
