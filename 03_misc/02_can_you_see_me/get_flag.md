# Excel Zero-Day Simulation CTF Challenge


![](attachments/Pasted%20image%2020251130164557.png)

## Challenge Overview

We're given a `challenge.xlsx` file that asks us to "exploit" a zero-day simulation by entering a 16-character serial.

## Solution

### Step 1: Analyze the XLSX Structure

XLSX files are ZIP archives. Listing the contents reveals a hidden file:

```bash
$ unzip -l challenge.xlsx
Archive:  challenge.xlsx
  Length      Date    Time    Name
---------  ---------- -----   ----
      ...
       46  2025-11-29 05:24   docProps/payload.bin   # <-- Hidden payload!
      ...
```

### Step 2: Extract and Examine the Payload

```bash
$ unzip -p challenge.xlsx docProps/payload.bin | xxd
00000000: 142a 242e 1b02 2d23 230d 2c2b 0437 3972  .*$...-##.,+.79r
00000010: 0820 0d22 0532 0d20 2a06 0113 291b 1703  . .".2. *...)...
00000020: 6b1a 600a 1671 0601 193a 1a6d 6d3e       k.`..q...:.mm>
```

This looks like XOR-encrypted data (46 bytes).

### Step 3: Reverse Engineer the Constraints

Examining the worksheet XML files reveals the constraint system:

**Sheet1 (Input):**

- User enters 16 characters in cells B2:Q2
- Row 3 checks if constraint values match specific targets

**Sheet2 (Constraints):**

- Row 1: `CODE()` function converts each input character to ASCII
- Row 2: Bitwise operations create 20 constraint values that must match targets

### Step 4: Solve with Z3

Using the Z3 SMT solver to find the 16-character serial:

```python
from z3 import *

chars = [BitVec(f'c{i}', 16) for i in range(16)]
A1, B1, C1, D1, E1, F1, G1, H1, I1, J1, K1, L1, M1, N1, O1, P1 = chars

solver = Solver()

# Constrain to printable ASCII
for c in chars:
    solver.add(c >= 32, c <= 126)

# Add all constraints
solver.add(LShR(A1 ^ 17, 2) == 18)
solver.add((B1 ^ 42) & 255 == 111)
solver.add((C1 + D1) ^ 123 == 218)
solver.add((E1 << 1) ^ F1 == 201)
solver.add((G1 * 2) ^ 99 == 209)
solver.add(LShR(H1 ^ I1, 3) == 3)
solver.add((J1 ^ 200) & 127 == 11)
solver.add((K1 + L1) ^ M1 == 221)
solver.add((N1 ^ 55) << 2 == 464)
solver.add((O1 ^ P1) ^ 111 == 125)
solver.add((A1 + B1) ^ 50 == 173)
solver.add((C1 ^ 33) << 1 == 230)
solver.add(LShR(D1 ^ E1, 1) == 5)
solver.add((F1 * 3) ^ 200 == 11)
solver.add((G1 ^ H1) & 255 == 28)
solver.add((I1 + J1 + K1) ^ 77 == 173)
solver.add(LShR(L1 ^ 66, 2) == 3)
solver.add((M1 + N1) ^ 88 == 215)
solver.add((O1 * 4) ^ 22 == 326)
solver.add((P1 ^ 99) & 63 == 37)

if solver.check() == sat:
    model = solver.model()
    serial = ''.join(chr(model[c].as_long()) for c in chars)
    print(f"Serial: {serial}")
```

**Result:** `ZERODAYEXCELLCTF` (reads as "ZERO DAY EXCEL CTF")

### Step 5: Decrypt the Payload

XOR decrypt the payload using the serial as a repeating key:

```python
serial = 'ZERODAYEXCELLCTF'
payload = bytes.fromhex('142a242e1b022d23230d2c2b0437397208200d2205320d202a060113291b17036b1a600a16710601193a1a6d6d3e')
key = serial.encode()

decrypted = bytes([payload[i] ^ key[i % len(key)] for i in range(len(payload))])
print(decrypted.decode())
```

## Flag

```
python3 get_flag.py 
Nova_Ctf{NigHtm4Re_mAsTerED_eXCE1_2ER0_DAy_!!}
```
