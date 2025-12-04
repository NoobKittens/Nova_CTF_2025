# Pieces Challenge Writeup

## Challenge Information

- **Category:** Cryptography / Forensics
- **Flag Format:** `NOVA_CTF{..}` or `Nova_Ctf{..}`
- **Files Provided:** `solve_me.rar`

![](attachments/Pasted%20image%2020251130164959.png)

## Solution

### Step 1: Extract the RAR Archive

![](attachments/Pasted%20image%2020251130170211.png)


The challenge provides a password-protected RAR file. The password  was `password123`.

```bash
unrar x -ppassword123 solve_me.rar
```

This extracts the following files:

- 16 encrypted PNG files (`*.png.enc`)
- 1 encrypted PowerShell script (`en.ps1.enc`)

### Step 2: Analyze the Encryption

The `.enc` extension and `.ps1` filename suggest PowerShell-based encryption. Examining the file sizes shows they're all multiples of 16 bytes, indicating AES block cipher encryption.

After testing various AES decryption methods, the correct approach was:

- **Algorithm:** AES-256-CBC
- **Key:** SHA256 hash of "password123"
- **IV:** First 16 bytes of the encrypted file

### Step 3: Decrypt the PowerShell Script

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import hashlib

with open('en.ps1.enc', 'rb') as f:
    data = f.read()

key = hashlib.sha256(b"password123").digest()
iv = data[:16]
cipher = AES.new(key, AES.MODE_CBC, iv)
decrypted = unpad(cipher.decrypt(data[16:]), 16)
print(decrypted.decode())
```

The decrypted script reveals the encryption logic:

```powershell
param(
    [Parameter(Mandatory=$true)]
    [string]$Password
)

# Convert password to AES key
$PasswordBytes = [System.Text.Encoding]::UTF8.GetBytes($Password)
$Sha = [System.Security.Cryptography.SHA256]::Create()
$Key = $Sha.ComputeHash($PasswordBytes)

# Generate AES object
$AES = [System.Security.Cryptography.Aes]::Create()
$AES.Key = $Key
$AES.Mode = "CBC"
$AES.Padding = "PKCS7"

# Encrypt each file in the folder
Get-ChildItem -File | ForEach-Object {
    $file = $_.FullName
    $AES.GenerateIV()
    $IV = $AES.IV
    $Bytes = [System.IO.File]::ReadAllBytes($file)
    $Encryptor = $AES.CreateEncryptor()
    $EncryptedBytes = $Encryptor.TransformFinalBlock($Bytes, 0, $Bytes.Length)
    $OutFile = "$file.enc"
    [System.IO.File]::WriteAllBytes($OutFile, $IV + $EncryptedBytes)
}
```

### Step 4: Decrypt All PNG Files

Using the same decryption method on all PNG files:

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import hashlib
import os

key = hashlib.sha256(b"password123").digest()

for fname in os.listdir('.'):
    if fname.endswith('.png.enc'):
        with open(fname, 'rb') as f:
            data = f.read()

        iv = data[:16]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(data[16:]), 16)

        with open(fname.replace('.enc', ''), 'wb') as f:
            f.write(decrypted)
```

All 16 files decrypt to valid PNG images (92x92 pixels, 1-bit grayscale).

### Step 5: Identify QR Code Fragments

The decrypted images are QR code fragments:

```bash
file *.png
# Output: PNG image data, 92 x 92, 1-bit grayscale, non-interlaced
```

With 16 images of equal size, this forms a 4x4 grid (368x368 total).

### Step 6: Reassemble the QR Code

The fragments must be arranged correctly. The approach:

1. **Edge Matching:** Each tile has edges that must match adjacent tiles
2. **Backtracking Algorithm:** Try all valid combinations until finding a complete solution

```python
from PIL import Image
import numpy as np

def get_edges(img):
    arr = np.array(img)
    return {
        'top': tuple(arr[0, :]),
        'bottom': tuple(arr[-1, :]),
        'left': tuple(arr[:, 0]),
        'right': tuple(arr[:, -1])
    }

def solve_grid(files, edges):
    def is_valid(grid, row, col, piece):
        if col > 0 and grid[row][col-1]:
            if edges[grid[row][col-1]]['right'] != edges[piece]['left']:
                return False
        if row > 0 and grid[row-1][col]:
            if edges[grid[row-1][col]]['bottom'] != edges[piece]['top']:
                return False
        return True

    def solve(grid, used, pos):
        if pos == 16:
            return True
        row, col = pos // 4, pos % 4
        for piece in files:
            if piece not in used and is_valid(grid, row, col, piece):
                grid[row][col] = piece
                used.add(piece)
                if solve(grid, used, pos + 1):
                    return True
                grid[row][col] = None
                used.remove(piece)
        return False

    grid = [[None]*4 for _ in range(4)]
    solve(grid, set(), 0)
    return grid
```

The correct arrangement:

```
['2a8db0c8', '3762f913', '08165fd7', 'cf30819d']
['c85399e3', 'ec3b5adc', 'a1f4e3d8', '6d40e8a3']
['cc55d722', 'cea2e675', 'faff389a', '28fa9ada']
['8edc283a', '3d39e1ff', 'daaca6e7', '744327df']
```

### Step 7: Decode the QR Code

Assemble and add a quiet zone (white border) for proper scanning:

```python
combined = Image.new('L', (92*4, 92*4), 255)
for row in range(4):
    for col in range(4):
        combined.paste(images[grid[row][col]], (col*92, row*92))

# Add quiet zone
border = 40
final = Image.new('L', (combined.width + 2*border, combined.height + 2*border), 255)
final.paste(combined, (border, border))
final.save('attachments/combined_qr.png')
```

Decode with zbarimg:

```bash
zbarimg -q --raw attachments/combined_qr.png
```

## Flag

```
Nova_ctf{M3rRy_cHR1StMAs!!}
```

