# Hidden Transmission [Nova2k25] Writeup


![](attachments/Pasted%20image%2020251130172930.png)

## Analysis

1.  **Initial Inspection**:
    The file is a valid PNG image. `strings` and `binwalk` did not reveal any obvious embedded files or flags.

2.  **Steganography**:
    Given the hint "steganography to conceal", we suspected LSB (Least Significant Bit) steganography. We wrote a Python script to extract the LSBs of the Red, Green, and Blue channels.

    ```python
    from PIL import Image

    def extract_lsb(image_path):
        img = Image.open(image_path)
        pixels = img.load()
        width, height = img.size
        
        lsb_r = ""
        # ... (extract LSBs for R, G, B) ...
        
        # Convert to bytes and save
    ```

    Analyzing the extracted data, we found a Base64 string at the beginning of the Red channel's LSB data:
    `ACAgIG1zZnM1IRkXU28ABXxaKSJAUVFebxsL`

3.  **Cryptography**:
    Decoding the Base64 string resulted in binary data. The hint "cryptography to protect" suggested encryption. We suspected a simple XOR cipher.

    We attempted to derive the key using the known flag format `NOVA_CTF{`.
    
    ```python
    decoded = base64.b64decode("ACAgIG1zZnM1IRkXU28ABXxaKSJAUVFebxsL")
    known_plain = b"NOVA_CTF{"
    key = xor(decoded[:len(known_plain)], known_plain)
    # Result: b'Nova2025N'
    ```

    The derived key pattern `Nova2025N` suggested the key is `Nova2025`.

4.  **Decryption**:
    XORing the entire decoded string with the key `Nova2025` revealed the flag.

    ```python
    key = b"Nova2025"
    flag = xor(decoded, key)
    print(flag)
    # Output: b'NOVA_CTF{Nova_2025_Crack!t}'
    ```

## Flag

`NOVA_CTF{Nova_2025_Crack!t}`


