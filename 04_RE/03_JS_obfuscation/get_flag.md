# NovaCTF 2025 - JS Obfuscation Challenge Writeup

![](attachments/Pasted%20image%2020251130182933.png)

## Solution

1.  **Inspect the Source Code:**
    Opening `index.html`, we see a script block containing obfuscated JavaScript.

    ```javascript
    var _realBlob="YmtOa1kzQjNjQU1DQVFZbVZsNGlJOE9YdzQvRGc4T2J3NXJEdGNPeXc3WERxY0tXd29YQ2hjS0l3NnZEbDhPY3c0SENwVUJlUUZobVluOXg=";
    (function(b){try{var s1=atob(b),s2=atob(s1),s3=_0x5xor(s2),s4=_0x219d(s3);console[_0x5a7e[0]]("%cREAL FLAG: "+s4,"color:#39ff14;font-size:19px;font-weight:bold")}catch(e){}})(_realBlob)
    ```

2.  **Analyze the Decoding Logic:**
    The script defines a `_realBlob` string and an immediately invoked function expression (IIFE) that processes it.
    The processing steps are:
    *   `s1 = atob(b)`: Base64 decode `_realBlob`.
    *   `s2 = atob(s1)`: Base64 decode `s1`.
    *   `s3 = _0x5xor(s2)`: Apply a custom XOR function.
    *   `s4 = _0x219d(s3)`: Apply a reversal function.

    The helper functions are defined earlier in the script:

    *   `_0x219d(x)`: Reverses the string `x`.
        ```javascript
        function _0x219d(x){return x[_0x5a7e[1]]("")[_0x5a7e[2]]()[_0x5a7e[3]]("")}
        // Equivalent to: return x.split("").reverse().join("")
        ```

    *   `_0x5xor(z)`: XORs each character code with `((i * 7) + 19) & 255`.
        ```javascript
        function _0x5xor(z){let r="";for(let i=0;i<z.length;i++){r+=String[_0x5a7e[6]](z[_0x5a7e[5]](i)^(((i*7)+19)&255))}return r}
        ```

3.  **Replicate the Logic (Solver Script):**
    We can write a Python script to perform these operations and reveal the flag.

    ```python
    import base64

    def reverse_string(x):
        return x[::-1]

    def xor_decrypt(z):
        r = ""
        for i in range(len(z)):
            char_code = ord(z[i])
            xor_val = ((i * 7) + 19) & 255
            r += chr(char_code ^ xor_val)
        return r

    _realBlob = "YmtOa1kzQjNjQU1DQVFZbVZsNGlJOE9YdzQvRGc4T2J3NXJEdGNPeXc3WERxY0tXd29YQ2hjS0l3NnZEbDhPY3c0SENwVUJlUUZobVluOXg="

    # Step 1: Base64 decode
    s1_bytes = base64.b64decode(_realBlob)
    s1 = s1_bytes.decode('utf-8')

    # Step 2: Base64 decode again
    s2_bytes = base64.b64decode(s1)
    s2 = s2_bytes.decode('utf-8')

    # Step 3: XOR decrypt
    s3 = xor_decrypt(s2)

    # Step 4: Reverse
    flag = reverse_string(s3)

    print(f"Flag: {flag}")
    ```

4.  **Result:**
    Running the solver yields the flag:
    `CTF{NOVA_2025_ULTRA_SECRET_W01F_SIGMA_KEY}`



