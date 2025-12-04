# Baby Bypass Writeup

**Challenge Name:** Baby Bypass
**Category:** Web Exploitation
**Points:** 50


![](attachments/Pasted%20image%2020251130154222.png)


![](attachments/Pasted%20image%2020251130154231.png)

## Vulnerability Analysis
The challenge presents a login form. The application filters several characters from the input: `'`, `-`, `true`, `=`, `"`. However, it **does not filter the backslash (`\`) character**.

The SQL query is likely constructed as follows:
```php
$sql = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";
```

By sending a backslash (`\`) as the `username`, the query becomes:
```sql
SELECT * FROM users WHERE username = '\' AND password = '$password'
```
The backslash escapes the closing single quote of the `username` field. This causes the database to treat the string starting from the first quote of `username` all the way to the opening quote of `password` as the username value. Effectively, the query becomes:
```sql
SELECT * FROM users WHERE username = ' [ESCAPED_QUOTE] AND password = ' [OUR_PASSWORD_PAYLOAD] '
```
This allows us to inject arbitrary SQL commands into the `password` field, which is now interpreted as part of the SQL command rather than a string literal.

## Exploitation
Since quotes (`'`) and equals (`=`) are stripped, we must use alternative techniques:
1.  **Hex Encoding**: To represent strings without quotes (e.g., table names, file paths), we use hex encoding (e.g., `0x61646d696e` for 'admin').
2.  **LIKE Operator**: Instead of `=`, we can use `LIKE` (or just avoid comparisons where possible).
3.  **UNION SELECT**: We can use `UNION SELECT` to retrieve data from the database or read files.

Using `UNION SELECT` and `load_file()`, we can read the source code of `index.php`, which contains the flag.

### Payload Construction
1.  **Username**: `\`
2.  **Password**: ` union select 1, load_file(0x2f7661722f7777772f68746d6c2f696e6465782e706870), 3#`

The hex string corresponds to `/var/www/html/index.php`.

## Flag
`NOVA_CTF{SQl1_pluS_h@sh1n9_1s_fuN_--------------------}`


![](attachments/Pasted%20image%2020251130154539.png)



![](attachments/Pasted%20image%2020251130155450.png)


![](attachments/Pasted%20image%2020251130155601.png)


```
echo -n '/var/www/html/index.php' | xxd -p
2f7661722f7777772f68746d6c2f696e6465782e706870
```


![](attachments/Pasted%20image%2020251130155930.png)

