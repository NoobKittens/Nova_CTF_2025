# Simple Sage Writeup


![](attachments/Pasted%20image%2020251130183319.png)

## Analysis

We are given:
- `n`: A 2048-bit modulus.
- `e`: A 2045-bit public exponent.
- `c`: The ciphertext.

The public exponent `e` is very large, almost the same size as `n`. This is a strong indicator that the private exponent `d` might be small. When `d` is small ($d < \frac{1}{3} N^{1/4}$), Wiener's Attack can be used to recover `d` efficiently using continued fractions.

## Solution

We implemented Wiener's Attack in Python. The attack works by expanding $\frac{e}{n}$ into a continued fraction. One of the convergents $\frac{k}{d}$ of this continued fraction will likely yield the correct private exponent `d`.

### Attack Script

```python
import sys

# ... (helper functions for continued fractions and solving quadratics) ...

def wiener_attack(n, e):
    print("Starting Wiener's Attack...")
    cf = continued_fractions(e, n)
    convs = convergents(cf)
    
    for k, d in convs:
        if k == 0:
            continue
        
        if (e * d - 1) % k != 0:
            continue
        
        phi = (e * d - 1) // k
        
        # x^2 - (n - phi + 1)x + n = 0
        b = -(n - phi + 1)
        roots = solve_quadratic(1, b, n)
        
        if roots:
            p, q = roots
            if p * q == n:
                print(f"Found d: {d}")
                return d
    return None

# ... (loading json and running attack) ...
```

Running the script recovered `d` and decrypted the flag.

## Flag

`Nova_ctf{yOu_kNow_YE1L_15_6AY}`


