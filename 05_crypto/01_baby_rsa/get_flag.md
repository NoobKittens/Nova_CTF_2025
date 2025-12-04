# Baby_rSa


![](attachments/Pasted%20image%2020251130183719.png)



A flag is encrypted using **triple-redundant RSA encryption**. The same plaintext message was encrypted on **three different servers**, using:

- **Same public exponent:** `e = 3` (tiny exponent)  
- **Different large RSA moduli (n1, n2, n3)**
- **Same plaintext**


The challenge used RSA with **e = 3** and encrypted the **same plaintext** using three different moduli (n1, n2, n3). This is vulnerable to **Håstad’s Broadcast Attack**, where:

ci=m3mod  nic_i = m^3 \mod n_ici​=m3modni​

Because `m^3 < n1 × n2 × n3`, we can use the **Chinese Remainder Theorem (CRT)** to combine the ciphertexts and recover **m³ exactly (no modulus reduction)**.

Then, take the **integer cube root** of the combined value to get `m`, convert it to bytes, and decode to ASCII.

```
#!/usr/bin/env python3
# recover.py
# Recover m from c1 = m^3 mod n1, c2 = m^3 mod n2, c3 = m^3 mod n3
# using CRT then integer cube root.

import sys

# Given data (paste as integers)
n1 = int(
    "389260030028296819722634860914752615069829328857502077087232030965150006342"
    "606952705902677084446344159193339051496368485050093984786934965830161867813241"
    "509740044686925332053238950500500527144391586912155106187018667942589646798"
    "683311776637929704732235236207067628911707667520838657711152062102170351624"
    "749663"
)
c1 = int(
    "287593712799237114731026285738322128134927735258618400348943628457734945337"
    "526201017574545066589169565062139940250619344863302427350484135061112890215"
    "108800358484559508163719422825284129945008603516038741253706462698461602912"
    "722141673591351881902048788520927219585775661439909831706399268197521580623"
    "006048266"
)

n2 = int(
    "231819737816538708885217113344384876787753250821673734001379787025595552294"
    "409310490109010403872295591771234041902034188321852078755249419580868176590"
    "833993272845687027952800866782993575978659116402892934793351935346034365908"
    "452290796156287576342050040545815130675221405582030990483943949679512239636"
    "778594237"
)
c2 = int(
    "197088056612924579751725770355165981454127103933110113481169328600263518138"
    "801734069329291558414514874838126705240936333844498289397632080716969289320"
    "480773687893130693873839151836751958317330923083378948506454552169035369689"
    "502281971325269778840281574619980899607036977785499811819651592777627957635"
    "353594806"
)

n3 = int(
    "333608258185822282068719087693152781865526696445831836636426055088871158500"
    "291285271976167670517006724135508538816677222139928088272880055308997043600"
    "579901240909267304189750875428895339915109376319455474467567596672651533670"
    "970154148139143863101794181858980347637215507028894375910310367003160895456"
    "117416549"
)
c3 = int(
    "222446369015303310483307679102334652605761227681070292318312620813248505797"
    "856521215641362461612468067317422564079348138473813009332989366815907061357"
    "359411455557364514067823840900118986244137779166891706227893830571459758816"
    "098217400090840289209204271858898189052498012212919175406558150369396753724"
    "906785991"
)


def crt_combine(cs, ns):
    """
    Chinese Remainder Theorem combine:
    Given cs[i] ≡ x (mod ns[i]), return x mod N where N = prod(ns)
    """
    assert len(cs) == len(ns)
    N = 1
    for ni in ns:
        N *= ni

    total = 0
    for ci, ni in zip(cs, ns):
        Ni = N // ni
        # Python 3.8+ supports modular inverse via pow(..., -1, mod)
        inv = pow(Ni, -1, ni)
        total += ci * Ni * inv

    return total % N, N


def integer_nth_root(k, n):
    """
    Return the integer part of the k-th root of n (i.e., floor(n**(1/k))),
    using binary search. Also returns True if exact (root**k == n).
    """
    if n < 0:
        raise ValueError("n must be non-negative")
    if n == 0:
        return 0, True

    # upper bound: 1 << ((bit_length + k - 1) // k)
    bl = n.bit_length()
    hi = 1 << ((bl + k - 1) // k)
    lo = 0
    while lo < hi:
        mid = (lo + hi) // 2
        p = mid ** k
        if p < n:
            lo = mid + 1
        else:
            hi = mid
    root = lo
    if root ** k > n:
        root -= 1
    return root, (root ** k == n)


def main():
    cs = [c1, c2, c3]
    ns = [n1, n2, n3]

    combined, N = crt_combine(cs, ns)
    print("[*] Combined value (m^3 mod N) computed via CRT.")
    # combined should equal m^3 because m^3 < N in correct low-exponent broadcast scenario

    # compute integer cube root
    m, exact = integer_nth_root(3, combined)
    if not exact:
        print("[!] Warning: cube root was not exact. The recovered root^3 != combined.")
        # still try: maybe combined = m^3 but due to reduction something went wrong
    else:
        print("[*] Exact cube root found.")

    try:
        # convert integer to bytes and decode
        mb = m.to_bytes((m.bit_length() + 7) // 8, byteorder="big")
        text = mb.decode("utf-8", errors="replace")
        print("\nRecovered plaintext (raw bytes -> utf-8):\n")
        print(text)
    except Exception as e:
        print("Error converting to bytes / decoding:", e)
        # print hex fallback
        print("Recovered integer (hex):")
        print(hex(m))

    # If you expect a flag like Nova_ctf{...}, quick search:
    s = text if 'text' in locals() else ""
    if "Nova_ctf{" in s:
        start = s.find("Nova_ctf{")
        end = s.find("}", start)
        if end != -1:
            print("\nFlag found:")
            print(s[start:end+1])
        else:
            print("\nFound 'Nova_ctf{' but couldn't find a closing '}' in decoded text.")


if __name__ == "__main__":
    main()
```



```
python3 get_flag.py 
[*] Combined value (m^3 mod N) computed via CRT.
[*] Exact cube root found.

Recovered plaintext (raw bytes -> utf-8):

AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAANova_ctf{cRyP7O_m@kEs_fun!!}

Flag found:
Nova_ctf{cRyP7O_m@kEs_fun!!}
Traceback (most recent call last):
  File "testzz.py", line 144, in <module>
    print(preview_text(pt))
```