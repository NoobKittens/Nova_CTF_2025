# Shadow Process - CTF Writeup

**Challenge:** Shadow Process
**Category:** Reverse Engineering / Malware Analysis
**Flag:** `NOVA_CTF{N0va_3nc0d1ng_t3chniqu3s!}`


![](attachments/Pasted%20image%2020251130172633.png)

## Static Analysis

We analyzed the binary using `objdump` and `readelf`.
We found a suspicious function `main` with many checks (`strstr` for "VirtualBox", "gdb", etc.).
We also found a decryption loop at address `0x1560`.

```assembly
advanced_mal_ctf:     file format elf64-x86-64


Disassembly of section .init:

0000000000001000 <_init>:
    1000:	f3 0f 1e fa          	endbr64
    1004:	48 83 ec 08          	sub    rsp,0x8
    1008:	48 8b 05 c1 2f 00 00 	mov    rax,QWORD PTR [rip+0x2fc1]        # 3fd0 <__gmon_start__@Base>
    100f:	48 85 c0             	test   rax,rax
    1012:	74 02                	je     1016 <_init+0x16>
    1014:	ff d0                	call   rax
    1016:	48 83 c4 08          	add    rsp,0x8
    101a:	c3                   	ret

Disassembly of section .plt:

0000000000001020 <getenv@plt-0x10>:
    1020:	ff 35 ca 2f 00 00    	push   QWORD PTR [rip+0x2fca]        # 3ff0 <_GLOBAL_OFFSET_TABLE_+0x8>
    1026:	ff 25 cc 2f 00 00    	jmp    QWORD PTR [rip+0x2fcc]        # 3ff8 <_GLOBAL_OFFSET_TABLE_+0x10>
    102c:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]

0000000000001030 <getenv@plt>:
    1030:	ff 25 ca 2f 00 00    	jmp    QWORD PTR [rip+0x2fca]        # 4000 <getenv@GLIBC_2.2.5>
    1036:	68 00 00 00 00       	push   0x0
    103b:	e9 e0 ff ff ff       	jmp    1020 <_init+0x20>

0000000000001040 <_exit@plt>:
    1040:	ff 25 c2 2f 00 00    	jmp    QWORD PTR [rip+0x2fc2]        # 4008 <_exit@GLIBC_2.2.5>
    1046:	68 01 00 00 00       	push   0x1
    104b:	e9 d0 ff ff ff       	jmp    1020 <_init+0x20>

0000000000001050 <__isoc23_sscanf@plt>:
    1050:	ff 25 ba 2f 00 00    	jmp    QWORD PTR [rip+0x2fba]        # 4010 <__isoc23_sscanf@GLIBC_2.38>
    1056:	68 02 00 00 00       	push   0x2
    105b:	e9 c0 ff ff ff       	jmp    1020 <_init+0x20>

0000000000001060 <puts@plt>:
    1060:	ff 25 b2 2f 00 00    	jmp    QWORD PTR [rip+0x2fb2]        # 4018 <puts@GLIBC_2.2.5>
    1066:	68 03 00 00 00       	push   0x3
    106b:	e9 b0 ff ff ff       	jmp    1020 <_init+0x20>

0000000000001070 <clock_gettime@plt>:
    1070:	ff 25 aa 2f 00 00    	jmp    QWORD PTR [rip+0x2faa]        # 4020 <clock_gettime@GLIBC_2.17>
    1076:	68 04 00 00 00       	push   0x4
    107b:	e9 a0 ff ff ff       	jmp    1020 <_init+0x20>

0000000000001080 <write@plt>:
    1080:	ff 25 a2 2f 00 00    	jmp    QWORD PTR [rip+0x2fa2]        # 4028 <write@GLIBC_2.2.5>
    1086:	68 05 00 00 00       	push   0x5
    108b:	e9 90 ff ff ff       	jmp    1020 <_init+0x20>

0000000000001090 <getpid@plt>:
    1090:	ff 25 9a 2f 00 00    	jmp    QWORD PTR [rip+0x2f9a]        # 4030 <getpid@GLIBC_2.2.5>
    1096:	68 06 00 00 00       	push   0x6
    109b:	e9 80 ff ff ff       	jmp    1020 <_init+0x20>

00000000000010a0 <fclose@plt>:
    10a0:	ff 25 92 2f 00 00    	jmp    QWORD PTR [rip+0x2f92]        # 4038 <fclose@GLIBC_2.2.5>
    10a6:	68 07 00 00 00       	push   0x7
    10ab:	e9 70 ff ff ff       	jmp    1020 <_init+0x20>

00000000000010b0 <strlen@plt>:
    10b0:	ff 25 8a 2f 00 00    	jmp    QWORD PTR [rip+0x2f8a]        # 4040 <strlen@GLIBC_2.2.5>
    10b6:	68 08 00 00 00       	push   0x8
    10bb:	e9 60 ff ff ff       	jmp    1020 <_init+0x20>

00000000000010c0 <__stack_chk_fail@plt>:
    10c0:	ff 25 82 2f 00 00    	jmp    QWORD PTR [rip+0x2f82]        # 4048 <__stack_chk_fail@GLIBC_2.4>
    10c6:	68 09 00 00 00       	push   0x9
    10cb:	e9 50 ff ff ff       	jmp    1020 <_init+0x20>

00000000000010d0 <printf@plt>:
    10d0:	ff 25 7a 2f 00 00    	jmp    QWORD PTR [rip+0x2f7a]        # 4050 <printf@GLIBC_2.2.5>
    10d6:	68 0a 00 00 00       	push   0xa
    10db:	e9 40 ff ff ff       	jmp    1020 <_init+0x20>

00000000000010e0 <pclose@plt>:
    10e0:	ff 25 72 2f 00 00    	jmp    QWORD PTR [rip+0x2f72]        # 4058 <pclose@GLIBC_2.2.5>
    10e6:	68 0b 00 00 00       	push   0xb
    10eb:	e9 30 ff ff ff       	jmp    1020 <_init+0x20>

00000000000010f0 <close@plt>:
    10f0:	ff 25 6a 2f 00 00    	jmp    QWORD PTR [rip+0x2f6a]        # 4060 <close@GLIBC_2.2.5>
    10f6:	68 0c 00 00 00       	push   0xc
    10fb:	e9 20 ff ff ff       	jmp    1020 <_init+0x20>

0000000000001100 <read@plt>:
    1100:	ff 25 62 2f 00 00    	jmp    QWORD PTR [rip+0x2f62]        # 4068 <read@GLIBC_2.2.5>
    1106:	68 0d 00 00 00       	push   0xd
    110b:	e9 10 ff ff ff       	jmp    1020 <_init+0x20>

0000000000001110 <fgets@plt>:
    1110:	ff 25 5a 2f 00 00    	jmp    QWORD PTR [rip+0x2f5a]        # 4070 <fgets@GLIBC_2.2.5>
    1116:	68 0e 00 00 00       	push   0xe
    111b:	e9 00 ff ff ff       	jmp    1020 <_init+0x20>

0000000000001120 <open@plt>:
    1120:	ff 25 52 2f 00 00    	jmp    QWORD PTR [rip+0x2f52]        # 4078 <open@GLIBC_2.2.5>
... (495 lines left)
```

This loop reads bytes from a buffer, XORs them with `0xa7`, subtracts a running value `edx` (which increments by 7), and stores the result.

## Data Recovery

We identified the source data buffer in `.rodata` at offset `0x21a0`.
The loop we found started processing at `0x21c0` with `edx=0x70`.
We calculated that `0x21a0` is 32 bytes (16 "steps" of 2 bytes) before `0x21c0`.
Extrapolating backwards, the initial `edx` for `0x21a0` should be `0`.

## Decryption

We implemented the decryption logic in Python:

```python
data = [0xe9, 0x90, 0x23, ...] # Bytes from 0x21a0
edx = 0
result = ""
for val in data:
    x = val ^ 0xa7
    x = (x - edx) & 0xFF
    result += chr(x)
    edx = (edx + 7) & 0xFF
print(result)
```

## Result


```
def decrypt():
    # Bytes extracted from 0x21a0 (skipping nulls/padding)
    # e9 00 90 00 23 00 d1 00 dc 00 f1 00 3f 00 33 00
    # cf 00 04 00 d0 00 1c 00 1c 00 1d 00 71 00 3b 00
    # 74 00 78 00 4b 00 49 00 5a 00 af 00 6a 00 b3 00
    # 6e 00
    
    data = [
        0xe9, 0x90, 0x23, 0xd1, 0xdc, 0xf1, 0x3f, 0x33,
        0xcf, 0x04, 0xd0, 0x1c, 0x1c, 0x1d, 0x71, 0x3b,
        0x74, 0x78, 0x4b, 0x49, 0x5a, 0xaf, 0x6a, 0xb3,
        0x6e
    ]
    
    edx = 0
    result = ""
    
    for val in data:
        # val ^= 0xa7
        # val -= edx
        # edx += 7

        x = val ^ 0xa7
        x = (x - edx) & 0xFF
        result += chr(x)

        edx = (edx + 7) & 0xFF
        
    print(f"Decrypted: {result}")

if __name__ == "__main__":
    decrypt()
```

The script outputted the string: `N0va_3nc0d1ng_t3chniqu3s!`
Wrapping this in the standard flag format gives: `NOVA_CTF{N0va_3nc0d1ng_t3chniqu3s!}`


