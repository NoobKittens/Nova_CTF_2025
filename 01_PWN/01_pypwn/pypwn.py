#!/usr/bin/env python3

from ctypes import CDLL, c_buffer, c_char
import sys, os

libc = CDLL('/lib/x86_64-linux-gnu/libc.so.6')

# Primary vulnerable buffer
buf = c_buffer(1024)

# Secondary buffer to create misdirection
shadow_buf = (c_char * 256)()

# Fake canary (completely useless but psychologically effective)
FAKE_CANARY = b"\xDE\xAD\xBE\xEF"

# Secret trigger (reversed for obfuscation)
TRIGGER = b"NOVA_CTF"[::-1]

print("=== Python Native Interface Memory Challenge ===")
print("Inbound payload stream initialized.")
print("Provide input sequence: ")
sys.stdout.flush()

# Intentional unsafe call
libc.gets(buf)

# Copy some of the overflow candidate area into a shadow buffer
for i in range(256):
    shadow_buf[i] = buf[512 + i]

# Output partial shadow to avoid trivial brute-force
print(f"[Diagnostics] Shadow segment preview: {bytes(shadow_buf[:12])}")

# Multi-stage validation
overflow_hit = TRIGGER in bytes(shadow_buf)
canary_hit = FAKE_CANARY in bytes(buf)

if overflow_hit:
    print("[+] Memory boundary violation acknowledged.")
    print("[+] Secondary trigger sequence validated.")
elif canary_hit:
    print("[!] Canary breach detected… but this is a decoy.")
    print("    Nice try, engineer.")
    sys.exit(1)
else:
    print("[-] No unauthorized memory behavior observed.")
    sys.exit(1)

# Final stage: file retrieval
flag_path = "/home/chal/flag.txt"
if os.path.exists(flag_path):
    print(open(flag_path).read())
else:
    print("Flag asset missing. Contact challenge admin.")
