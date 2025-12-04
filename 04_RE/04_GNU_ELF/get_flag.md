# Writeup: hard_re

## Challenge Info

- **Name**: hard_re
- **Category**: Reverse Engineering
- **Flag**: `NovaCTF{Linux_RE_master_2025}`


![](attachments/Pasted%20image%2020251130182948.png)

## Analysis

The binary `hard_re` is a 64-bit ELF executable. It employs several anti-debugging and anti-analysis techniques:

1.  **ptrace**: Checks if the process is already being traced.
2.  **getppid**: Checks the parent process ID.
3.  **TracerPid**: Reads `/proc/self/status` to check for a tracer.
4.  **Parent Process Name**: Checks `/proc/<ppid>/comm` to ensure it's not run by a debugger or shell like `gdb`, `strace`, `ltrace`.
5.  **Environment Variables**: Checks for `LD_PRELOAD`, `LD_LIBRARY_PATH`, `GDB`, `strace`, etc.
6.  **Timing Checks**: Uses `clock_gettime` to measure execution time and exit if it's too slow (indicating debugging).

## Bypass

We created a `bypass.c` shared library and preloaded it using `LD_PRELOAD` to hook the following functions:

- `ptrace`: Always return 0.
- `open` / `openat`: Redirect `/proc/self/status` to a fake status file with `TracerPid: 0`, and `/proc/<ppid>/comm` to a fake comm file containing `bash`.
- `getenv`: Return NULL for blacklisted environment variables.
- `clock_gettime`: Manipulate the returned time to bypass timing checks.

## Solution

The binary reads input from stdin. It processes the input using a custom algorithm involving a key.
The key is derived from the first 8 bytes of the input.
The binary compares the processed input against a hardcoded buffer.

We identified the algorithm by analyzing the disassembly (specifically the loop at `0x14f0`).
The algorithm resembles a custom stream cipher or hash-based encryption.

Since we know the flag format starts with `NovaCTF{`, we used these 8 bytes to recover the key used by the algorithm.
The key recovery script (`solve.py`) brute-forces the key byte-by-byte (since each byte of the key affects the corresponding byte of the output in a reversible way).

**Recovered Key**: `0x32903957071488d9`

Using this key, we decrypted the remaining bytes of the hardcoded buffer to reveal the flag.

## Solver Script

The `solve.py` script implements the decryption logic:

1.  Extracts the hardcoded encrypted data and the S-box (or permutation table) from the binary.
2.  Uses the known prefix `NovaCTF{` to recover the 64-bit key `r9`.
3.  Decrypts the entire buffer using the recovered key.

## Flag

`NovaCTF{Linux_RE_master_2025}`


