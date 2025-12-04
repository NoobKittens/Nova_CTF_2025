# Slack Protocol Writeup

![](attachments/Pasted%20image%2020251130175018.png)

## Solution Walkthrough

### 1. Initial Analysis
We started with a disk image file `Drive_G.001`. Using `fls` from The Sleuth Kit, we listed the files in the image to get an overview of the filesystem.

```bash
fls Drive_G.001
```

Output:
```
r/r 3:	NEW VOLUME  (Volume Label Entry)
d/d 6:	System Volume Information
r/r 7:	FLAG.txt
d/d 8:	$RECYCLE.BIN
...
```

We found a file named `FLAG.txt`. However, reading its content revealed it was a decoy:
```bash
icat Drive_G.001 7
# Output: THIS IS NOT FLAG
```

### 2. Investigating Slack Space
The challenge title "Slack Protocol" and the description "slack remembers" strongly hinted at **file slack space**—the unused space between the end of a file's data and the end of the last allocated cluster.

We examined the metadata for `FLAG.txt` to find its location:
```bash
istat Drive_G.001 7
```
This told us the file was allocated at sector 104. We extracted the entire 4096-byte cluster (8 sectors * 512 bytes) starting at sector 104 to see what was hidden in the slack space.

```bash
dd if=Drive_G.001 of=flag_cluster.dat bs=512 count=8 skip=104
strings flag_cluster.dat
```

The output revealed a hidden string after the "THIS IS NOT FLAG" text:
```
THIS IS NOT FLAG 
Fully_Reocverd_Slack_Space
```
The string `Fully_Reocverd_Slack_Space` (note the typo) appeared to be a password.

### 3. Recovering the PDF
The description also mentioned "Recover the PDF". We searched the raw disk image for the PDF file signature `%PDF`.

```bash
grep -a -b "%PDF" Drive_G.001
```
This returned two offsets: `1210000` and `6226864`. We extracted the data starting from the first offset:

```bash
dd if=Drive_G.001 of=recovered1.pdf bs=1 skip=1210000
```

### 4. Decrypting the PDF
We attempted to read the recovered PDF. It was password-protected. We used the password found in the slack space: `Fully_Reocverd_Slack_Space`.

Using `pdftotext` with the user password:
```bash
pdftotext -opw Fully_Reocverd_Slack_Space recovered1.pdf recovered1.txt
cat recovered1.txt
```

The content of the PDF was a sequence of hex values:
```
51 57 35 7a 64 32 56 79 49 47 6c 7a 49 48 74 43 5a 57 46 31 64 47 6c 6d 64 57 78 66 54 56 6c 68 62 6d 31 68 63 6e 30 3d
```

### 5. Decoding the Flag
We decoded the hex string to ASCII, which resulted in a Base64 string:
```bash
echo "51 57 ... 30 3d" | xxd -r -p
# Output: QW5zd2VyIGlzIHtCZWF1dGlmdWxfTVlhbm1hcn0=
```

Finally, we decoded the Base64 string:
```bash
echo "QW5zd2VyIGlzIHtCZWF1dGlmdWxfTVlhbm1hcn0=" | base64 -d
# Output: Answer is {Beautiful_MYanmar}
```

## Final Flag
```
NOVA_CTF{Beautiful_MYanmar}
```

