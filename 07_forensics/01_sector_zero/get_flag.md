# Sector Zero Solution

![](attachments/Pasted%20image%2020251130174141.png)
## Analysis

The provided file `Corrupt_Disk.001` is a damaged disk image.
`file` identifies it as a DOS/MBR boot sector, but the partition table is corrupt.
`binwalk` reveals a hidden PNG image embedded in the file.

## Extraction

We used `foremost` (or `binwalk`) to extract the hidden PNG image.

```bash
foremost -i Corrupt_Disk.001 -o foremost_output
```

This recovered `attachments/00007232.png`.

## Flag Retrieval

The PNG image contains text. Using `tesseract` for OCR:

```bash
tesseract foremost_output/png/attachments/00007232.png stdout
```

Output: `NCSC2025{Have_A_FUN}`

