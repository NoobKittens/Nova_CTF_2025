# Null Bloom Writeup


![](attachments/Pasted%20image%2020251130174850.png)

## Analysis

1.  **File Identification**:
    The `Suspicious_file` is a ZIP archive. Extracting it reveals the structure of a Word document (`[Content_Types].xml`, `word/`, `docProps/`, etc.).

2.  **Text Search**:
    Searching for the flag format "NOVA" or "CTF" directly in the extracted files yielded no results.
    Reading `word/document.xml` showed the text "The truth is hidden in plain sight…" in red, but also many empty paragraphs with the `<w:vanish/>` tag.

3.  **Header and Footer Analysis**:
    The `word/document.xml` references a header (`header1.xml`) and a footer (`footer1.xml`).

    *   **Header (`word/header1.xml`)**:
        Contains a Base64 encoded string: `e0hlbGxv`.
        Decoding `e0hlbGxv`:
        ```bash
        echo "e0hlbGxv" | base64 -d
        # Output: {Hello
        ```
        Note: `e0` (0xE0) is not the standard Base64 for `{` (0x7B), but due to bit shifting in Base64 decoding, `e0` (011110) followed by `hl` (100001...) aligns to produce `01111011` (0x7B) which is `{`.
        The text is set to white color (`FFFFFF`), making it invisible on a white background.

    *   **Footer (`word/footer1.xml`)**:
        Contains another Base64 encoded string: `X1dvcmxkfQo=`.
        Decoding `X1dvcmxkfQo=`:
        ```bash
        echo "X1dvcmxkfQo=" | base64 -d
        # Output: _World}
        ```
        This text is also set to white color.

4.  **Combining the Parts**:
    Combining the decoded header and footer gives: `{Hello` + `_World}` = `{Hello_World}`.

    The flag format is `NOVA_CTF{...}`.

## Solution

The flag is split between the header and the footer, encoded in Base64, and hidden using white text.

**Flag:** `NOVA_CTF{Hello_World}`

