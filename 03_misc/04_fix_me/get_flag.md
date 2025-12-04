# Nova CTF - Fix Me Writeup

## Challenge Information

- **Challenge Name:** Fix Me
- **Category:** Forensics / Steganography
- **Points:** 50
- **Flag Format:** `Nova_ctf{XXXXX_XXX}`

![](attachments/Pasted%20image%2020251130171403.png)
## Initial Analysis

Upon opening the image, we can see a QR code that's heavily corrupted with salt-and-pepper noise. The QR code structure is visible (we can see the three position markers in the corners), but the noise makes it unreadable by standard QR code readers.

The noise appears to be random pixel-level corruption distributed across the entire image, which is a classic image processing challenge.

## Solution Approach

The key to solving this challenge is applying image denoising techniques to clean up the QR code before attempting to decode it.

### Strategy

1. **Denoise the image** - Remove salt-and-pepper noise
2. **Apply thresholding** - Convert to clean binary (black/white) image
3. **Decode the QR code** - Extract the flag

### Tools Used

- Python 3
- PIL (Python Imaging Library) - Image processing
- NumPy - Array operations and thresholding
- zbarimg - QR code decoding utility

## Step-by-Step Solution

### Step 1: Load the Image

```python
from PIL import Image
import numpy as np

# Load image in grayscale mode
img = Image.open('attachments/novactf.png').convert('L')
```

### Step 2: Apply Median Filter

The median filter is particularly effective against salt-and-pepper noise because it replaces each pixel with the median value of its neighbors, effectively removing isolated noise pixels.

```python
from PIL import ImageFilter

# Apply median filter with kernel size 5
img_denoised = img.filter(ImageFilter.MedianFilter(size=5))
```

### Step 3: Apply Binary Thresholding

Convert the denoised image to a clean binary image (pure black and white).

```python
# Convert to numpy array for thresholding
arr = np.array(img_denoised)

# Apply simple threshold at 128 (mid-point)
threshold = 128
arr_binary = ((arr > threshold) * 255).astype(np.uint8)

# Convert back to image
img_clean = Image.fromarray(arr_binary)
img_clean.save('attachments/novactf_cleaned.png')
```

### Step 4: Decode the QR Code

Use zbarimg to decode the cleaned QR code:

```bash
zbarimg --raw attachments/novactf_cleaned.png
```

## Complete Solution Script

```python
#!/usr/bin/env python3
from PIL import Image, ImageFilter
import subprocess
import numpy as np

# Read the image in grayscale
img = Image.open('attachments/novactf.png').convert('L')

# Apply median filter to remove salt-and-pepper noise
img_denoised = img.filter(ImageFilter.MedianFilter(size=5))

# Convert to numpy array for thresholding
arr = np.array(img_denoised)

# Apply binary threshold
threshold = 128
arr_binary = ((arr > threshold) * 255).astype(np.uint8)

# Convert back to image and save
img_clean = Image.fromarray(arr_binary)
img_clean.save('attachments/novactf_cleaned.png')

# Decode QR code
result = subprocess.run(['zbarimg', '-q', '--raw', 'attachments/novactf_cleaned.png'],
                       capture_output=True, text=True)

if result.returncode == 0 and result.stdout.strip():
    print(f"Flag: {result.stdout.strip()}")
else:
    print("Failed to decode QR code")
```

## Flag

```
python3 get_flag.py
Nova_ctf{4lignment_is_not_En0uGh_1nym0r4_2025}
```


