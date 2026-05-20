# CTF Challenge Writeup: Poster Drop

## Challenge Overview

**Challenge Name:** Poster Drop  
**Difficulty:** Easy  
**Flag Format:** `0xV01D{......}`  
**Attempts Allowed:** 5

## Challenge Description

A small artifact (PNG image) is provided with instructions to inspect it carefully and recover the hidden flag. The challenge title "Poster Drop" hints at the nature of the vulnerability.

## Solution

### Step 1: Examine the File

The challenge provides a file named `poster.png`. At first glance, it appears to be a simple gradient image (96x64 pixels, 8-bit RGB).

```bash
$ file poster.png
poster.png: PNG image data, 96 x 64, 8-bit/color RGB, non-interlaced
```

### Step 2: Analyze File Structure

PNG files have a specific structure:
1. **PNG Signature:** `89 50 4E 47 0D 0A 1A 0A` (8 bytes)
2. **Chunks:** Multiple chunks containing data
3. **IEND Chunk:** Marks the end of the PNG file (always `00 00 00 00 49 45 4E 44 AE 42 60 82`)

### Step 3: Inspect Beyond the PNG IEND Chunk

Using Python to analyze the binary content:

```python
with open("poster.png", 'rb') as f:
    data = f.read()

# The PNG IEND chunk ends at position 17058
# Check what's after it
print(data[17070:])
```

### Step 4: Discover Hidden Data

Upon examining the bytes after the PNG's IEND chunk, we find:

```
\n0xV01D{PNG_ENDS_BUT_DATA_STAYS}\n
```

### Technical Details

- **File Size:** 17,103 bytes
- **PNG Data Size:** ~17,070 bytes (up to and including IEND chunk)
- **Hidden Data Offset:** 17,070 bytes
- **Hidden Data:** `0xV01D{PNG_ENDS_BUT_DATA_STAYS}` (appended after valid PNG)

PNG chunks found in the file:
- `IHDR` (Image Header) at position 8, length 13
- `IDAT` (Image Data) at position 33, length 17,013
- `IEND` (Image End) at position 17,058, length 0

## Exploitation Technique

This challenge demonstrates **file appending steganography** (also called "data dropper" technique):

1. **Valid PNG File:** The image itself is a completely valid PNG file that can be opened normally
2. **Hidden Data:** Additional data is appended after the PNG's IEND chunk
3. **No Corruption:** PNG viewers ignore data after IEND, so the image displays normally
4. **Hidden in Plain Sight:** The flag is literally there, accessible via binary file analysis

## Why This Works

PNG files (and many other file formats) are **length-delimited**. They know where they end based on specific markers and chunk information, not by file size. This means:
- Any data appended after the IEND chunk is technically outside the PNG file structure
- PNG parsers ignore this data entirely
- The file remains valid and opens normally

## Tools Used for Solution

1. **Python:** File analysis and hex examination
2. **Binary Analysis:** Manual inspection of file structure
3. **Hex Dump:** Visualization of raw bytes

## Complete Python Solution Script

```python
#!/usr/bin/env python3

import os

file_path = "poster.png"
file_size = os.path.getsize(file_path)

print(f"[*] File size: {file_size} bytes")

with open(file_path, 'rb') as f:
    data = f.read()

# Verify PNG signature
if data[:8] == b'\x89PNG\r\n\x1a\n':
    print("[+] Valid PNG signature found")

# Parse PNG chunks
print("\n[*] Parsing PNG chunks:")
pos = 8
chunk_count = 0

while pos < len(data):
    if pos + 8 > len(data):
        break
    
    length = int.from_bytes(data[pos:pos+4], 'big')
    chunk_type = data[pos+4:pos+8].decode('latin1', errors='ignore')
    
    print(f"    Chunk {chunk_count}: Type={chunk_type}, Length={length}, Pos={pos}")
    
    if chunk_type == 'IEND':
        print(f"[+] IEND chunk found at position {pos}")
        data_start = pos + 12  # Skip length (4) + type (4) + CRC (4)
        print(f"[+] Hidden data starts at position {data_start}")
        break
    
    pos += 4 + 4 + length + 4
    chunk_count += 1

# Extract and display hidden data
print("\n[*] Hidden data after PNG IEND:")
hidden_data = data[data_start:].decode('latin1', errors='ignore').strip()
print(f"[!] FLAG: {hidden_data}")
```

## Key Takeaways

1. **Don't Trust File Extensions:** Always verify file contents
2. **Understand File Formats:** Know the structure of common formats
3. **Binary Analysis:** Hex editors and binary viewers are essential CTF tools
4. **File Appending:** A simple but effective steganography technique
5. **Challenge Naming:** "Poster Drop" hints at data being "dropped" at the end

## The Flag

```
0xV01D{PNG_ENDS_BUT_DATA_STAYS}
```

## Challenge Difficulty Assessment

**Difficulty: Easy** ✓

- Simple file structure (PNG is well-documented)
- Data hiding method is straightforward (file appending)
- No encryption or complex processing required
- Requires basic binary analysis skills

---

**Author:** CTF Challenge Creator  
**Writeup Date:** May 19, 2026  
**Status:** Solved ✓
