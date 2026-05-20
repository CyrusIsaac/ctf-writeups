# Canvas Drift — CTF Writeup

## Challenge Information

**Challenge Name:** Canvas Drift  
**Category:** Misc / Steganography  
**Flag Format:** `0xV01D{...}`

Recovered flag:

```text
0xV01D{LSB_PIXELS_TELL_STORIES}
```

---

# Initial Analysis

The challenge provided a ZIP archive containing an image-based artifact.  
The title **Canvas Drift** strongly hinted toward image manipulation or hidden data inside image pixels.

Typical indicators for this kind of challenge include:

- LSB steganography
- Hidden alpha channel data
- Metadata abuse
- Pixel-channel manipulation
- Embedded compressed payloads

---

# Step 1 — Extract the Archive

```bash
unzip 04_medium_lsb_canvas.zip
```

This revealed the challenge image.

---

# Step 2 — Basic File Inspection

First, verify the file type:

```bash
file canvas.png
```

Then inspect metadata:

```bash
exiftool canvas.png
```

No obvious flag appeared in metadata.

---

# Step 3 — Strings Analysis

Search for readable content:

```bash
strings canvas.png
```

No direct flag was visible.

---

# Step 4 — Steganography Investigation

Because the challenge title referenced **Canvas**, the next step was checking for hidden pixel data.

The strongest indicator was that the image looked visually normal while still having a relatively large file size.

This usually points to:

- hidden LSB data
- appended payloads
- encoded pixel channels

---

# Step 5 — Extract LSB Data

Using an LSB extraction tool:

```bash
zsteg canvas.png
```

The output revealed hidden text inside pixel bitplanes.

A useful extraction command was:

```bash
zsteg -E b1,r,lsb,xy canvas.png
```

This recovered the hidden message:

```text
0xV01D{LSB_PIXELS_TELL_STORIES}
```

---

# Final Flag

```text
0xV01D{LSB_PIXELS_TELL_STORIES}
```

---

# Key Takeaway

This challenge used classic **Least Significant Bit (LSB)** steganography inside image pixel channels.

The visible image was only a carrier, while the actual payload was hidden within modified pixel bits.
