# Glass Parcel - Writeup

## Challenge Overview

The challenge provided a single downloadable artifact and hinted that the file was **self-contained**.

The challenge name, **Glass Parcel**, suggested that the file might be transparent on the surface while hiding additional content internally, which is common in polyglot or embedded-file challenges.

Flag format:

```text
0xV01D{.....}
```

---

## Initial Inspection

After downloading the challenge archive, the first step was checking the file type.

Typical commands used:

```bash
file challenge_file
binwalk challenge_file
strings challenge_file
xxd challenge_file | less
```

The archive turned out to be a **polyglot-style file** containing hidden embedded data.

---

## Extraction Phase

Using `binwalk` revealed additional embedded sections inside the artifact.

Example:

```bash
binwalk -e challenge_file
```

This extracted hidden payloads from the file.

Further inspection of the extracted contents revealed readable strings related to the final flag.

---

## Recovering the Flag

Searching through the extracted files and strings exposed the hidden flag:

```text
0xV01D{POLYGLOT_FILES_CAN_SING}
```

---

# Final Flag

```text
0xV01D{POLYGLOT_FILES_CAN_SING}
```
