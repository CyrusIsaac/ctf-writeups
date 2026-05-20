# CTF Writeup – Easy First Letters

## Challenge Description

A small artifact was provided with the instruction:

> "Inspect it carefully and recover the single valid flag."

The archive contained a ZIP file named:

```text
01_easy_first_letters.zip
```

---

## Step 1 – Extract the ZIP

After extracting the archive, the contents revealed a very small challenge with a strong hint in the title:

```text
easy_first_letters
```

This immediately suggests checking the **first letters** of something.

---

## Step 2 – Inspect the Files

By examining the included text/content carefully, the first letter of each relevant line/word formed a hidden message.

The extracted sequence spelled:

```text
FIRST_LETTERS_NEVER_LIE
```

---

## Step 3 – Construct the Flag

The challenge explicitly provided the flag format:

```text
0xV01D{.....}
```

Placing the recovered message inside the braces gives:

```text
0xV01D{FIRST_LETTERS_NEVER_LIE}
```

---

# Final Flag

```text
0xV01D{FIRST_LETTERS_NEVER_LIE}
```
