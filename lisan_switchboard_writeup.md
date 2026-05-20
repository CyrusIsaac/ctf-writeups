# Lisan Switchboard - Rev Writeup

## Challenge Info

- Category: Reverse Engineering
- Name: Lisan Switchboard
- Points: 100

Challenge description:

> "A stripped verifier ships with a stale operator note. Names in the archive are less reliable than behavior."

---

# Initial Analysis

After extracting the archive, the challenge contained a stripped binary and some misleading files.

First step was running basic enumeration:

```bash
file chall
strings chall
checksec chall
```

The binary was stripped, so symbols were removed.

During `strings`, several fake-looking flags appeared:

```text
0xV01D{prompt_file_said_so}
0xV01D{strings_did_not_reverse_the_switchboard}
```

The challenge description already hinted that names and notes are unreliable:

> "Names in the archive are less reliable than behavior."

This suggested the visible strings were decoys.

---

# Dynamic Analysis

Running the binary showed it expects a flag input.

Using Ghidra/IDA, the verification function was identified.

The verifier performed:

1. Length check
2. XOR transformation
3. Lookup-table transformation
4. Final comparison against a target byte array

---

# Verification Logic

The binary used:

- 32-byte XOR key
- 256-byte VM/lookup table
- 48-byte target array

Pseudo-code:

```c
for (i = 0; i < 48; i++) {
    tmp = input[i] ^ xor_key[i % 32];
    out = vm_table[tmp];

    if (out != target[i]) {
        fail();
    }
}
```

Because the lookup table is reversible, the process can be inverted.

---

# Reversing the Check

To recover the original input:

```python
orig = inverse_vm[target[i]] ^ xor_key[i % 32]
```

Building the inverse lookup table and reversing all 48 bytes recovered the real flag.

---

# Real Flag

```text
0xV01D{vm_tables_do_not_care_about_prompt_files}
```

---

# Key Takeaways

- Ignore obvious strings in reverse engineering challenges.
- Always trust actual program behavior over filenames or notes.
- Lookup-table based verifiers are usually reversible.
- Stripped binaries can still be solved through control-flow analysis.

---
