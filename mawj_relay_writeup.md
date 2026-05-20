# Mawj Relay — CTF Writeup

## Challenge Information

- **Challenge Name:** Mawj Relay
- **Category:** Android / Reverse Engineering
- **Author:** 0x4sh

---

# Initial Analysis

The challenge provided a ZIP archive containing a small Android APK.

After extracting the APK, the following files were identified as important:

```text
AndroidManifest.xml
classes.dex
assets/push_routes.bin
assets/README_NOTE.txt
res/values/strings.xml
```

---

# Step 1 — Looking for Easy Flags

Running `strings` on the APK quickly revealed two fake flags:

```text
0xV01D{ai_took_the_push_bait}
0xV01D{debug_strings_are_decoys}
```

The `README_NOTE.txt` also hinted that debug strings should not be trusted.

These were intentional decoys.

---

# Step 2 — Inspecting the DEX Strings

Extracting strings from `classes.dex` revealed useful information:

```text
ACTION=com.void.echo.PUSH
LABEL=EchoPush
open assets/push_routes.bin
ignore res/values/strings.xml debug_flag
```

This suggested that:

- The app processes push notifications
- The real data is stored in `assets/push_routes.bin`
- The values `ACTION` and `LABEL` are important

---

# Step 3 — Understanding the Key Generation

Inside `strings.xml` there was another useful hint:

```text
key = sha256(action + ':' + label)
```

Using the discovered values:

```text
action = com.void.echo.PUSH
label  = EchoPush
```

The generated string becomes:

```text
com.void.echo.PUSH:EchoPush
```

Computing SHA-256:

```text
4276edc747793b5a82e66be42a9a901a4d72f2a2fd5db3a344b99c4f2055b30b
```

---

# Step 4 — Analyzing `push_routes.bin`

The file started with:

```text
VPUSH1
```

This indicated a custom binary format.

After examining the data structure and entropy, it became clear the payload was XOR-encrypted.

The SHA-256 hash derived earlier was used as the repeating XOR key.

---

# Step 5 — Decryption

Using the SHA-256 digest as a repeating XOR stream successfully decrypted the payload.

Recovered content:

```json
{
  "route":"prod/receiver/primary",
  "priority":42,
  "flag":"0xV01D{push_receiver_xor_is_not_crypto}",
  "crc32":"verified after decrypt"
}
```

---

# Final Flag

```text
0xV01D{push_receiver_xor_is_not_crypto}
```

---

# Key Takeaways

- Never trust obvious debug flags in reversing challenges
- APK assets often hide the real payload
- XOR with repeating keys is weak encryption
- Metadata and string resources frequently contain key derivation hints
