# Rimal Capture — Forensics Writeup

## Challenge Details

- **Challenge Name:** Rimal Capture
- **Category:** Forensics
- **Points:** 100

---

## Description

> An incident capture mixes routine traffic with one operator session.  
> The final text was not entered as cleanly as the first pass suggests.

The challenge hinted that the final text involved typing mistakes or corrections.

---

# Step 1 — Open the Capture

After downloading the challenge files, open the `.pcap` file in Wireshark.

At first glance, the capture contains normal network traffic mixed with USB activity.

---

# Step 2 — Search for Suspicious Data

While analyzing HTTP traffic, a fake flag appears inside a User-Agent string:

```text
0xV01D{http_user_agent_is_bait}
```

This looked suspicious because the challenge description mentioned that the final text was *not entered cleanly*.

So the HTTP flag was only bait.

---

# Step 3 — Analyze USB HID Traffic

Apply the following filter in Wireshark:

```wireshark
usbhid.data
```

This reveals USB keyboard HID packets.

Each packet represents keyboard input from a user.

---

# Step 4 — Decode Keystrokes

Export or decode the HID data using a USB HID keyboard parser/script.

Recovered keystrokes:

```text
flag=0xV01D{hid_backspacx<BACKSPACE>es_are_evidence}
```

The user mistakenly typed:

```text
hid_backspacxes_are_evidence
```

Then pressed **Backspace** to remove the extra `x`.

---

# Step 5 — Reconstruct the Final Input

After applying the backspace correctly:

```text
0xV01D{hid_backspaces_are_evidence}
```

---

# Final Flag

```text
0xV01D{hid_backspaces_are_evidence}
```

---

# Learning Points

- USB HID traffic can leak typed keyboard input.
- Always inspect editing keys like Backspace.
- Fake flags are often placed intentionally in forensic challenges.
- Reconstructing user intent is important in HID analysis.
