# astral propagation — PCBC Padding Oracle Attack

**Category:** Crypto
**Challenge:** `astral propagation`

## The service

```python
import secrets
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.strxor import strxor

MESSAGE = b'propagating cipher block chaining'

class Pcbc:
    def __init__(self, key):
        self.cipher = AES.new(key, AES.MODE_ECB)

    def encrypt(self, buf):
        buf = pad(buf, 16)
        iv = get_random_bytes(16)
        out = iv
        for i in range(0, len(buf), 16):
            p = buf[i:i+16]
            c = self.cipher.encrypt(strxor(iv, p))
            iv = strxor(p, c)
            out += c
        return out

    def decrypt(self, buf):
        iv = buf[:16]
        out = bytes()
        for i in range(16, len(buf), 16):
            c = buf[i:i+16]
            p = strxor(iv, self.cipher.decrypt(c))
            iv = strxor(p, c)
            out += p
        out = unpad(out, 16)
        return out
```

The server repeatedly reads a hex-encoded "ciphertext" from us and runs `Pcbc.decrypt` on it:

- if `unpad` raises → prints `failed to decrypt`
- if it decrypts to something other than `MESSAGE` → prints `incorrect message`
- if it decrypts to exactly `MESSAGE` → prints the flag

We never see plaintext directly — only which of those three buckets we landed in. That single bit ("padding valid?") is enough.

## Why PCBC doesn't save you here

PCBC ("Propagating CBC") chains the *plaintext* into the next block's IV as well as the ciphertext:

```
p_i      = iv_i XOR D(C_i)
iv_{i+1} = p_i XOR C_i
```

This is often described as resistant to the classic Vaudenay padding-oracle attack because flipping a bit anywhere corrupts every block downstream — you can't do the usual "peel off one byte at a time across a long, fixed ciphertext" trick.

But decryption of a *single* block only depends on the chaining value feeding into it and the block itself. If I send a bare 2-block message `X || C`, the server computes:

```
p = X XOR D(C)
```

That is *exactly* the CBC padding-oracle primitive — `X` plays the role of the IV, `C` is the ciphertext block. Since I fully control `X`, I can brute-force it byte-by-byte to make `p` end in valid PKCS7 padding, exactly as in a standard CBC padding-oracle attack. When the oracle reports `incorrect message` (i.e. it decrypted successfully but the message just wasn't a match), that tells me the padding was valid. `failed to decrypt` means invalid padding.

This gives me, for **any ciphertext block `C` I choose**, the ability to recover:

```
I = D(C) = AES_ECB_decrypt(C)
```

without ever knowing the key. In other words, PCBC's "propagation" defense only actually protects a ciphertext that's already fixed and multi-block — it does nothing to stop a chosen-ciphertext, single-block query.

## From "decrypt any block" to "encrypt anything"

Being able to compute `D(C)` for a `C` of my choosing turns out to be enough to **forge a full ciphertext that decrypts to an arbitrary chosen plaintext**, by building it backwards.

Target plaintext (PKCS7-padded) splits into blocks `P0, P1, P2`. I want ciphertext `IV, C0, C1, C2` such that decrypting it yields exactly `P0, P1, P2`.

Work from the **last** block to the first:

1. **Block 2 (last):** Pick `C2` freely (e.g. all zero bytes). Recover `I2 = D(C2)` via the padding-oracle byte search.
   Decryption requires `iv_2 XOR I2 = P2`, so the chaining value feeding into this block must be:
   `iv_2 = P2 XOR I2`

2. Since `iv_2 = P1 XOR C1` (PCBC's chaining rule) and `P1` is already known (it's part of our target message), this **forces**:
   `C1 = iv_2 XOR P1`
   — no freedom left; `C1` is now a concrete value.

3. **Block 1:** Recover `I1 = D(C1)` for that concrete `C1`. Required `iv_1 = P1 XOR I1`, which forces:
   `C0 = iv_1 XOR P0`

4. **Block 0 (first):** Recover `I0 = D(C0)`. This time the chaining value `iv_0` *is* the explicit IV field in the ciphertext blob — nothing forces it, we just set it directly:
   `IV = P0 XOR I0`

Assemble `IV || C0 || C1 || C2` and send it to the server. It decrypts to exactly `MESSAGE` (with valid PKCS7 padding), and the server prints the flag.

## Recovering `D(C)` (the padding-oracle core)

Standard byte-at-a-time CBC padding oracle, applied to the 2-block message `X || C`:

```python
def recover_D(C):
    known = bytearray(16)                 # will hold D(C)
    for pos in range(15, -1, -1):
        pad_val = 16 - pos
        for guess in range(256):
            X = bytearray(16)
            for j in range(pos + 1, 16):
                X[j] = known[j] ^ pad_val   # force already-known suffix to the new pad value
            X[pos] = guess
            resp = ask(bytes(X) + C)
            if "incorrect message" in resp:      # valid padding!
                if pos == 15:
                    # disambiguate a possible false positive (e.g. real pad was 02 02)
                    X2 = bytearray(X); X2[14] ^= 0xFF
                    if "failed to decrypt" in ask(bytes(X2) + C):
                        continue
                known[pos] = guess ^ pad_val
                break
    return bytes(known)
```

Cost: up to 256 queries per byte × 16 bytes × 3 blocks ≈ a few thousand queries — trivial for a scripted TCP session.

## Full exploit

```python
import socket, sys

HOST, PORT = "tcp.flagyard.com", 24967
MESSAGE = b'propagating cipher block chaining'
BS = 16

def pkcs7_pad(data, block_size=16):
    n = block_size - (len(data) % block_size)
    return data + bytes([n]) * n

def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

class Conn:
    def __init__(self, host, port):
        self.s = socket.create_connection((host, port))
        self.buf = b""
        self.count = 0

    def _recv_until_prompt(self):
        while b"ciphertext (hex): " not in self.buf:
            chunk = self.s.recv(4096)
            if not chunk:
                break
            self.buf += chunk
        idx = self.buf.find(b"ciphertext (hex): ")
        line, self.buf = self.buf[:idx], self.buf[idx + len(b"ciphertext (hex): "):]
        return line.decode(errors="replace")

    def ask(self, ct: bytes) -> str:
        self.count += 1
        self.s.sendall(ct.hex().encode() + b"\n")
        lines = [l.strip() for l in self._recv_until_prompt().splitlines() if l.strip()]
        return lines[-1] if lines else ""

def recover_D(conn, C):
    known = bytearray(16)
    for pos in range(15, -1, -1):
        pad_val = 16 - pos
        found = False
        for guess in range(256):
            X = bytearray(16)
            for j in range(pos + 1, 16):
                X[j] = known[j] ^ pad_val
            X[pos] = guess
            resp = conn.ask(bytes(X) + C)
            if "incorrect message" in resp:
                if pos == 15:
                    X2 = bytearray(X); X2[14] ^= 0xFF
                    if "failed to decrypt" in conn.ask(bytes(X2) + C):
                        continue
                known[pos] = guess ^ pad_val
                found = True
                break
        if not found:
            raise RuntimeError(f"failed at byte {pos}")
    return bytes(known)

def build_ciphertext(conn, target_blocks):
    n = len(target_blocks)
    C = [None] * n
    C[n - 1] = bytes(16)
    I = recover_D(conn, C[n - 1])
    iv_needed = xor(target_blocks[n - 1], I)
    for i in range(n - 1, 0, -1):
        C[i - 1] = xor(iv_needed, target_blocks[i - 1])
        I = recover_D(conn, C[i - 1])
        iv_needed = xor(target_blocks[i - 1], I)
    IV = iv_needed
    out = IV
    for c in C:
        out += c
    return out

def main():
    conn = Conn(HOST, PORT)
    conn._recv_until_prompt()

    padded = pkcs7_pad(MESSAGE, BS)
    blocks = [padded[i:i + BS] for i in range(0, len(padded), BS)]

    ct = build_ciphertext(conn, blocks)
    print("[+] Server response:", conn.ask(ct))

if __name__ == "__main__":
    main()
```

## Result

The crafted ciphertext decrypts (under the server's unknown key) to exactly `b'propagating cipher block chaining'` with valid PKCS7 padding, without the key ever being known or brute-forced. The server prints the flag.

## Takeaways

- A padding oracle is not just a decryption oracle — with the reverse-block construction it's a full **encryption oracle**: you can produce ciphertext for *any* chosen plaintext.
- PCBC's plaintext-chaining only prevents attacks that reuse/tamper with blocks of an existing, fixed multi-block ciphertext. It adds no protection against chosen 2-block probes, which is all a padding-oracle byte-recovery needs.
- Moral: don't distinguish "bad padding" from "wrong plaintext" in your error messages, regardless of cipher mode.
