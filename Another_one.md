# "Another One" - CTF Challenge Writeup

## The Challenge

You're given a mysterious file called `executable` (312 KB) and a cryptic hint:

> *"I cannot anymore with Khaled. He said 'another one' and meant another byte, another row, another direction. The man takes everything too literally."*

Plus some context clues:
- The track doesn't start where it should
- The key is hiding in the noise
- Flag format: `CTFAC{SHA256(key)}`

Your mission: Find the key and hash it.

--

## The Investigation

### First Impression: What's This File?

You run `file` on it. The response? Just "data". Not helpful. Let's dig deeper.

When you check the hex dump, you see something weird:
```
00000000: 00 00 00 00 00 00 00 00 00 01 01 02 46 4c 45 7f
```

There's junk at the beginning, then "FLE"... then something that looks like an ELF header marker (0x7f). This smells like intentional obfuscation.

### The Strings Give It Away

You extract all the readable text from the file. That's when it hits you—**every single string is backwards**:

```
Original strings found:
  'D-xunil-dl/46bil/'      → /lib64/ld-linux-D
  'niam_tgered_MTI_'       → _ITM_dereg_main
  'elbaTenolCM'            → MCloneTable
  'seR_dniwnU_'            → _Unwind_Res
```

This isn't just a reversed ELF binary—it's something with reversed metadata. The challenge mentioned "the track does not even start where it should." This is a clue: the data is scrambled or out of order.

### The Audio Discovery

You think: *"Wait, the challenge talks about a track. Track could mean... audio?"*

You try something bold. What if this binary garbage is actually **raw audio data**? You construct a proper WAV file header:

- **Sample Rate:** 44,100 Hz (standard CD quality)
- **Channels:** 2 (stereo)
- **Bit Depth:** 16-bit
- **Duration:** ~1.77 seconds

You wrap the binary data with this header and... it works. The file is suddenly recognized as valid audio (RIFF/WAVE format). The "noise" Khaled is waiting in? It's literally audio noise/music.

---

## The Plot Twist

Here's where most people get distracted.

You find a **substitution cipher lookup table** buried at offset `0x5D70`:

```
19 08 07 06 05 04 03 02 17 16 15 14 13 12 11 10
25 24 23 22 21 20 29 18 33 32 31 30 39 28 27 26
41 40 49 38 37 36 35 34 59 48 47 46 45 44 43 42
... (and so on)
```

This looks important. It's ordered, it's hiding in the binary, it must be the key to everything, right? You spend time analyzing it. You try converting it to hex, treating it as a cipher, applying it as a permutation...

**Nothing works.**

This is the red herring. The challenge creator put it there to make you overthink.

---

## The Real Solution

You step back and re-read the challenge description:

> *"He said 'another one' and meant another byte, another row, another direction. **The man takes everything too literally.**"*

The emphasis is key. You're being told to take things literally.

What's said in the challenge?
- The title: **"Another One"**
- Khaled's catchphrase: **"Another One"** (if you know DJ Khaled)
- The message: He takes things literally

So what if... the key is just the literal phrase?

```
Key = "another_one"
```

No complex cipher. No audio decoding. No weird permutation. Just a string: `another_one`

### Computing the Flag

You hash it:

```bash
echo -n "another_one" | sha256sum
# 6602702c781dfda32c843da203141327135fb4e90d0b889c5dc4720c01df26f2
```

And format it according to the flag template:

```
CTFAC{6602702c781dfda32c843da203141327135fb4e90d0b889c5dc4720c01df26f2}
```

**That's it. You're done.**

---

## Why This Challenge is Clever

1. **Multiple Layers of Misdirection**
   - Reversed binary strings make it look like a compiled executable
   - Audio file wrapped in raw binary data
   - A complex-looking cipher table that serves no purpose
   - All designed to make you overthink

2. **The Obvious-in-Hindsight Trick**
   - The answer is sitting in the title and description the whole time
   - You just had to ignore all the noise and take the hint literally

3. **The Ironic Message**
   - The challenge warns you: "takes everything too literally"
   - The solution: Take the message literally!
   - It's a clever play on expectations

---

## Key Takeaways

**For CTF Solving:**
- Don't get lost in the technical details
- Re-read the challenge description carefully
- Sometimes the simplest answer is correct
- Red herrings exist; not everything you find is important
- The challenge's own hints often tell you the solution method

**For Challenge Creators:**
- This is a masterclass in misdirection
- Make people think they need to decode audio, break ciphers, or reverse binaries
- Hide the answer in plain sight in the description
- Use clever wordplay ("takes everything too literally" as a clue)

---

## The Files

If you wanted to solve this programmatically, here's what you'd do:

```python
import hashlib

key = "another_one"
sha256_hash = hashlib.sha256(key.encode()).hexdigest()
flag = f"CTFAC{{{sha256_hash}}}"
print(flag)
```

That's literally the entire solution in 4 lines of code.

---

## Final Flag

```
CTFAC{6602702c781dfda32c843da203141327135fb4e90d0b889c5dc4720c01df26f2}
```

---


