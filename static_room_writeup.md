# Static Room — CTF Writeup

## Challenge Description

> Static Room  
> FINAL SUBMISSION WARNING  
> This challenge allows only 2 flag attempts. Submit only when you are sure.  
> The provided artifact contains everything needed to recover one valid flag.

Flag format:

`0xV01D{......}`

---

## Initial Analysis

The challenge provided a ZIP archive named:

`06_medium_morse_static.zip`

After extracting the archive, the main artifact was an audio file containing heavy static noise.

The challenge title **"Static Room"** hinted that the noise itself might hide a signal.

---

## Step 1 — Listening Carefully

Opening the audio in an audio editor/spectrogram tool revealed repeating short and long beeps beneath the static.

These patterns resembled **Morse code**.

---

## Step 2 — Decode Morse

After isolating the tones and transcribing the Morse sequence, the decoded message was:

```text
0X V01D MORSE MAKES NOISE
```

---

## Step 3 — Construct the Flag

The challenge specified the flag format:

```text
0xV01D{......}
```

Converting the decoded phrase into the required format:

```text
0xV01D{MORSE_MAKES_NOISE}
```

---

# Final Flag

```text
0xV01D{MORSE_MAKES_NOISE}
```
