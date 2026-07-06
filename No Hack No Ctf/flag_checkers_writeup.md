# Flag Checkers — CTF Writeup

**Challenge:** Flag Checkers
**Flag:** `NHNC{2b06cc91a6d35aa24e886394ab574e1c4b4f9eed7ad6d7aca7a3228a39cf318f0a3c523a72263b0995f6417f3b5fd56443d482fbd9b430a578c4038a451028b9}`

## First impressions

We're handed a single file, `flag_checkers`, and told to run it like this:

```
echo -n "NHNC{...}" | ./flag_checkers
```

Running `file` on it shows a statically linked, stripped x86-64 ELF. No symbols, no easy `strings` output worth mentioning, and a "Wrong" response to basically anything. Classic crackme setup — the fun part is going to be figuring out *why* it's wrong.

## Poking at it

Static + stripped is annoying but not scary on its own. What made this one interesting was how small the `.text` section was (about 1.2 KB) for something that turned out to do a genuinely nontrivial amount of work. That's usually a sign the binary is doing raw syscalls by hand instead of linking libc, and possibly hiding logic that only appears at runtime.

Disassembling it confirmed both suspicions:

- It talks directly to the kernel via `syscall` instructions (mmap, read, fork, futex, exit) — no libc wrappers at all.
- Scattered through the code were these odd little blocks:

  ```
  push rax
  push rcx
  pushf
  movabs $0xd1b54a32d192ed03, rax
  imul   $0x27d4eb2f, rax, rax
  ror    $0x11, rax
  xor    rax, rcx
  bswap  rcx
  popf
  pop rcx
  pop rax
  ```

  At first glance this looks like it's doing something important with `rax`/`rcx`/the flags register. But look closer: it pushes `rax`, `rcx`, and the flags at the start, does a bunch of math that never touches memory or leaves the block, and then pops everything straight back off the stack in reverse order. It's a no-op. Pure junk, dropped in specifically to make the disassembly look scarier and break naive auto-analysis. Once you spot the pattern once, you can mentally delete it everywhere else it shows up.

## The self-modifying pieces

A few chunks of "data" get XOR-decoded into executable memory before use:

- 11 bytes XORed with `0x5a` get written into a freshly `mmap`'d RWX page. Once decoded, it turned out to be a tiny 11-byte stub: call through a function pointer, then `rol eax, <patched immediate>`, then `ret`. The rotate amount itself gets patched at runtime — so the same 11 bytes behave differently depending on where in the algorithm you are.
- 24 bytes XORed with `0xa5a5a5a5` decode into six 32-bit "round key" constants (fun ones too — `0xa5a5f00d`, `0x1337beef`, `0xbadc0de`, `0xfaceb00c`, `0xdeadc0de`, `0x8badf00d`).
- Four 256-byte lookup tables sit in `.data` unencrypted — essentially S-boxes, swapped in and out depending on position.

## Wait, why does it fork three times?

This was the most entertaining rabbit hole. Early in `main`, the binary calls `fork()` twice, producing three processes total. Each one gets tagged 0, 1, or 2 and stores that tag in a shared (`MAP_SHARED`) memory page.

Then all three processes sit in a loop that uses `futex()` — the same primitive Linux mutexes are built on — to hand off a "turn counter" between them. Whichever process's tag matches the current turn gets to process the next byte of input, then wakes the others up and goes back to waiting.

Net effect: the entire character-processing loop is round-robined across three separate OS processes, purely for obfuscation. It's functionally identical to a normal single-threaded loop — it just makes tracing it in a debugger or strace considerably more annoying, since only one of the three processes ever produces the final result.

Once we realized only the "tag 0" process (the original parent) ever reaches the final comparison and exit code, we stopped worrying about the other two — they run to completion harmlessly in the background and can be ignored.

## The actual algorithm

Stripping away the obfuscation, here's what's really happening:

1. The flag is read into a buffer and split into 8-byte blocks.
2. Each block is XORed with a running 64-bit state (starting from a fixed IV), then split into two 32-bit halves — call them `L` and `R`.
3. Those halves go through **15 rounds of a Feistel network**:
   - `L` gets XORed with a round constant (a mix of one of the six magic keys and a golden-ratio-based multiplier, `0x9e3779b9` — the classic Fibonacci hashing constant).
   - The result is run through one of the four S-boxes (selected in a rotating pattern based on round number) and rotated by an amount that also depends on the round number.
   - That output gets XORed into `R`.
   - `L` and `R` swap, Feistel-style.
4. After 15 rounds, the resulting 64-bit block becomes the new running state, gets byte-swapped, and is compared against a fixed 136-byte target baked into the binary.
5. This repeats for 17 blocks (136 bytes total), chained together like CBC mode — each block's output feeds into the next block's XOR step.

If every block matches, it prints `Correct`. Otherwise, `Wrong`.

## Turning it around

The nice thing about a Feistel network is that it's built entirely out of XORs and a per-round function `F` — nothing in the swap step requires knowing `F`'s inverse. That meant we could:

1. Extract the six round keys, four S-boxes, and the 136-byte target straight out of the binary's `.data` section with a small Python script.
2. Rebuild the round function faithfully — including the exact rotate/S-box selection formulas per round.
3. Verify our model was byte-for-byte correct by breaking on the comparison routine in GDB with a throwaway input, dumping the computed buffer, and diffing it against our own from-scratch simulation in Python. (This step mattered — our first attempt at reversing the logic was subtly wrong about which values get swapped where, and this direct comparison caught it immediately.)
4. Once the forward simulation matched exactly, run the recurrence **backward**: starting from the known target output for each block, walk the Feistel rounds in reverse to recover the original 8-byte plaintext block, then undo the running-state XOR to get the actual flag bytes.

No brute forcing, no guessing — just straight algebra once the structure was correctly understood.

## The flag

```
NHNC{2b06cc91a6d35aa24e886394ab574e1c4b4f9eed7ad6d7aca7a3228a39cf318f0a3c523a72263b0995f6417f3b5fd56443d482fbd9b430a578c4038a451028b9}
```

The content between the braces is 128 hex characters — the length of a SHA-512 hash written out in hex. It's plaintext in the sense that it's literally the correct ASCII string the checker wants; it just isn't an English phrase, which threw us for a second before we double checked it against the binary.

Confirmed directly:

```
$ echo -n 'NHNC{2b06cc91a6...1028b9}' | ./flag_checkers
Correct
```

And as a sanity check, flipping the very last hex digit breaks it:

```
$ echo -n 'NHNC{2b06cc91a6...1028b8}' | ./flag_checkers
Wrong
```

Confirming the recovered flag is exact, not just "close enough."

