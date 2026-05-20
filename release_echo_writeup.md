# Release Echo — CTF Writeup

## Challenge Information

- **Category:** Misc
- **Challenge Name:** Release Echo
- **Flag Format:** `0xV01D{...}`

---

## Initial Analysis

The challenge provided a self-contained ZIP artifact:

```text
07_hard_git_fossil.zip
```

The name strongly hinted toward:

- Git history
- Fossilized / deleted data
- Commit recovery
- Hidden release information

The first step was extracting the archive and inspecting its contents.

---

## Enumeration

After extraction, the repository structure suggested that the challenge involved historical data recovery rather than active application exploitation.

Useful checks included:

```bash
ls -la
find . -type f
git log --all --oneline
git reflog
git fsck --lost-found
```

The important clue came from inspecting repository history and deleted objects.

---

## Recovering Hidden Data

The repository contained traces of removed content that still existed inside Git objects.

Using:

```bash
git fsck --lost-found
```

and examining dangling blobs/commits eventually revealed hidden historical content.

Relevant object inspection:

```bash
git show <object_hash>
```

or:

```bash
git cat-file -p <object_hash>
```

One of the recovered historical entries exposed the flag.

---

## Flag

```text
0xV01D{HISTORY_REMEMBERS}
```

---

## Key Takeaway

Even if files are deleted from the current working tree, Git history and dangling objects may still preserve sensitive information.

Common recovery techniques:

- `git reflog`
- `git fsck`
- dangling blob inspection
- old commits/tags/branches
- stash recovery

Git remembers more than developers expect.
