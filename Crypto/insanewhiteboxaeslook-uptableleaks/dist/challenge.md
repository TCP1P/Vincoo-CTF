# INSANE Whitebox AES – Look-up Table Leaks

You found a “whitebox-style” AES implementation that refuses to give you an oracle… but it *did* dump all its lookup tables.

Unfortunately the dump is full of decoys.

Your goal:

1. Recover the **AES-128 master key** using `tables.bin` and a few known plaintext/ciphertext pairs.
2. Use that key to decrypt `flag.enc`.

Files you get:

- `tables.bin` — binary dump of **384** lookup tables (shuffled order, no labels).
- `known_pairs.txt` — some known pairs (ECB + PKCS#7).
- `flag.enc` — encrypted flag (ECB + PKCS#7).

---

## `tables.bin` format

All integers are **little-endian**.

Header:

- 4 bytes  : magic
- u32      : version
- u32      : table_count
- u32      : reserved
- u32      : header_noise_len
- bytes    : header_noise (`header_noise_len` bytes)

Then `table_count` tables follow, back-to-back:

- each table is `256 × u32` (so **1024 bytes per table**)

There is **no metadata per table**.

---

## `known_pairs.txt` format

One pair per line:

`<pt16_hex>:<ct32_hex>`

The plaintext shown is **16 bytes** (it was padded to **32 bytes** before encryption).

---

## Hint

Some tables are “too structured” if you compare `T[x] XOR T[0]` instead of the raw values.

Good luck. :)
