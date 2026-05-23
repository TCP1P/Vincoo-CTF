# TimeBomb VM — Official Writeup (High Level)

## Gambaran

Service menjalankan 5 round. Tiap round server mengirim:

- `SEED`: 32-bit (8 hex)
- `BYTECODE_B64`: base64 dari bytecode terenkripsi
- `CYCLE_BUDGET`: batas siklus VM

Kamu harus mengirim balik token 32 byte (64 hex) dalam **1200ms**.

## Kenapa `timebombvm` (dist binary) tidak cukup

Binary `timebombvm` sengaja dibuat sebagai “reference implementation” yang tidak optimal.
Kalau dipakai sebagai oracle/subprocess per round, kemungkinan besar kalah oleh timer.
Intended solve: reverse VM & codec lalu buat emulator sendiri yang lebih cepat.

## Langkah solve

1) **Reverse codec bytecode**

   - Base64 decode → ciphertext bytes
   - Decrypt stream cipher berbasis `seed` dan indeks round
   - Dapat plaintext yang punya header `TBVM...` + instruction stream

2) **Reverse opcode permutation**

   Opcode di instruction stream bukan 0..15 langsung. Ada mapping per-seed yang menghasilkan 16 byte unik.
   Untuk eksekusi, buat inverse map `opcode_byte -> semantic_opcode`.

3) **Reverse VM**

   - 8 regs 32-bit, mem 256 byte, flag `z`
   - Operand campuran fixed + varint (ULEB/SLEB)
   - Ada opcode nonlinear `MIX` yang memakai S-Box 256 byte dari seed
   - `MEMXOR` melakukan XOR region mem pakai regs + S-Box

4) **Emulate cepat**

   - Precompute `sbox` dan `opcode_inv` per round
   - Gunakan `bytearray` untuk memory dan integer list untuk regs
   - Implement parser bytecode satu pass (PC) tanpa membangun AST

5) **Kirim token**

   Token adalah output 32 byte dari opcode `OUT` (hex 64 char, case-insensitive diterima).

## File solver

`solver/solve.py` mengimplementasikan semua langkah di atas dan menangani parsing protocol + reconnect.
