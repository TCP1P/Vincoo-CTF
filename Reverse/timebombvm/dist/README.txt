TimeBomb VM (Reverse Engineering)
================================

Koneksi service:
  nc {{host}} {{port}}

Server mengadakan 5 rounds.
Untuk tiap round, kamu akan menerima:

  SEED: <8 hex>
  BC_LEN: <int>
  BYTECODE_B64: <...>
  CYCLE_BUDGET: <int>
  >

Tugas kamu: balas 1 baris token berukuran 32 bytes dalam hex (64 karakter hex).
Case-insensitive diterima.

Batas waktu input: 1200ms (server-side) per round.
Jika telat / salah format / salah token => disconnect.

Attachment
----------
- timebombvm: ELF Linux helper (dari source). Diberikan untuk membantu reverse.
  *Peringatan*: binary ini sengaja tidak optimal sehingga kurang cocok dijadikan oracle cepat.
- sample_session.txt: contoh transcript (tanpa jawaban).

Menjalankan helper bineri
-------------------------
Helper bisa dipakai untuk menghitung token dari satu round secara lokal.

Usage:
  ./timebombvm <seed_hex> <cycle_budget> <bytecode_b64>

Contoh:
  ./timebombvm deadbeef 120000 "AAAB..."

Output:
  64-hex token di stdout.

Catatan:
- Pastikan kamu mengirim token tepat 64 hex + newline.
- Program terenkripsi; helper akan auto-detect parameter internal yang dibutuhkan.
- Latensi jaringan ada, tapi timeout tetap ketat.
