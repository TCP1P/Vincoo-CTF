python3 src/gen.py# README_PANITIA (internal)

## Generate instance (buat ulang dist/*)

Jalankan dari repository root:

    python3 src/gen.py

Optional:
- FLAG=... untuk override isi flag (default sama seperti di challenge.yml)
- SEED=... menambah entropy (tetap tidak reproducible tanpa src/panitia_salt.bin)
- REPRODUCE=1 untuk reuse src/panitia_seed.bin (reproduce instance terakhir persis)

Private files yang dibuat di src/ (JANGAN DIKIRIM ke peserta):
- panitia_salt.bin
- panitia_seed.bin

## Verify (recover key + decrypt flag)

    python3 solver/solve.py

Output harus mencetak flag (exact).
