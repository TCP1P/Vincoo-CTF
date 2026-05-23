#!/usr/bin/env python3
"""
Instance generator for the offline crypto challenge.

Creates (in ./dist):
- tables.bin
- known_pairs.txt
- flag.enc

Private files (kept in ./src, NEVER ship to players):
- panitia_salt.bin
- panitia_seed.bin

Dependencies: pycryptodome only.
"""
from __future__ import annotations

import os
import struct
import hashlib
import subprocess
import sys
from typing import List, Dict, Tuple

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

# -----------------------------
# Constants
# -----------------------------
DEFAULT_FLAG = "VincooCTF{0bfu5c4t10n_15_my_3ncrypt10n}"
MAGIC = b"VWBX"
VERSION = 3
TABLE_COUNT = 384
SIG_NIBBLE = 0xA  # 4-bit signature (used only for table selection)
KNOWN_PAIRS_N = 8

# AES S-box (needed for key schedule)
SBOX = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
]
INV_SBOX = [0] * 256
for i, v in enumerate(SBOX):
    INV_SBOX[v] = i

RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]  # 1..10 used

# -----------------------------
# Deterministic RNG (seeded by private material)
# -----------------------------
class DRBG:
    def __init__(self, seed: bytes):
        self.key = hashlib.sha256(seed).digest()
        self.counter = 0

    def randbytes(self, n: int) -> bytes:
        out = b""
        while len(out) < n:
            self.counter += 1
            ctr = self.counter.to_bytes(8, "big")
            out += hashlib.sha256(self.key + ctr).digest()
        return out[:n]

    def rand_u32(self) -> int:
        return struct.unpack("<I", self.randbytes(4))[0]

    def randbelow(self, n: int) -> int:
        if n <= 0:
            raise ValueError("n must be > 0")
        while True:
            x = self.rand_u32()
            lim = (1 << 32) - ((1 << 32) % n)
            if x < lim:
                return x % n

    def shuffle(self, arr: List) -> None:
        for i in range(len(arr) - 1, 0, -1):
            j = self.randbelow(i + 1)
            arr[i], arr[j] = arr[j], arr[i]

    def rand_nonzero_byte(self) -> int:
        while True:
            b = self.randbelow(256)
            if b != 0:
                return b

# -----------------------------
# Tiny linear algebra over bits (32-bit and 8-bit)
# -----------------------------
def basis32_build(vectors: List[int]) -> Dict[int, int]:
    basis: Dict[int, int] = {}
    for v in vectors:
        x = v & 0xFFFFFFFF
        for p in sorted(basis.keys(), reverse=True):
            if (x >> p) & 1:
                x ^= basis[p]
        if x:
            p = x.bit_length() - 1
            basis[p] = x
    return basis

def basis32_reduce(v: int, basis: Dict[int, int]) -> int:
    x = v & 0xFFFFFFFF
    for p in sorted(basis.keys(), reverse=True):
        if (x >> p) & 1:
            x ^= basis[p]
    return x & 0xFFFFFFFF

def mat32_inv(rows: List[int]) -> List[int] | None:
    rows = [r & 0xFFFFFFFF for r in rows]
    inv = [1 << i for i in range(32)]
    for col in range(32):
        pivot = None
        for r in range(col, 32):
            if (rows[r] >> col) & 1:
                pivot = r
                break
        if pivot is None:
            return None
        if pivot != col:
            rows[col], rows[pivot] = rows[pivot], rows[col]
            inv[col], inv[pivot] = inv[pivot], inv[col]
        for r in range(32):
            if r != col and ((rows[r] >> col) & 1):
                rows[r] ^= rows[col]
                inv[r] ^= inv[col]
    return [r & 0xFFFFFFFF for r in inv]

def mat32_apply(rows: List[int], v: int) -> int:
    out = 0
    vv = v & 0xFFFFFFFF
    for i, r in enumerate(rows):
        if ((r & vv).bit_count() & 1):
            out |= (1 << i)
    return out & 0xFFFFFFFF

# -----------------------------
# AES helpers (key schedule)
# -----------------------------
def rot_word(w: bytes) -> bytes:
    return w[1:] + w[:1]

def sub_word(w: bytes) -> bytes:
    return bytes(SBOX[b] for b in w)

def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def key_schedule_128(key: bytes) -> List[bytes]:
    assert len(key) == 16
    w = [key[i * 4 : (i + 1) * 4] for i in range(4)]
    for i in range(4, 44):
        temp = w[i - 1]
        if i % 4 == 0:
            temp = xor_bytes(sub_word(rot_word(temp)), bytes([RCON[i // 4], 0, 0, 0]))
        w.append(xor_bytes(w[i - 4], temp))
    return [b"".join(w[4 * r : 4 * r + 4]) for r in range(11)]

# -----------------------------
# GF(2^8) multiplication (AES polynomial)
# -----------------------------
def gf_mul(a: int, b: int) -> int:
    res = 0
    aa = a & 0xFF
    bb = b & 0xFF
    for _ in range(8):
        if bb & 1:
            res ^= aa
        hi = aa & 0x80
        aa = (aa << 1) & 0xFF
        if hi:
            aa ^= 0x1B
        bb >>= 1
    return res & 0xFF

# -----------------------------
# CRC8 (for table authenticity)
# -----------------------------
def crc8(data: bytes, poly: int = 0x1D, init: int = 0xC7) -> int:
    crc = init & 0xFF
    for b in data:
        crc ^= b
        for _ in range(8):
            if crc & 0x80:
                crc = ((crc << 1) & 0xFF) ^ poly
            else:
                crc = (crc << 1) & 0xFF
    return crc & 0xFF

# -----------------------------
# Build random invertible 32x32 matrix
# -----------------------------
def rand_invertible_matrix32(rng: DRBG) -> Tuple[List[int], List[int]]:
    while True:
        rows = [rng.rand_u32() for _ in range(32)]
        inv = mat32_inv(rows.copy())
        if inv is not None:
            return rows, inv

# -----------------------------
# Real table builder
# -----------------------------
def make_real_table(
    rng: DRBG,
    L_rows: List[int],
    row: int,
    pos_id: int,
    kbyte: int,
    sig_nibble: int,
) -> Tuple[List[int], int]:
    """
    Returns (table[256], b_in).
    The "leak" is hidden in the coset representative of table[0] after reducing by the table's
    own difference-space basis.
    """
    a = rng.rand_nonzero_byte()
    b_in = rng.randbelow(256)
    t = b_in ^ kbyte  # masked key byte

    # base outputs without the final offset
    base = [0] * 256
    for x in range(256):
        z = gf_mul(a, x) ^ t
        y = INV_SBOX[z]  # core byte permutation
        pre = (y & 0xFF) << (8 * row)  # place in a lane
        base[x] = mat32_apply(L_rows, pre)

    diffs = [(base[x] ^ base[0]) & 0xFFFFFFFF for x in range(1, 256)]
    basis = basis32_build(diffs)
    if len(basis) != 8:
        raise RuntimeError("Unexpected basis dimension while building real table")

    pivots = set(basis.keys())
    nonp = [i for i in range(32) if i not in pivots]
    if len(nonp) != 24:
        raise RuntimeError("Unexpected non-pivot length while building real table")

    chk = crc8(bytes([pos_id & 0xFF, b_in & 0xFF, sig_nibble & 0xFF]))
    msg24 = (sig_nibble & 0xF) | ((b_in & 0xFF) << 4) | ((pos_id & 0xF) << 12) | ((chk & 0xFF) << 16)

    # canonical representative q: pivot bits must be 0, message bits live in non-pivot positions
    q = 0
    for idx, bitpos in enumerate(nonp):
        if (msg24 >> idx) & 1:
            q |= (1 << bitpos)
    q &= 0xFFFFFFFF

    # randomize inside the difference-space so q survives reduction but offsets look random
    basis_vecs = [basis[p] for p in sorted(basis.keys(), reverse=True)]
    coeff = rng.randbelow(1 << 8)
    s = 0
    for i, bv in enumerate(basis_vecs):
        if (coeff >> i) & 1:
            s ^= bv
    off = (q ^ s) & 0xFFFFFFFF

    return [(v ^ off) & 0xFFFFFFFF for v in base], b_in

# -----------------------------
# Decoy tables
# -----------------------------
def make_random_decoy(rng: DRBG) -> List[int]:
    return [rng.rand_u32() for _ in range(256)]

def make_lowrank_decoy(rng: DRBG, dim: int) -> List[int]:
    """
    Produce a decoy with a small difference footprint (dimension=dim),
    to intentionally waste time.
    """
    if not (1 <= dim <= 8):
        raise ValueError("dim must be 1..8 for this decoy builder")

    while True:
        vecs: List[int] = []
        while len(vecs) < dim:
            v = rng.rand_u32()
            b = basis32_build(vecs + [v])
            if len(b) == len(vecs) + 1:
                vecs.append(v)

        offset = rng.rand_u32()
        p = list(range(256))
        rng.shuffle(p)

        table = []
        for x in range(256):
            coeff = p[x]  # 8 bits
            val = offset
            for i in range(dim):
                if (coeff >> i) & 1:
                    val ^= vecs[i]
            table.append(val & 0xFFFFFFFF)

        diffs = [table[x] ^ table[0] for x in range(1, 256)]
        b = basis32_build(diffs)
        if len(b) == dim:
            return table

# -----------------------------
# Main generation
# -----------------------------
def main() -> None:
    script_dir = os.path.dirname(os.path.abspath(__file__))
    root_dir = os.path.abspath(os.path.join(script_dir, ".."))
    dist_dir = os.path.join(root_dir, "dist")
    solver_path = os.path.join(root_dir, "solver", "solve.py")

    os.makedirs(dist_dir, exist_ok=True)

    # Private salt (never shipped)
    salt_path = os.path.join(script_dir, "panitia_salt.bin")
    if not os.path.exists(salt_path):
        with open(salt_path, "wb") as f:
            f.write(os.urandom(32))

    with open(salt_path, "rb") as f:
        salt = f.read()

    # Hardened seed material
    seed_path = os.path.join(script_dir, "panitia_seed.bin")
    reproduce = os.environ.get("REPRODUCE", "").strip() == "1"

    if reproduce and os.path.exists(seed_path):
        with open(seed_path, "rb") as f:
            master_seed = f.read()
    else:
        user_seed = os.environ.get("SEED", "").encode()
        material = os.urandom(32) + salt + user_seed
        master_seed = hashlib.sha256(material).digest()
        with open(seed_path, "wb") as f:
            f.write(master_seed)

    rng = DRBG(master_seed)

    flag = os.environ.get("FLAG", DEFAULT_FLAG)
    flag_bytes = flag.encode()

    # Master AES key (secret)
    master_key = rng.randbytes(16)
    rk10 = key_schedule_128(master_key)[10]  # last round key bytes (in standard order)

    # Per-column 32x32 mixing matrices
    L_cols: List[List[int]] = []
    for _ in range(4):
        rows, _inv = rand_invertible_matrix32(rng)
        L_cols.append(rows)

    # Build 16 real tables
    real_tables: List[List[int]] = []
    for pos_id in range(16):
        col = pos_id // 4
        row = pos_id % 4
        kbyte = rk10[pos_id]
        table, _b_in = make_real_table(
            rng=rng,
            L_rows=L_cols[col],
            row=row,
            pos_id=pos_id,
            kbyte=kbyte,
            sig_nibble=SIG_NIBBLE,
        )
        real_tables.append(table)

    # Build decoys
    decoys_needed = TABLE_COUNT - 16
    decoys: List[List[int]] = []

    # Mix of full-random and low-dimension traps
    num_rand = 250
    num_dim8 = 80
    num_dim7 = decoys_needed - num_rand - num_dim8
    if num_dim7 < 0:
        raise RuntimeError("Bad decoy split; adjust constants")

    for _ in range(num_rand):
        decoys.append(make_random_decoy(rng))
    for _ in range(num_dim8):
        decoys.append(make_lowrank_decoy(rng, 8))
    for _ in range(num_dim7):
        decoys.append(make_lowrank_decoy(rng, 7))

    tables = real_tables + decoys
    rng.shuffle(tables)

    # Write tables.bin
    tables_path = os.path.join(dist_dir, "tables.bin")
    header_noise = rng.randbytes(64)
    reserved = rng.rand_u32()

    with open(tables_path, "wb") as f:
        f.write(struct.pack("<4sIIII", MAGIC, VERSION, TABLE_COUNT, reserved, len(header_noise)))
        f.write(header_noise)
        for tbl in tables:
            f.write(struct.pack("<256I", *tbl))

    # Known pairs + flag encryption
    cipher = AES.new(master_key, AES.MODE_ECB)

    known_path = os.path.join(dist_dir, "known_pairs.txt")
    with open(known_path, "w", encoding="utf-8") as f:
        f.write("# format: <pt16_hex>:<ct32_hex>\n")
        for _ in range(KNOWN_PAIRS_N):
            pt16 = rng.randbytes(16)
            ct32 = cipher.encrypt(pad(pt16, 16))
            f.write(f"{pt16.hex()}:{ct32.hex()}\n")

    flag_enc_path = os.path.join(dist_dir, "flag.enc")
    with open(flag_enc_path, "wb") as f:
        f.write(cipher.encrypt(pad(flag_bytes, 16)))

    # Sanity-check using the official solver (fail fast).
    # Capture stdout to avoid leaking the flag in generator output.
    try:
        res = subprocess.run(
            [sys.executable, solver_path],
            cwd=root_dir,
            capture_output=True,
            text=True,
            check=False,
        )
    except Exception as e:
        raise RuntimeError(f"Sanity-check failed to run solver: {e}") from e

    if res.returncode != 0:
        raise RuntimeError("Sanity-check failed: solver exited non-zero.\n" + res.stderr)

    out_flag = res.stdout.strip().splitlines()[-1].strip()
    if out_flag != flag:
        raise RuntimeError("Sanity-check failed: decrypted flag mismatch.")

    # Release-safe log (no secrets)
    print("OK: dist/ regenerated (tables.bin, known_pairs.txt, flag.enc)")

if __name__ == "__main__":
    main()
