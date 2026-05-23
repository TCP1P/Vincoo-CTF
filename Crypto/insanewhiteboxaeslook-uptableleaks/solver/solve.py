#!/usr/bin/env python3
"""
Official organizer solver (panitia).

Reads:
- dist/tables.bin
- dist/known_pairs.txt
- dist/flag.enc

Recovers AES-128 master key from the lookup table dump + known pairs,
then decrypts the flag and prints it.

Dependencies: pycryptodome only.
"""
from __future__ import annotations

import os
import struct
from typing import Dict, List, Tuple

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


# -----------------------------
# AES tables (key schedule + core model used for table recovery)
# -----------------------------
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

SIG_NIBBLE = 0xA  # must match generator

# -----------------------------
# CRC8 (table authenticity)
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

# Precompute mul table for speed
MUL_TABLE = [[gf_mul(a, x) for x in range(256)] for a in range(256)]

# -----------------------------
# Linear algebra helpers (bitwise, no numpy)
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

def cols_to_rows32(cols: List[int]) -> List[int]:
    rows = [0] * 32
    for col_idx, c in enumerate(cols):
        cc = c & 0xFFFFFFFF
        for bit in range(32):
            if (cc >> bit) & 1:
                rows[bit] |= (1 << col_idx)
    return [r & 0xFFFFFFFF for r in rows]

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

def cols_to_rows8(cols: List[int]) -> List[int]:
    rows = [0] * 8
    for col_idx, c in enumerate(cols):
        for bit in range(8):
            if (c >> bit) & 1:
                rows[bit] |= (1 << col_idx)
    return [r & 0xFF for r in rows]

def mat8_inv(rows: List[int]) -> List[int] | None:
    rows = [r & 0xFF for r in rows]
    inv = [1 << i for i in range(8)]
    for col in range(8):
        pivot = None
        for r in range(col, 8):
            if (rows[r] >> col) & 1:
                pivot = r
                break
        if pivot is None:
            return None
        if pivot != col:
            rows[col], rows[pivot] = rows[pivot], rows[col]
            inv[col], inv[pivot] = inv[pivot], inv[col]
        for r in range(8):
            if r != col and ((rows[r] >> col) & 1):
                rows[r] ^= rows[col]
                inv[r] ^= inv[col]
    return [r & 0xFF for r in inv]

def mat8_mul(A_rows: List[int], B_rows: List[int]) -> List[int]:
    C: List[int] = []
    for a in A_rows:
        row = 0
        x = a & 0xFF
        while x:
            lsb = x & -x
            k = (lsb.bit_length() - 1)
            row ^= B_rows[k]
            x ^= lsb
        C.append(row & 0xFF)
    return C

def mat8_apply(rows: List[int], v: int) -> int:
    out = 0
    vv = v & 0xFF
    for i, r in enumerate(rows):
        if ((r & vv).bit_count() & 1):
            out |= (1 << i)
    return out & 0xFF

# -----------------------------
# AES-128 key schedule reversal from last round key
# -----------------------------
def rot_word(w: bytes) -> bytes:
    return w[1:] + w[:1]

def sub_word(w: bytes) -> bytes:
    return bytes(SBOX[b] for b in w)

def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def inv_key_schedule_128(rk10: bytes) -> bytes:
    """Recover master key from AES-128 round-10 key (16 bytes)."""
    if len(rk10) != 16:
        raise ValueError("rk10 must be 16 bytes")
    w = [b"\x00" * 4 for _ in range(44)]
    for i in range(4):
        w[40 + i] = rk10[i * 4 : (i + 1) * 4]
    for i in range(43, 3, -1):
        temp = w[i - 1]
        if i % 4 == 0:
            temp = xor_bytes(sub_word(rot_word(temp)), bytes([RCON[i // 4], 0, 0, 0]))
        w[i - 4] = xor_bytes(w[i], temp)
    return b"".join(w[0:4])

# -----------------------------
# Parsing
# -----------------------------
def read_tables(path: str) -> List[List[int]]:
    with open(path, "rb") as f:
        hdr = f.read(4 + 4 * 4)
        if len(hdr) != 20:
            raise ValueError("Bad header length")
        magic, version, table_count, reserved, noise_len = struct.unpack("<4sIIII", hdr)
        _ = (magic, version, reserved)  # deliberately unused fields
        if table_count <= 0 or table_count > 2048:
            raise ValueError("Suspicious table_count")
        noise = f.read(noise_len)
        if len(noise) != noise_len:
            raise ValueError("Bad noise length")

        tables: List[List[int]] = []
        for _i in range(table_count):
            data = f.read(256 * 4)
            if len(data) != 256 * 4:
                raise ValueError("Unexpected EOF while reading table data")
            tables.append(list(struct.unpack("<256I", data)))
        return tables

def read_known_pairs(path: str) -> List[Tuple[bytes, bytes]]:
    out: List[Tuple[bytes, bytes]] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            pt_hex, ct_hex = line.split(":", 1)
            pt = bytes.fromhex(pt_hex)
            ct = bytes.fromhex(ct_hex)
            if len(pt) != 16 or len(ct) != 32:
                raise ValueError("Bad known_pairs line lengths")
            out.append((pt, ct))
    if not out:
        raise ValueError("No known pairs found")
    return out

# -----------------------------
# Step 1: detect the 16 real tables deterministically
# -----------------------------
def detect_real_tables(tables: List[List[int]]) -> Dict[int, Dict]:
    candidates: List[Dict] = []
    for idx, T in enumerate(tables):
        t0 = T[0]
        diffs = [T[x] ^ t0 for x in range(1, 256)]
        basis = basis32_build(diffs)
        if len(basis) != 8:
            continue

        reduced = basis32_reduce(t0, basis)
        pivots = set(basis.keys())
        nonp = [i for i in range(32) if i not in pivots]
        if len(nonp) != 24:
            continue

        msg24 = 0
        for bit_idx, bitpos in enumerate(nonp):
            msg24 |= ((reduced >> bitpos) & 1) << bit_idx

        sig = msg24 & 0xF
        if sig != SIG_NIBBLE:
            continue
        b_in = (msg24 >> 4) & 0xFF
        pos_id = (msg24 >> 12) & 0xF
        chk = (msg24 >> 16) & 0xFF
        if pos_id >= 16:
            continue
        if chk != crc8(bytes([pos_id, b_in, sig])):
            continue

        candidates.append(
            {
                "table_index": idx,
                "pos_id": pos_id,
                "row": pos_id % 4,
                "col": pos_id // 4,
                "b_in": b_in,
            }
        )

    # Deduplicate by pos_id (extremely unlikely to collide, but be safe)
    by_pos: Dict[int, Dict] = {}
    for c in candidates:
        pid = c["pos_id"]
        if pid not in by_pos or c["table_index"] < by_pos[pid]["table_index"]:
            by_pos[pid] = c

    if len(by_pos) != 16:
        raise RuntimeError(f"Expected 16 real tables, got {len(by_pos)} (raw candidates={len(candidates)})")

    return by_pos

# -----------------------------
# Step 2: undo per-column 32-bit mixing (up to a per-row basis)
# -----------------------------
def build_demix_matrix_for_column(tables: List[List[int]], by_pos: Dict[int, Dict], col: int) -> List[int]:
    # Build a 32-vector basis for the whole column by concatenating 8 basis vectors from each row-table.
    cols: List[int] = []
    for row in range(4):
        pos_id = row + 4 * col
        T = tables[by_pos[pos_id]["table_index"]]
        t0 = T[0]
        diffs = [T[x] ^ t0 for x in range(1, 256)]
        basis = basis32_build(diffs)
        if len(basis) != 8:
            raise RuntimeError("Unexpected dim while building demix matrix")
        vecs = [basis[p] for p in sorted(basis.keys(), reverse=True)]
        cols.extend(vecs)

    if len(cols) != 32:
        raise RuntimeError("Bad basis length while building demix matrix")

    P_rows = cols_to_rows32(cols)
    R_rows = mat32_inv(P_rows)
    if R_rows is None:
        raise RuntimeError("Demix matrix not invertible (should never happen)")

    return R_rows

# -----------------------------
# Step 3: recover masked parameters (a,t) per table, then key byte
# -----------------------------
SAMPLE_XS = list(range(1, 65))  # deterministic quick-check points

def recover_at_from_f(f: List[int]) -> Tuple[int, int]:
    """
    Given f[x] = observed 8-bit mapping (with f[0]=0),
    find (a,t) such that there exists an invertible 8x8 linear map M with:
      f(x) = M( INV_SBOX(a*x XOR t) XOR INV_SBOX(t) )
    for all x, where a*x is multiplication in the AES 8-bit field.
    """
    for a in range(1, 256):
        mul_a = MUL_TABLE[a]
        for t in range(256):
            c0 = INV_SBOX[t]

            # Pick 8 linearly independent columns u_i
            u_cols: List[int] = []
            v_cols: List[int] = []
            basis_u: Dict[int, int] = {}

            for x in range(1, 256):
                u = INV_SBOX[mul_a[x] ^ t] ^ c0
                tmp = u
                for p in sorted(basis_u.keys(), reverse=True):
                    if (tmp >> p) & 1:
                        tmp ^= basis_u[p]
                if tmp:
                    p = tmp.bit_length() - 1
                    basis_u[p] = tmp
                    u_cols.append(u)
                    v_cols.append(f[x])
                    if len(u_cols) == 8:
                        break

            if len(u_cols) < 8:
                continue

            U_rows = cols_to_rows8(u_cols)
            U_inv = mat8_inv(U_rows)
            if U_inv is None:
                continue

            V_rows = cols_to_rows8(v_cols)
            M_rows = mat8_mul(V_rows, U_inv)

            # Quick check
            ok = True
            for x in SAMPLE_XS:
                u = INV_SBOX[mul_a[x] ^ t] ^ c0
                if mat8_apply(M_rows, u) != f[x]:
                    ok = False
                    break
            if not ok:
                continue

            # Full check
            for x in range(256):
                u = INV_SBOX[mul_a[x] ^ t] ^ c0
                if mat8_apply(M_rows, u) != f[x]:
                    ok = False
                    break
            if ok:
                return a, t

    raise RuntimeError("Failed to recover (a,t) from table (unexpected)")

def recover_rk10_bytes(tables: List[List[int]], by_pos: Dict[int, Dict]) -> bytes:
    # Build demix matrix for each column
    demix: Dict[int, List[int]] = {}
    for col in range(4):
        demix[col] = build_demix_matrix_for_column(tables, by_pos, col)

    rk10 = [0] * 16
    for pos_id in range(16):
        info = by_pos[pos_id]
        row = info["row"]
        col = info["col"]
        T = tables[info["table_index"]]
        R_rows = demix[col]
        t0 = T[0]

        # f[x] is the demixed 8-bit difference in this row-block
        f: List[int] = [0] * 256
        for x in range(256):
            diff = T[x] ^ t0
            coord = mat32_apply(R_rows, diff)
            f[x] = (coord >> (8 * row)) & 0xFF

        _a, t = recover_at_from_f(f)
        kbyte = t ^ info["b_in"]
        rk10[pos_id] = kbyte

    return bytes(rk10)

# -----------------------------
# Step 4: try the 2 plausible byte-orderings (endianness/representation trap)
# -----------------------------
def transpose_state_bytes(b: bytes) -> bytes:
    # Interpret b as 4x4, transpose, then flatten back to column-major.
    if len(b) != 16:
        raise ValueError("need 16 bytes")
    out = []
    for i in range(16):
        r = i % 4
        c = i // 4
        rm_idx = 4 * r + c
        out.append(b[rm_idx])
    return bytes(out)

def verify_master_key(key: bytes, pairs: List[Tuple[bytes, bytes]]) -> bool:
    cipher = AES.new(key, AES.MODE_ECB)
    for pt16, ct32 in pairs:
        if cipher.encrypt(pad(pt16, 16)) != ct32:
            return False
    return True

# -----------------------------
# Main
# -----------------------------
def main() -> None:
    script_dir = os.path.dirname(os.path.abspath(__file__))
    root_dir = os.path.abspath(os.path.join(script_dir, ".."))
    dist_dir = os.path.join(root_dir, "dist")

    tables = read_tables(os.path.join(dist_dir, "tables.bin"))
    pairs = read_known_pairs(os.path.join(dist_dir, "known_pairs.txt"))
    with open(os.path.join(dist_dir, "flag.enc"), "rb") as f:
        flag_ct = f.read()

    by_pos = detect_real_tables(tables)
    rk10_raw = recover_rk10_bytes(tables, by_pos)

    # Two interpretations:
    # A) pos_id already matches AES round-key byte order (column-major)
    # B) pos_id matches a transposed convention
    candidates = [rk10_raw, transpose_state_bytes(rk10_raw)]

    master_key = None
    for rk10 in candidates:
        key = inv_key_schedule_128(rk10)
        if verify_master_key(key, pairs):
            master_key = key
            break

    if master_key is None:
        raise RuntimeError("Key verification failed for all representations")

    cipher = AES.new(master_key, AES.MODE_ECB)
    flag = unpad(cipher.decrypt(flag_ct), 16)
    print(flag.decode("utf-8", errors="replace"))

if __name__ == "__main__":
    main()
