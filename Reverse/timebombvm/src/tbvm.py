#!/usr/bin/env python3
"""TimeBomb VM core (server-side reference).

VM summary:
- 8 x 32-bit regs, 256-byte memory, zflag.
- 16 semantic opcodes, but *encoded opcode bytes* are permuted per-SEED.
- Bytecode plaintext has a small header + instruction stream.
- Full plaintext is encrypted with a seed-based stream cipher and base64'd.

Note: this module is optimized enough for server-side verification.
"""

from __future__ import annotations

import base64
import struct
from dataclasses import dataclass
from typing import List, Tuple

REGS = 8
MEM_SIZE = 256
OP_COUNT = 16

MAGIC = b"TBVM"
VERSION = 1
FLAGS = 0x42
HEADER_LEN = 28

# Round-dependent tweak for encryption key derivation.
ROUND_SALT = (
    0xA3B1C2D3,
    0xC0DEC0DE,
    0x9E3779B9,
    0x7F4A7C15,
    0x1B873593,
)


def _u32(x: int) -> int:
    return x & 0xFFFFFFFF


def _rol32(x: int, r: int) -> int:
    r &= 31
    return _u32((x << r) | (x >> (32 - r)))


def _ror32(x: int, r: int) -> int:
    r &= 31
    return _u32((x >> r) | (x << (32 - r)))


def _rol8(x: int, r: int) -> int:
    r &= 7
    x &= 0xFF
    return ((x << r) | (x >> (8 - r))) & 0xFF


def _ror8(x: int, r: int) -> int:
    r &= 7
    x &= 0xFF
    return ((x >> r) | (x << (8 - r))) & 0xFF


def _nibswap(x: int) -> int:
    x &= 0xFF
    return ((x & 0x0F) << 4) | ((x >> 4) & 0x0F)


class XorShift32:
    __slots__ = ("s",)

    def __init__(self, seed: int):
        self.s = _u32(seed) or 0x12345678

    def next_u32(self) -> int:
        x = self.s
        x ^= (x << 13) & 0xFFFFFFFF
        x ^= (x >> 17) & 0xFFFFFFFF
        x ^= (x << 5) & 0xFFFFFFFF
        self.s = _u32(x)
        return self.s

    def next_u8(self) -> int:
        return (self.next_u32() >> 24) & 0xFF


def fnv1a32(data: bytes) -> int:
    h = 0x811C9DC5
    for b in data:
        h ^= b
        h = _u32(h * 0x01000193)
    return h


def opcode_bytes(seed: int) -> List[int]:
    """Return list[16] mapping semantic opcode -> encoded opcode byte."""
    pr = XorShift32(seed ^ 0xA341316C)

    # partial Fisher-Yates to pick 16 unique bytes from 0..255
    pool = list(range(256))
    for i in range(255, 255 - 16, -1):
        j = pr.next_u32() % (i + 1)
        pool[i], pool[j] = pool[j], pool[i]

    selected = pool[256 - 16 :]

    # extra shuffle of the 16 bytes (still deterministic)
    for i in range(15, 0, -1):
        j = pr.next_u32() % (i + 1)
        selected[i], selected[j] = selected[j], selected[i]

    return selected


def inverse_opcode_map(opbytes: List[int]) -> List[int]:
    inv = [0xFF] * 256
    for sem, ob in enumerate(opbytes):
        inv[ob] = sem
    return inv


def sbox_bytes(seed: int) -> bytes:
    pr = XorShift32(seed ^ 0x1B873593)
    arr = list(range(256))
    for i in range(255, 0, -1):
        j = pr.next_u32() % (i + 1)
        arr[i], arr[j] = arr[j], arr[i]

    # light diffusion pass
    for i in range(256):
        arr[i] = (arr[i] ^ ((i * 73) & 0xFF) ^ ((seed >> (i & 7)) & 0xFF)) & 0xFF

    return bytes(arr)


def encrypt(plain: bytes, seed: int, round_idx: int) -> bytes:
    kseed = _u32(seed ^ ROUND_SALT[round_idx - 1] ^ 0xC0DEC0DE)
    pr = XorShift32(kseed)
    out = bytearray(len(plain))
    for i, b in enumerate(plain):
        k = pr.next_u8()
        x = b ^ k
        x = _rol8(x, 3)
        x = _nibswap(x)
        x ^= (k * 0xA7) & 0xFF
        out[i] = x
    return bytes(out)


def decrypt(cipher: bytes, seed: int, round_idx: int) -> bytes:
    kseed = _u32(seed ^ ROUND_SALT[round_idx - 1] ^ 0xC0DEC0DE)
    pr = XorShift32(kseed)
    out = bytearray(len(cipher))
    for i, c in enumerate(cipher):
        k = pr.next_u8()
        x = c ^ ((k * 0xA7) & 0xFF)
        x = _nibswap(x)
        x = _ror8(x, 3)
        out[i] = x ^ k
    return bytes(out)


def enc_uleb128(x: int) -> bytes:
    x &= 0xFFFFFFFF
    out = bytearray()
    while True:
        b = x & 0x7F
        x >>= 7
        if x:
            out.append(b | 0x80)
        else:
            out.append(b)
            break
    return bytes(out)


def enc_sleb128(x: int) -> bytes:
    x = int(x)
    out = bytearray()
    more = True
    while more:
        b = x & 0x7F
        x >>= 7
        sign = b & 0x40
        if (x == 0 and sign == 0) or (x == -1 and sign != 0):
            more = False
        else:
            b |= 0x80
        out.append(b)
    return bytes(out)


def dec_uleb128(buf: bytes, p: int) -> Tuple[int, int]:
    shift = 0
    val = 0
    while True:
        b = buf[p]
        p += 1
        val |= (b & 0x7F) << shift
        if (b & 0x80) == 0:
            return _u32(val), p
        shift += 7
        if shift > 35:
            return _u32(val), p


def dec_sleb128(buf: bytes, p: int) -> Tuple[int, int]:
    shift = 0
    val = 0
    b = 0
    while True:
        b = buf[p]
        p += 1
        val |= (b & 0x7F) << shift
        shift += 7
        if (b & 0x80) == 0:
            break
        if shift > 35:
            break

    if (shift < 32) and (b & 0x40):
        val |= - (1 << shift)
    return int(val), p


@dataclass
class RoundPack:
    seed: int
    round_idx: int
    bc_b64: str
    bc_len: int
    cycle_budget: int
    expected_token_hex: str


# Semantic opcode IDs (stable; only encoded bytes are permuted)
OP_NOP = 0
OP_LDI = 1
OP_ADD = 2
OP_XOR = 3
OP_ADDI = 4
OP_MUL = 5
OP_ROL = 6
OP_LDR = 7
OP_STR = 8
OP_CMP = 9
OP_JZ = 10
OP_JNZ = 11
OP_MIX = 12
OP_MEMXOR = 13
OP_OUT = 14
OP_HALT = 15


class Asm:
    def __init__(self, opbytes: List[int]):
        self.op = opbytes
        self.buf = bytearray()

    def pos(self) -> int:
        return len(self.buf)

    def _emit(self, sem: int, tail: bytes = b"") -> None:
        self.buf.append(self.op[sem])
        self.buf += tail

    def nop(self) -> None:
        self._emit(OP_NOP)

    def ldi(self, r: int, imm_u32: int) -> None:
        self._emit(OP_LDI, bytes([r & 7]) + enc_uleb128(imm_u32))

    def add(self, ra: int, rb: int) -> None:
        self._emit(OP_ADD, bytes([ra & 7, rb & 7]))

    def xor(self, ra: int, rb: int) -> None:
        self._emit(OP_XOR, bytes([ra & 7, rb & 7]))

    def addi(self, r: int, imm_s32: int) -> None:
        self._emit(OP_ADDI, bytes([r & 7]) + enc_sleb128(imm_s32))

    def mul(self, ra: int, rb: int) -> None:
        self._emit(OP_MUL, bytes([ra & 7, rb & 7]))

    def rol(self, r: int, imm: int) -> None:
        self._emit(OP_ROL, bytes([r & 7, imm & 0xFF]))

    def ldr(self, dst: int, addr_r: int) -> None:
        self._emit(OP_LDR, bytes([dst & 7, addr_r & 7]))

    def str(self, src: int, addr_r: int) -> None:
        self._emit(OP_STR, bytes([src & 7, addr_r & 7]))

    def cmp(self, ra: int, rb: int) -> None:
        self._emit(OP_CMP, bytes([ra & 7, rb & 7]))

    def jz_placeholder(self) -> int:
        self.buf.append(self.op[OP_JZ])
        self.buf.append(0)
        return len(self.buf) - 1

    def jnz_placeholder(self) -> int:
        self.buf.append(self.op[OP_JNZ])
        self.buf.append(0)
        return len(self.buf) - 1

    def mix(self, ra: int, rb: int) -> None:
        self._emit(OP_MIX, bytes([ra & 7, rb & 7]))

    def memxor(self, addr_r: int, ln: int, src: int) -> None:
        self._emit(OP_MEMXOR, bytes([addr_r & 7, ln & 0xFF, src & 7]))

    def out(self, addr_r: int) -> None:
        self._emit(OP_OUT, bytes([addr_r & 7]))

    def halt(self) -> None:
        self._emit(OP_HALT)

    def patch_rel8(self, rel_byte_pos: int, target_pos: int) -> None:
        base = rel_byte_pos + 1
        rel = target_pos - base
        if not -128 <= rel <= 127:
            raise ValueError("relative jump out of range")
        self.buf[rel_byte_pos] = rel & 0xFF


def _hdr_tag(seed: int, payload_fnv: int, payload_len: int) -> int:
    x = _u32(seed ^ payload_fnv ^ (payload_len * 0x45D9F3B))
    x = _rol32(x + 0x9E3779B9, (seed >> 27) & 31)
    return _u32(x ^ 0xA5A5A5A5)


def assemble_plain(seed: int, round_idx: int) -> bytes:
    opb = opcode_bytes(seed)
    a = Asm(opb)

    # r0=seed, r1=seed^const, r2=const, r3=addr, r4=const, r5=temp, r6=0, r7=ctr
    a.ldi(0, seed)
    a.ldi(1, _u32(seed ^ 0xA5A5A5A5 ^ (round_idx * 0x3C6EF35F)))
    a.ldi(2, 0x6D2B79F5)
    a.ldi(3, 0)
    a.ldi(4, _u32(0x9E3779B9 + round_idx * 0x1337))
    a.ldi(6, 0)

    # Unreachable dead code block (anti-trivial):
    a.cmp(6, 6)  # zflag=1
    jz_to_main = a.jz_placeholder()

    # Dead / misleading instructions
    a.ldi(5, 0x13371337)
    a.mul(5, 5)
    a.xor(5, 0)
    a.addi(5, -123)
    a.rol(5, 17)
    a.mix(5, 1)
    a.memxor(3, 17, 5)
    a.nop()
    a.nop()

    main_pos = a.pos()
    a.patch_rel8(jz_to_main, main_pos)

    # Stage 1: fill 256 bytes (64 stores of 4 bytes)
    fill_cnt = 64
    a.ldi(7, fill_cnt)
    fill_loop = a.pos()
    a.mix(0, 1)
    a.add(0, 2)
    a.xor(1, 4)
    a.str(0, 3)
    a.addi(3, 4)
    a.addi(7, -1)
    a.cmp(7, 6)
    jnz_fill = a.jnz_placeholder()
    a.patch_rel8(jnz_fill, fill_loop)

    # Stage 2: heavy-ish mixing loop
    iters = 2200 + ((seed >> 20) & 0x3FF)
    a.ldi(7, iters)
    a.ldi(3, _u32(seed ^ (round_idx * 0x7F4A7C15)) & 0xFF)
    loop2 = a.pos()
    a.ldr(5, 3)
    a.mix(5, 0)
    a.xor(0, 5)
    a.str(0, 3)
    a.memxor(3, 32, 0)
    a.rol(1, 7)
    a.add(1, 5)
    a.addi(3, 13)
    a.addi(7, -1)
    a.cmp(7, 6)
    jnz2 = a.jnz_placeholder()
    a.patch_rel8(jnz2, loop2)

    # Output
    a.ldi(3, 128)
    a.out(3)
    a.halt()

    payload = bytes(a.buf)
    payload_len = len(payload)
    payload_fnv = fnv1a32(payload)

    tag = _hdr_tag(seed, payload_fnv, payload_len)

    header = struct.pack(
        "<4sBBHIIIII",
        MAGIC,
        VERSION,
        FLAGS,
        HEADER_LEN,
        _u32(seed),
        _u32(round_idx),
        _u32(payload_len),
        _u32(payload_fnv),
        _u32(tag),
    )

    assert len(header) == HEADER_LEN
    return header + payload


def _load_u32_le(mem: bytearray, addr: int) -> int:
    a = addr & 0xFF
    return (
        mem[a]
        | (mem[(a + 1) & 0xFF] << 8)
        | (mem[(a + 2) & 0xFF] << 16)
        | (mem[(a + 3) & 0xFF] << 24)
    )


def _store_u32_le(mem: bytearray, addr: int, v: int) -> None:
    a = addr & 0xFF
    v &= 0xFFFFFFFF
    mem[a] = v & 0xFF
    mem[(a + 1) & 0xFF] = (v >> 8) & 0xFF
    mem[(a + 2) & 0xFF] = (v >> 16) & 0xFF
    mem[(a + 3) & 0xFF] = (v >> 24) & 0xFF


def _mix32(x: int, y: int, sbox: bytes) -> int:
    # Nonlinear, byte-oriented mixing using a seed-generated S-box.
    t = _u32(x ^ _rol32(y, 7) ^ 0x9E3779B9)
    o = 0
    # 4 lanes
    b0 = t & 0xFF
    b1 = (t >> 8) & 0xFF
    b2 = (t >> 16) & 0xFF
    b3 = (t >> 24) & 0xFF

    b0 = sbox[b0] ^ ((y >> 0) & 0xFF)
    b1 = sbox[b1] ^ ((y >> 8) & 0xFF)
    b2 = sbox[b2] ^ ((y >> 16) & 0xFF)
    b3 = sbox[b3] ^ ((y >> 24) & 0xFF)

    b0 = _rol8(b0, (y >> 1) & 7)
    b1 = _rol8(b1, (y >> 9) & 7)
    b2 = _rol8(b2, (y >> 17) & 7)
    b3 = _rol8(b3, (y >> 25) & 7)

    o = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
    o = _u32(o + _ror32(x, 3) + 0x7F4A7C15)
    return o


def emulate_plain(plain: bytes, cycle_budget: int) -> bytes:
    if len(plain) < HEADER_LEN:
        raise ValueError("bytecode too short")

    magic, ver, flg, hlen, seed, ridx, plen, pfnv, tag = struct.unpack(
        "<4sBBHIIIII", plain[:HEADER_LEN]
    )
    if magic != MAGIC or ver != VERSION or hlen != HEADER_LEN:
        raise ValueError("bad header")

    payload = plain[HEADER_LEN:]
    if len(payload) != plen:
        raise ValueError("length mismatch")

    if fnv1a32(payload) != pfnv:
        raise ValueError("payload checksum mismatch")

    if _hdr_tag(seed, pfnv, plen) != tag:
        raise ValueError("header tag mismatch")

    opb = opcode_bytes(seed)
    inv = inverse_opcode_map(opb)
    sbox = sbox_bytes(seed)

    regs = [0] * REGS
    mem = bytearray(MEM_SIZE)
    z = 0

    out = bytearray(32)
    out_set = False

    p = 0
    cycles = 0
    payload_mv = memoryview(payload)
    mem_local = mem
    sbox_local = sbox
    regs_local = regs
    inv_local = inv

    while p < plen and cycles < cycle_budget:
        op = payload_mv[p]
        p += 1
        sem = inv_local[op]
        if sem == 0xFF:
            cycles += 1
            continue

        # base cost
        cycles += 1

        if sem == OP_NOP:
            continue

        if sem == OP_LDI:
            r = payload_mv[p] & 7
            p += 1
            v, p = dec_uleb128(payload, p)
            regs_local[r] = v
            z = 1 if v == 0 else 0
            continue

        if sem == OP_ADDI:
            r = payload_mv[p] & 7
            p += 1
            v, p = dec_sleb128(payload, p)
            regs_local[r] = _u32(regs_local[r] + v)
            z = 1 if regs_local[r] == 0 else 0
            continue

        if sem == OP_ADD:
            ra = payload_mv[p] & 7
            rb = payload_mv[p + 1] & 7
            p += 2
            regs_local[ra] = _u32(regs_local[ra] + regs_local[rb])
            z = 1 if regs_local[ra] == 0 else 0
            continue

        if sem == OP_XOR:
            ra = payload_mv[p] & 7
            rb = payload_mv[p + 1] & 7
            p += 2
            regs_local[ra] = _u32(regs_local[ra] ^ regs_local[rb])
            z = 1 if regs_local[ra] == 0 else 0
            continue

        if sem == OP_MUL:
            ra = payload_mv[p] & 7
            rb = payload_mv[p + 1] & 7
            p += 2
            regs_local[ra] = _u32((regs_local[ra] * regs_local[rb]) & 0xFFFFFFFF)
            z = 1 if regs_local[ra] == 0 else 0
            continue

        if sem == OP_ROL:
            r = payload_mv[p] & 7
            imm = payload_mv[p + 1]
            p += 2
            regs_local[r] = _rol32(regs_local[r], imm)
            z = 1 if regs_local[r] == 0 else 0
            continue

        if sem == OP_LDR:
            dst = payload_mv[p] & 7
            ar = payload_mv[p + 1] & 7
            p += 2
            addr = regs_local[ar] & 0xFF
            regs_local[dst] = _load_u32_le(mem_local, addr)
            z = 1 if regs_local[dst] == 0 else 0
            continue

        if sem == OP_STR:
            src = payload_mv[p] & 7
            ar = payload_mv[p + 1] & 7
            p += 2
            addr = regs_local[ar] & 0xFF
            _store_u32_le(mem_local, addr, regs_local[src])
            continue

        if sem == OP_CMP:
            ra = payload_mv[p] & 7
            rb = payload_mv[p + 1] & 7
            p += 2
            z = 1 if regs_local[ra] == regs_local[rb] else 0
            continue

        if sem == OP_JZ:
            rel = struct.unpack_from("b", payload_mv, p)[0]
            p += 1
            if z:
                p = (p + rel) % plen
            continue

        if sem == OP_JNZ:
            rel = struct.unpack_from("b", payload_mv, p)[0]
            p += 1
            if not z:
                p = (p + rel) % plen
            continue

        if sem == OP_MIX:
            ra = payload_mv[p] & 7
            rb = payload_mv[p + 1] & 7
            p += 2
            regs_local[ra] = _mix32(regs_local[ra], regs_local[rb], sbox_local)
            z = 1 if regs_local[ra] == 0 else 0
            continue

        if sem == OP_MEMXOR:
            ar = payload_mv[p] & 7
            ln = payload_mv[p + 1]
            sr = payload_mv[p + 2] & 7
            p += 3
            base = regs_local[ar] & 0xFF
            w = regs_local[sr]
            # extra cost proportional to length
            cycles += ln
            b0 = w & 0xFF
            b1 = (w >> 8) & 0xFF
            b2 = (w >> 16) & 0xFF
            b3 = (w >> 24) & 0xFF
            sb = sbox_local
            m = mem_local
            for i in range(ln):
                mix = sb[(i + b0) & 0xFF] ^ (b1 if (i & 1) else b2)
                k = (b0 if (i & 3) == 0 else b1 if (i & 3) == 1 else b2 if (i & 3) == 2 else b3)
                m[(base + i) & 0xFF] ^= (k ^ mix) & 0xFF
            continue

        if sem == OP_OUT:
            ar = payload_mv[p] & 7
            p += 1
            base = regs_local[ar] & 0xFF
            for i in range(32):
                out[i] = mem_local[(base + i) & 0xFF]
            out_set = True
            continue

        if sem == OP_HALT:
            break

    if out_set:
        return bytes(out)

    # Fallback: always produce 32 bytes deterministically.
    h = _u32(0xDEADBEEF ^ seed ^ (ridx * 0x9E3779B9))
    for r in regs_local:
        h = _u32(_rol32(h, 5) ^ r)
    for i in range(64):
        h = _u32((h * 0x01000193) ^ mem_local[i])
    pr = XorShift32(h)
    for i in range(32):
        out[i] = pr.next_u8() ^ sbox_local[i]
    return bytes(out)


def make_round(seed: int, round_idx: int) -> RoundPack:
    plain = assemble_plain(seed, round_idx)
    cipher = encrypt(plain, seed, round_idx)
    b64 = base64.b64encode(cipher).decode("ascii")

    # Provide cycle budget (tight-ish, but safe)
    fill_cnt = 64
    iters = 2200 + ((seed >> 20) & 0x3FF)
    cycles = 90 + (8 * fill_cnt) + (43 * iters)
    cycle_budget = cycles + 250

    expected = emulate_plain(plain, cycle_budget).hex()
    return RoundPack(
        seed=seed,
        round_idx=round_idx,
        bc_b64=b64,
        bc_len=len(cipher),
        cycle_budget=cycle_budget,
        expected_token_hex=expected,
    )
