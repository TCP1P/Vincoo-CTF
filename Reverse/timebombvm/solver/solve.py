#!/usr/bin/env python3
import base64
import socket
import struct
import sys
import time

# ===== Spec constants (must match dist binary / server) =====
REGS = 8
MEM_SIZE = 256
OP_COUNT = 16

MAGIC = b"TBVM"
VERSION = 1
FLAGS = 0x42
HEADER_LEN = 28

ROUND_SALT = (
    0xA3B1C2D3,
    0xC0DEC0DE,
    0x9E3779B9,
    0x7F4A7C15,
    0x1B873593,
)

# semantic opcodes
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


def u32(x: int) -> int:
    return x & 0xFFFFFFFF


def rol32(x: int, r: int) -> int:
    r &= 31
    return u32((x << r) | (x >> (32 - r)))


def ror32(x: int, r: int) -> int:
    r &= 31
    return u32((x >> r) | (x << (32 - r)))


def rol8(x: int, r: int) -> int:
    r &= 7
    x &= 0xFF
    return ((x << r) | (x >> (8 - r))) & 0xFF


def ror8(x: int, r: int) -> int:
    r &= 7
    x &= 0xFF
    return ((x >> r) | (x << (8 - r))) & 0xFF


def nibswap(x: int) -> int:
    x &= 0xFF
    return ((x & 0x0F) << 4) | ((x >> 4) & 0x0F)


class XorShift32:
    __slots__ = ("s",)

    def __init__(self, seed: int):
        self.s = u32(seed) or 0x12345678

    def next_u32(self) -> int:
        x = self.s
        x ^= (x << 13) & 0xFFFFFFFF
        x ^= (x >> 17) & 0xFFFFFFFF
        x ^= (x << 5) & 0xFFFFFFFF
        self.s = u32(x)
        return self.s

    def next_u8(self) -> int:
        return (self.next_u32() >> 24) & 0xFF


def fnv1a32(data: bytes) -> int:
    h = 0x811C9DC5
    for b in data:
        h ^= b
        h = u32(h * 0x01000193)
    return h


def hdr_tag(seed: int, payload_fnv: int, payload_len: int) -> int:
    x = u32(seed ^ payload_fnv ^ (payload_len * 0x45D9F3B))
    x = rol32(x + 0x9E3779B9, (seed >> 27) & 31)
    return u32(x ^ 0xA5A5A5A5)


def opcode_bytes(seed: int) -> list[int]:
    """semantic -> encoded opcode byte"""
    pr = XorShift32(seed ^ 0xA341316C)
    pool = list(range(256))
    # partial fisher-yates: pick 16 unique bytes from 0..255
    for i in range(255, 255 - OP_COUNT, -1):
        j = pr.next_u32() % (i + 1)
        pool[i], pool[j] = pool[j], pool[i]
    selected = pool[256 - OP_COUNT :]
    # extra shuffle of the 16 bytes
    for i in range(OP_COUNT - 1, 0, -1):
        j = pr.next_u32() % (i + 1)
        selected[i], selected[j] = selected[j], selected[i]
    return selected


def sbox_bytes(seed: int) -> bytes:
    pr = XorShift32(seed ^ 0x1B873593)
    arr = list(range(256))
    for i in range(255, 0, -1):
        j = pr.next_u32() % (i + 1)
        arr[i], arr[j] = arr[j], arr[i]
    for i in range(256):
        arr[i] = (arr[i] ^ ((i * 73) & 0xFF) ^ ((seed >> (i & 7)) & 0xFF)) & 0xFF
    return bytes(arr)


def decrypt(cipher: bytes, seed: int, round_idx: int) -> bytes:
    kseed = u32(seed ^ ROUND_SALT[round_idx - 1] ^ 0xC0DEC0DE)
    pr = XorShift32(kseed)
    out = bytearray(len(cipher))
    for i, c in enumerate(cipher):
        k = pr.next_u8()
        x = c ^ ((k * 0xA7) & 0xFF)
        x = nibswap(x)
        x = ror8(x, 3)
        out[i] = x ^ k
    return bytes(out)


def uleb_read(buf: bytes, p: int) -> tuple[int, int]:
    shift = 0
    val = 0
    while True:
        b = buf[p]
        p += 1
        val |= (b & 0x7F) << shift
        if (b & 0x80) == 0:
            return u32(val), p
        shift += 7
        if shift > 35:
            return u32(val), p


def sleb_read(buf: bytes, p: int) -> tuple[int, int]:
    shift = 0
    val = 0
    while True:
        b = buf[p]
        p += 1
        val |= (b & 0x7F) << shift
        shift += 7
        if (b & 0x80) == 0:
            if shift < 32 and (b & 0x40):
                val |= (-1) << shift
            return int(val), p


def load_u32_le(mem: bytearray, addr: int) -> int:
    a = addr & 0xFF
    return mem[a] | (mem[(a + 1) & 0xFF] << 8) | (mem[(a + 2) & 0xFF] << 16) | (mem[(a + 3) & 0xFF] << 24)


def store_u32_le(mem: bytearray, addr: int, v: int) -> None:
    a = addr & 0xFF
    v &= 0xFFFFFFFF
    mem[a] = v & 0xFF
    mem[(a + 1) & 0xFF] = (v >> 8) & 0xFF
    mem[(a + 2) & 0xFF] = (v >> 16) & 0xFF
    mem[(a + 3) & 0xFF] = (v >> 24) & 0xFF


def mix32(x: int, y: int, sbox: bytes) -> int:
    t = u32(x ^ rol32(y, 7) ^ 0x9E3779B9)
    b0 = t & 0xFF
    b1 = (t >> 8) & 0xFF
    b2 = (t >> 16) & 0xFF
    b3 = (t >> 24) & 0xFF

    b0 = sbox[b0] ^ ((y >> 0) & 0xFF)
    b1 = sbox[b1] ^ ((y >> 8) & 0xFF)
    b2 = sbox[b2] ^ ((y >> 16) & 0xFF)
    b3 = sbox[b3] ^ ((y >> 24) & 0xFF)

    b0 = rol8(b0, (y >> 1) & 7)
    b1 = rol8(b1, (y >> 9) & 7)
    b2 = rol8(b2, (y >> 17) & 7)
    b3 = rol8(b3, (y >> 25) & 7)

    o = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
    o = u32(o + ror32(x, 3) + 0x7F4A7C15)
    return o


def emulate_plain(plain: bytes, cycle_budget: int) -> bytes:
    if len(plain) < HEADER_LEN:
        raise ValueError("short")

    magic, ver, flg, hlen, seed, ridx, plen, pfnv, tag = struct.unpack_from(
        "<4sBBHIIIII", plain, 0
    )
    if magic != MAGIC or ver != VERSION or flg != FLAGS or hlen != HEADER_LEN:
        raise ValueError("header")

    payload = plain[HEADER_LEN:]
    if len(payload) != plen:
        raise ValueError("plen")
    if fnv1a32(payload) != pfnv:
        raise ValueError("fnv")
    if hdr_tag(seed, pfnv, plen) != tag:
        raise ValueError("tag")

    opb = opcode_bytes(seed)
    inv = [0xFF] * 256
    for sem, ob in enumerate(opb):
        inv[ob] = sem
    sbox = sbox_bytes(seed)

    regs = [0] * REGS
    mem = bytearray(MEM_SIZE)
    z = 0

    out = bytearray(32)
    out_set = False

    code = payload
    plen = len(code)
    pc = 0
    cycles = 0

    inv_l = inv
    regs_l = regs
    mem_l = mem
    sbox_l = sbox
    unpack_b = struct.unpack_from

    while pc < plen and cycles < cycle_budget:
        op = code[pc]
        pc += 1
        sem = inv_l[op]
        if sem == 0xFF:
            cycles += 1
            continue

        cycles += 1

        if sem == OP_NOP:
            continue

        if sem == OP_LDI:
            r = code[pc] & 7
            pc += 1
            v, pc = uleb_read(code, pc)
            regs_l[r] = v
            z = 1 if v == 0 else 0
            continue

        if sem == OP_ADDI:
            r = code[pc] & 7
            pc += 1
            v, pc = sleb_read(code, pc)
            regs_l[r] = u32(regs_l[r] + v)
            z = 1 if regs_l[r] == 0 else 0
            continue

        if sem == OP_ADD:
            ra = code[pc] & 7
            rb = code[pc + 1] & 7
            pc += 2
            regs_l[ra] = u32(regs_l[ra] + regs_l[rb])
            z = 1 if regs_l[ra] == 0 else 0
            continue

        if sem == OP_XOR:
            ra = code[pc] & 7
            rb = code[pc + 1] & 7
            pc += 2
            regs_l[ra] = u32(regs_l[ra] ^ regs_l[rb])
            z = 1 if regs_l[ra] == 0 else 0
            continue

        if sem == OP_MUL:
            ra = code[pc] & 7
            rb = code[pc + 1] & 7
            pc += 2
            regs_l[ra] = u32((regs_l[ra] * regs_l[rb]) & 0xFFFFFFFF)
            z = 1 if regs_l[ra] == 0 else 0
            continue

        if sem == OP_ROL:
            r = code[pc] & 7
            imm = code[pc + 1]
            pc += 2
            regs_l[r] = rol32(regs_l[r], imm)
            z = 1 if regs_l[r] == 0 else 0
            continue

        if sem == OP_LDR:
            dst = code[pc] & 7
            ar = code[pc + 1] & 7
            pc += 2
            addr = regs_l[ar] & 0xFF
            regs_l[dst] = load_u32_le(mem_l, addr)
            z = 1 if regs_l[dst] == 0 else 0
            continue

        if sem == OP_STR:
            src = code[pc] & 7
            ar = code[pc + 1] & 7
            pc += 2
            addr = regs_l[ar] & 0xFF
            store_u32_le(mem_l, addr, regs_l[src])
            continue

        if sem == OP_CMP:
            ra = code[pc] & 7
            rb = code[pc + 1] & 7
            pc += 2
            z = 1 if regs_l[ra] == regs_l[rb] else 0
            continue

        if sem == OP_JZ:
            rel = unpack_b("b", code, pc)[0]
            pc += 1
            if z:
                pc = (pc + rel) % plen
            continue

        if sem == OP_JNZ:
            rel = unpack_b("b", code, pc)[0]
            pc += 1
            if not z:
                pc = (pc + rel) % plen
            continue

        if sem == OP_MIX:
            ra = code[pc] & 7
            rb = code[pc + 1] & 7
            pc += 2
            regs_l[ra] = mix32(regs_l[ra], regs_l[rb], sbox_l)
            z = 1 if regs_l[ra] == 0 else 0
            continue

        if sem == OP_MEMXOR:
            ar = code[pc] & 7
            ln = code[pc + 1]
            sr = code[pc + 2] & 7
            pc += 3
            base = regs_l[ar] & 0xFF
            w = regs_l[sr]
            cycles += ln
            b0 = w & 0xFF
            b1 = (w >> 8) & 0xFF
            b2 = (w >> 16) & 0xFF
            b3 = (w >> 24) & 0xFF
            sb = sbox_l
            m = mem_l
            for i in range(ln):
                mix = sb[(i + b0) & 0xFF] ^ (b1 if (i & 1) else b2)
                if (i & 3) == 0:
                    k = b0
                elif (i & 3) == 1:
                    k = b1
                elif (i & 3) == 2:
                    k = b2
                else:
                    k = b3
                m[(base + i) & 0xFF] ^= (k ^ mix) & 0xFF
            continue

        if sem == OP_OUT:
            ar = code[pc] & 7
            pc += 1
            base = regs_l[ar] & 0xFF
            for i in range(32):
                out[i] = mem_l[(base + i) & 0xFF]
            out_set = True
            continue

        if sem == OP_HALT:
            break

    if out_set:
        return bytes(out)

    h = u32(0xDEADBEEF ^ seed ^ (ridx * 0x9E3779B9))
    for r in regs_l:
        h = u32(rol32(h, 5) ^ r)
    for i in range(64):
        h = u32((h * 0x01000193) ^ mem_l[i])
    pr = XorShift32(h)
    for i in range(32):
        out[i] = pr.next_u8() ^ sbox_l[i]
    return bytes(out)


def solve_round(seed: int, b64: str, cycle_budget: int, round_hint: int) -> str:
    ct = base64.b64decode(b64.encode("ascii"))

    # Try hinted round first, then the rest (robust against desync).
    tries = [round_hint] + [i for i in range(1, 6) if i != round_hint]
    last_err = None
    for ridx in tries:
        try:
            plain = decrypt(ct, seed, ridx)
            out = emulate_plain(plain, cycle_budget)
            return out.hex()
        except Exception as e:
            last_err = e
    raise RuntimeError(f"decrypt/emulate failed: {last_err}")


class SockBuf:
    def __init__(self, sock: socket.socket):
        self.sock = sock
        self.buf = bytearray()

    def _fill(self) -> None:
        chunk = self.sock.recv(4096)
        if not chunk:
            raise EOFError("socket closed")
        self.buf.extend(chunk)

    def recv_until(self, marker: bytes) -> bytes:
        while True:
            idx = self.buf.find(marker)
            if idx != -1:
                out = bytes(self.buf[: idx + len(marker)])
                del self.buf[: idx + len(marker)]
                return out
            self._fill()

    def recv_line(self) -> bytes:
        return self.recv_until(b"\n")


def parse_round(block: str):
    seed = None
    bc_len = None
    b64 = None
    budget = None

    for line in block.splitlines():
        line = line.strip()
        if line.startswith("SEED:"):
            seed = int(line.split(":", 1)[1].strip(), 16)
        elif line.startswith("BC_LEN:"):
            bc_len = int(line.split(":", 1)[1].strip())
        elif line.startswith("BYTECODE_B64:"):
            b64 = line.split(":", 1)[1].strip()
        elif line.startswith("CYCLE_BUDGET:"):
            budget = int(line.split(":", 1)[1].strip())

    if seed is None or bc_len is None or b64 is None or budget is None:
        raise ValueError("could not parse round")
    return seed, bc_len, b64, budget


def solve_once(host: str, port: int) -> None:
    with socket.create_connection((host, port), timeout=5.0) as s:
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        r = SockBuf(s)

        for round_idx in range(1, 6):
            # read until prompt
            block = r.recv_until(b"\n> ").decode("utf-8", "replace")
            seed, bc_len, b64, budget = parse_round(block)

            # (optional) sanity check
            _ = bc_len

            t0 = time.perf_counter()
            token = solve_round(seed, b64, budget, round_idx)
            dt_ms = (time.perf_counter() - t0) * 1000.0

            s.sendall(token.encode("ascii") + b"\n")
            resp = r.recv_line().decode("utf-8", "replace").rstrip("\n")
            print(resp)

            if "[WRONG]" in resp or "[TIMEOUT]" in resp:
                return

            # local debug (won't affect service)
            if dt_ms > 400:
                print(f"[local] slow round {round_idx}: {dt_ms:.1f}ms", file=sys.stderr)

        # read whatever left (flag line); server prints an extra blank line after last [OK]
        try:
            for _ in range(8):
                rest = r.recv_line().decode("utf-8", "replace").strip()
                if rest:
                    print(rest)
                    break
        except Exception:
            pass


def main() -> None:
    if len(sys.argv) < 3:
        print(f"usage: {sys.argv[0]} <host> <port>")
        sys.exit(1)

    host = sys.argv[1]
    port = int(sys.argv[2])

    # retries for stability
    for attempt in range(1, 4):
        try:
            solve_once(host, port)
            return
        except Exception as e:
            if attempt == 3:
                raise
            print(f"[retry] attempt {attempt} failed: {e}", file=sys.stderr)
            time.sleep(0.15)


if __name__ == "__main__":
    main()
