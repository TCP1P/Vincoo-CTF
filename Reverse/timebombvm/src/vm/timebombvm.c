// TimeBomb VM reference runner (dist attachment)
//
// Notes:
// - This implementation is intentionally *not* optimized as an oracle.
// - It's safe (not a pwn); bounds checks are present.
// - VM + codec spec matches server-side implementation.

#include <ctype.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define REGS 8
#define MEM_SIZE 256
#define OP_COUNT 16
#define HEADER_LEN 28

static const uint8_t MAGIC[4] = {'T','B','V','M'};
static const uint8_t VERSION = 1;
static const uint8_t FLAGS = 0x42;

static const uint32_t ROUND_SALT[5] = {
    0xA3B1C2D3u,
    0xC0DEC0DEu,
    0x9E3779B9u,
    0x7F4A7C15u,
    0x1B873593u,
};

// === Anti-trivial decoys (strings + unused code) ===
__attribute__((used))
static const char *DECOY_STRINGS[] = {
    "pwnme: printf(\"%p %p %p\\n\")",
    "stack canary? nope.",
    "ROP chain builder v0.0.0",
    "AES-256-GCM (lol no)",
    "You found the strings, not the solution.",
};

__attribute__((used))
static uint32_t decoy_crc32(const char *s) {
    // Not real CRC32. Misleading on purpose.
    uint32_t h = 0xDEADBEEFu;
    for (size_t i = 0; s[i]; i++) {
        h ^= (uint8_t)s[i];
        h = (h << 5) | (h >> 27);
        h += 0x1337u;
    }
    return h;
}

// === Helpers ===
static inline uint32_t u32(uint64_t x) { return (uint32_t)(x & 0xFFFFFFFFu); }

static inline uint32_t rol32(uint32_t x, uint32_t r) {
    r &= 31u;
    return u32(((uint64_t)x << r) | ((uint64_t)x >> (32u - r)));
}

static inline uint32_t ror32(uint32_t x, uint32_t r) {
    r &= 31u;
    return u32(((uint64_t)x >> r) | ((uint64_t)x << (32u - r)));
}

static inline uint8_t rol8(uint8_t x, uint8_t r) {
    r &= 7u;
    return (uint8_t)(((uint32_t)x << r) | ((uint32_t)x >> (8u - r)));
}

static inline uint8_t ror8(uint8_t x, uint8_t r) {
    r &= 7u;
    return (uint8_t)(((uint32_t)x >> r) | ((uint32_t)x << (8u - r)));
}

static inline uint8_t nibswap(uint8_t x) {
    return (uint8_t)(((x & 0x0Fu) << 4) | ((x >> 4) & 0x0Fu));
}

typedef struct {
    uint32_t s;
} xs32;

static inline void xs_init(xs32 *st, uint32_t seed) {
    st->s = seed ? seed : 0x12345678u;
}

static inline uint32_t xs_next_u32(xs32 *st) {
    uint32_t x = st->s;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    st->s = x;
    return x;
}

static inline uint8_t xs_next_u8(xs32 *st) {
    return (uint8_t)(xs_next_u32(st) >> 24);
}

static uint32_t fnv1a32(const uint8_t *data, size_t n) {
    uint32_t h = 0x811C9DC5u;
    for (size_t i = 0; i < n; i++) {
        h ^= data[i];
        h = u32((uint64_t)h * 0x01000193u);
    }
    return h;
}

static uint32_t hdr_tag(uint32_t seed, uint32_t payload_fnv, uint32_t payload_len) {
    uint32_t x = u32(seed ^ payload_fnv ^ u32((uint64_t)payload_len * 0x45D9F3Bu));
    // Match the Python reference's slightly "wide" rotate:
    // it rotates (x + const) without masking to 32-bit *before* the shifts.
    // For r==0 the expression becomes: (y | (y >> 32)) & 0xFFFFFFFF.
    uint64_t y = (uint64_t)x + 0x9E3779B9u;
    uint32_t r = (seed >> 27) & 31u;
    if (r == 0) {
        x = u32((uint32_t)(y | (y >> 32)));
    } else {
        x = u32((uint32_t)(((y << r) | (y >> (32 - r))) & 0xFFFFFFFFu));
    }
    return u32(x ^ 0xA5A5A5A5u);
}

// === Base64 decoding ===
static int b64_val(int c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static bool base64_decode(const char *in, uint8_t **out, size_t *out_len) {
    size_t n = strlen(in);
    // upper bound
    uint8_t *buf = (uint8_t *)malloc((n * 3) / 4 + 4);
    if (!buf) return false;

    size_t o = 0;
    int val = 0;
    int valb = -8;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)in[i];
        if (isspace(c)) continue;
        if (c == '=') break;
        int v = b64_val(c);
        if (v < 0) { free(buf); return false; }
        val = (val << 6) | v;
        valb += 6;
        if (valb >= 0) {
            buf[o++] = (uint8_t)((val >> valb) & 0xFF);
            valb -= 8;
        }
    }

    *out = buf;
    *out_len = o;
    return true;
}

// === Crypto codec ===
static void decrypt_bytes(const uint8_t *cipher, uint8_t *plain, size_t n, uint32_t seed, uint32_t round_idx) {
    uint32_t kseed = u32(seed ^ ROUND_SALT[round_idx - 1] ^ 0xC0DEC0DEu);
    xs32 pr;
    xs_init(&pr, kseed);

    for (size_t i = 0; i < n; i++) {
        uint8_t k = xs_next_u8(&pr);
        uint8_t x = (uint8_t)(cipher[i] ^ (uint8_t)((uint32_t)k * 0xA7u));
        x = nibswap(x);
        x = ror8(x, 3);
        plain[i] = (uint8_t)(x ^ k);
    }
}

// === Opcode map and S-box ===
static void opcode_bytes(uint32_t seed, uint8_t out_op[OP_COUNT]) {
    xs32 pr;
    xs_init(&pr, seed ^ 0xA341316Cu);

    uint8_t pool[256];
    for (int i = 0; i < 256; i++) pool[i] = (uint8_t)i;

    for (int i = 255; i >= 256 - 16; i--) {
        uint32_t j = xs_next_u32(&pr) % (uint32_t)(i + 1);
        uint8_t tmp = pool[i];
        pool[i] = pool[j];
        pool[j] = tmp;
    }

    for (int i = 0; i < 16; i++) out_op[i] = pool[256 - 16 + i];

    for (int i = 15; i > 0; i--) {
        uint32_t j = xs_next_u32(&pr) % (uint32_t)(i + 1);
        uint8_t tmp = out_op[i];
        out_op[i] = out_op[j];
        out_op[j] = tmp;
    }
}

static void inverse_opcode_map(const uint8_t op[OP_COUNT], uint8_t inv[256]) {
    for (int i = 0; i < 256; i++) inv[i] = 0xFFu;
    for (int sem = 0; sem < OP_COUNT; sem++) {
        inv[op[sem]] = (uint8_t)sem;
    }
}

static void sbox_bytes(uint32_t seed, uint8_t sbox[256]) {
    xs32 pr;
    xs_init(&pr, seed ^ 0x1B873593u);

    for (int i = 0; i < 256; i++) sbox[i] = (uint8_t)i;

    for (int i = 255; i > 0; i--) {
        uint32_t j = xs_next_u32(&pr) % (uint32_t)(i + 1);
        uint8_t tmp = sbox[i];
        sbox[i] = sbox[j];
        sbox[j] = tmp;
    }

    for (int i = 0; i < 256; i++) {
        uint8_t v = sbox[i];
        v ^= (uint8_t)((i * 73) & 0xFF);
        v ^= (uint8_t)((seed >> (i & 7)) & 0xFF);
        sbox[i] = v;
    }
}

// === LEB128 decoding ===
static bool dec_uleb128(const uint8_t *buf, size_t n, size_t *p, uint32_t *out) {
    uint32_t shift = 0;
    uint32_t val = 0;
    while (*p < n) {
        uint8_t b = buf[(*p)++];
        val |= (uint32_t)(b & 0x7Fu) << shift;
        if ((b & 0x80u) == 0) { *out = val; return true; }
        shift += 7;
        if (shift > 35) { *out = val; return true; }
    }
    return false;
}

static bool dec_sleb128(const uint8_t *buf, size_t n, size_t *p, int32_t *out) {
    int32_t shift = 0;
    int32_t val = 0;
    uint8_t b = 0;
    while (*p < n) {
        b = buf[(*p)++];
        val |= ((int32_t)(b & 0x7F)) << shift;
        shift += 7;
        if ((b & 0x80u) == 0) break;
        if (shift > 35) break;
    }
    if (shift < 32 && (b & 0x40u)) val |= - (1 << shift);
    *out = val;
    return true;
}

static inline uint32_t load_u32_le(const uint8_t mem[MEM_SIZE], uint8_t addr) {
    uint8_t a = addr;
    return (uint32_t)mem[a]
        | ((uint32_t)mem[(uint8_t)(a + 1)] << 8)
        | ((uint32_t)mem[(uint8_t)(a + 2)] << 16)
        | ((uint32_t)mem[(uint8_t)(a + 3)] << 24);
}

static inline void store_u32_le(uint8_t mem[MEM_SIZE], uint8_t addr, uint32_t v) {
    uint8_t a = addr;
    mem[a] = (uint8_t)(v & 0xFFu);
    mem[(uint8_t)(a + 1)] = (uint8_t)((v >> 8) & 0xFFu);
    mem[(uint8_t)(a + 2)] = (uint8_t)((v >> 16) & 0xFFu);
    mem[(uint8_t)(a + 3)] = (uint8_t)((v >> 24) & 0xFFu);
}

static inline uint32_t mix32(uint32_t x, uint32_t y, const uint8_t sbox[256]) {
    uint32_t t = u32(x ^ rol32(y, 7) ^ 0x9E3779B9u);
    uint8_t b0 = (uint8_t)(t & 0xFFu);
    uint8_t b1 = (uint8_t)((t >> 8) & 0xFFu);
    uint8_t b2 = (uint8_t)((t >> 16) & 0xFFu);
    uint8_t b3 = (uint8_t)((t >> 24) & 0xFFu);

    b0 = (uint8_t)(sbox[b0] ^ (uint8_t)((y >> 0) & 0xFFu));
    b1 = (uint8_t)(sbox[b1] ^ (uint8_t)((y >> 8) & 0xFFu));
    b2 = (uint8_t)(sbox[b2] ^ (uint8_t)((y >> 16) & 0xFFu));
    b3 = (uint8_t)(sbox[b3] ^ (uint8_t)((y >> 24) & 0xFFu));

    b0 = rol8(b0, (uint8_t)((y >> 1) & 7u));
    b1 = rol8(b1, (uint8_t)((y >> 9) & 7u));
    b2 = rol8(b2, (uint8_t)((y >> 17) & 7u));
    b3 = rol8(b3, (uint8_t)((y >> 25) & 7u));

    uint32_t o = (uint32_t)b0 | ((uint32_t)b1 << 8) | ((uint32_t)b2 << 16) | ((uint32_t)b3 << 24);
    o = u32((uint64_t)o + ror32(x, 3) + 0x7F4A7C15u);
    return o;
}

// === Intentionally slow "oracle" overhead ===
static inline void slow_tick(volatile uint32_t *noise, uint8_t byte) {
    // This has no effect on output, but makes subprocess-oracle approaches painful.
    // It is *not* part of the VM semantics.
    uint32_t n = *noise ^ (uint32_t)byte;
    // Tune if needed. (must not be optimized away)
    for (int i = 0; i < 17000; i++) {
        n = u32((uint64_t)n * 1664525u + 1013904223u);
        n ^= n >> 16;
    }
    *noise = n;
}

static bool emulate_plain(const uint8_t *plain, size_t plain_len, uint32_t cycle_budget, uint8_t out32[32]) {
    if (plain_len < HEADER_LEN) return false;

    // Parse header: <4sBBHIIIII
    // magic[4], ver,u8 flags, u16 hlen, seed, ridx, plen, pfnv, tag
    const uint8_t *p = plain;
    if (memcmp(p, MAGIC, 4) != 0) return false;
    uint8_t ver = p[4];
    uint8_t flg = p[5];
    uint16_t hlen = (uint16_t)p[6] | ((uint16_t)p[7] << 8);
    (void)flg;
    if (ver != VERSION || hlen != HEADER_LEN) return false;

    uint32_t seed = (uint32_t)p[8] | ((uint32_t)p[9] << 8) | ((uint32_t)p[10] << 16) | ((uint32_t)p[11] << 24);
    uint32_t ridx = (uint32_t)p[12] | ((uint32_t)p[13] << 8) | ((uint32_t)p[14] << 16) | ((uint32_t)p[15] << 24);
    uint32_t plen = (uint32_t)p[16] | ((uint32_t)p[17] << 8) | ((uint32_t)p[18] << 16) | ((uint32_t)p[19] << 24);
    uint32_t pfnv = (uint32_t)p[20] | ((uint32_t)p[21] << 8) | ((uint32_t)p[22] << 16) | ((uint32_t)p[23] << 24);
    uint32_t tag = (uint32_t)p[24] | ((uint32_t)p[25] << 8) | ((uint32_t)p[26] << 16) | ((uint32_t)p[27] << 24);

    if (FLAGS != FLAGS) {
        // placeholder to keep FLAGS "used"
        decoy_crc32(DECOY_STRINGS[0]);
    }

    if (plain_len != (size_t)HEADER_LEN + (size_t)plen) return false;
    const uint8_t *payload = plain + HEADER_LEN;

    if (fnv1a32(payload, plen) != pfnv) return false;
    if (hdr_tag(seed, pfnv, plen) != tag) return false;

    uint8_t opb[OP_COUNT];
    uint8_t inv[256];
    uint8_t sbox[256];
    opcode_bytes(seed, opb);
    inverse_opcode_map(opb, inv);
    sbox_bytes(seed, sbox);

    uint32_t regs[REGS];
    uint8_t mem[MEM_SIZE];
    memset(regs, 0, sizeof(regs));
    memset(mem, 0, sizeof(mem));

    uint8_t out[32];
    bool out_set = false;
    int z = 0;

    size_t pc = 0;
    uint32_t cycles = 0;

    volatile uint32_t noise = 0xCAFEBABEu;

    while (pc < plen && cycles < cycle_budget) {
        uint8_t op = payload[pc++];
        uint8_t sem = inv[op];
        if (sem == 0xFFu) {
            cycles += 1;
            slow_tick(&noise, op);
            continue;
        }

        cycles += 1;
        slow_tick(&noise, op);

        switch (sem) {
            case 0: // NOP
                break;
            case 1: { // LDI
                if (pc + 1 > plen) return false;
                uint8_t r = payload[pc++] & 7u;
                uint32_t v;
                if (!dec_uleb128(payload, plen, &pc, &v)) return false;
                regs[r] = v;
                z = (v == 0);
                break;
            }
            case 4: { // ADDI
                if (pc + 1 > plen) return false;
                uint8_t r = payload[pc++] & 7u;
                int32_t v;
                if (!dec_sleb128(payload, plen, &pc, &v)) return false;
                regs[r] = u32((uint64_t)regs[r] + (int64_t)v);
                z = (regs[r] == 0);
                break;
            }
            case 2: { // ADD
                if (pc + 2 > plen) return false;
                uint8_t ra = payload[pc++] & 7u;
                uint8_t rb = payload[pc++] & 7u;
                regs[ra] = u32((uint64_t)regs[ra] + regs[rb]);
                z = (regs[ra] == 0);
                break;
            }
            case 3: { // XOR
                if (pc + 2 > plen) return false;
                uint8_t ra = payload[pc++] & 7u;
                uint8_t rb = payload[pc++] & 7u;
                regs[ra] = u32(regs[ra] ^ regs[rb]);
                z = (regs[ra] == 0);
                break;
            }
            case 5: { // MUL
                if (pc + 2 > plen) return false;
                uint8_t ra = payload[pc++] & 7u;
                uint8_t rb = payload[pc++] & 7u;
                regs[ra] = u32((uint64_t)regs[ra] * regs[rb]);
                z = (regs[ra] == 0);
                break;
            }
            case 6: { // ROL
                if (pc + 2 > plen) return false;
                uint8_t r = payload[pc++] & 7u;
                uint8_t imm = payload[pc++];
                regs[r] = rol32(regs[r], imm);
                z = (regs[r] == 0);
                break;
            }
            case 7: { // LDR
                if (pc + 2 > plen) return false;
                uint8_t dst = payload[pc++] & 7u;
                uint8_t ar = payload[pc++] & 7u;
                uint8_t addr = (uint8_t)(regs[ar] & 0xFFu);
                regs[dst] = load_u32_le(mem, addr);
                z = (regs[dst] == 0);
                break;
            }
            case 8: { // STR
                if (pc + 2 > plen) return false;
                uint8_t src = payload[pc++] & 7u;
                uint8_t ar = payload[pc++] & 7u;
                uint8_t addr = (uint8_t)(regs[ar] & 0xFFu);
                store_u32_le(mem, addr, regs[src]);
                break;
            }
            case 9: { // CMP
                if (pc + 2 > plen) return false;
                uint8_t ra = payload[pc++] & 7u;
                uint8_t rb = payload[pc++] & 7u;
                z = (regs[ra] == regs[rb]);
                break;
            }
            case 10: { // JZ
                if (pc + 1 > plen) return false;
                int8_t rel = (int8_t)payload[pc++];
                if (z) {
                    int32_t np = (int32_t)pc + (int32_t)rel;
                    np %= (int32_t)plen;
                    if (np < 0) np += (int32_t)plen;
                    pc = (size_t)np;
                }
                break;
            }
            case 11: { // JNZ
                if (pc + 1 > plen) return false;
                int8_t rel = (int8_t)payload[pc++];
                if (!z) {
                    int32_t np = (int32_t)pc + (int32_t)rel;
                    np %= (int32_t)plen;
                    if (np < 0) np += (int32_t)plen;
                    pc = (size_t)np;
                }
                break;
            }
            case 12: { // MIX
                if (pc + 2 > plen) return false;
                uint8_t ra = payload[pc++] & 7u;
                uint8_t rb = payload[pc++] & 7u;
                regs[ra] = mix32(regs[ra], regs[rb], sbox);
                z = (regs[ra] == 0);
                break;
            }
            case 13: { // MEMXOR
                if (pc + 3 > plen) return false;
                uint8_t ar = payload[pc++] & 7u;
                uint8_t ln = payload[pc++];
                uint8_t sr = payload[pc++] & 7u;
                uint8_t base = (uint8_t)(regs[ar] & 0xFFu);
                uint32_t w = regs[sr];
                cycles += (uint32_t)ln;

                uint8_t b0 = (uint8_t)(w & 0xFFu);
                uint8_t b1 = (uint8_t)((w >> 8) & 0xFFu);
                uint8_t b2 = (uint8_t)((w >> 16) & 0xFFu);
                uint8_t b3 = (uint8_t)((w >> 24) & 0xFFu);

                for (uint32_t i = 0; i < (uint32_t)ln; i++) {
                    uint8_t mix = (uint8_t)(sbox[(uint8_t)(i + b0)] ^ ((i & 1u) ? b1 : b2));
                    uint8_t k;
                    switch (i & 3u) {
                        case 0: k = b0; break;
                        case 1: k = b1; break;
                        case 2: k = b2; break;
                        default: k = b3; break;
                    }
                    mem[(uint8_t)(base + (uint8_t)i)] ^= (uint8_t)(k ^ mix);
                }
                break;
            }
            case 14: { // OUT
                if (pc + 1 > plen) return false;
                uint8_t ar = payload[pc++] & 7u;
                uint8_t base = (uint8_t)(regs[ar] & 0xFFu);
                for (uint32_t i = 0; i < 32; i++) {
                    out[i] = mem[(uint8_t)(base + (uint8_t)i)];
                }
                out_set = true;
                break;
            }
            case 15: // HALT
                pc = plen; // exit
                break;
            default:
                break;
        }
    }

    if (out_set) {
        memcpy(out32, out, 32);
        return true;
    }

    // Fallback (shouldn't happen for valid programs)
    uint32_t h = u32(0xDEADBEEFu ^ seed ^ u32(ridx * 0x9E3779B9u));
    for (int i = 0; i < REGS; i++) {
        h = u32(rol32(h, 5) ^ regs[i]);
    }
    for (int i = 0; i < 64; i++) {
        h = u32((uint64_t)h * 0x01000193u) ^ mem[i];
    }

    xs32 pr;
    xs_init(&pr, h);
    for (int i = 0; i < 32; i++) {
        out32[i] = (uint8_t)(xs_next_u8(&pr) ^ sbox[i]);
    }
    return true;
}

static bool parse_seed_hex(const char *s, uint32_t *out) {
    if (strlen(s) != 8) return false;
    uint32_t v = 0;
    for (int i = 0; i < 8; i++) {
        char c = s[i];
        int d;
        if (c >= '0' && c <= '9') d = c - '0';
        else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
        else return false;
        v = (v << 4) | (uint32_t)d;
    }
    *out = v;
    return true;
}

static void hex_print32(const uint8_t out32[32]) {
    static const char *H = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {
        putchar(H[(out32[i] >> 4) & 0xF]);
        putchar(H[out32[i] & 0xF]);
    }
    putchar('\n');
}

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "usage: %s <seed8hex> <cycle_budget_int> <BYTECODE_B64>\n", argv[0]);
        fprintf(stderr, "example: %s deadbeef 120000 'SGVsbG8='\n", argv[0]);
        return 1;
    }

    // keep decoys referenced
    (void)decoy_crc32(DECOY_STRINGS[1]);

    uint32_t seed;
    if (!parse_seed_hex(argv[1], &seed)) {
        fprintf(stderr, "bad seed\n");
        return 1;
    }

    char *end = NULL;
    uint32_t budget = (uint32_t)strtoul(argv[2], &end, 10);
    if (!end || *end != '\0') {
        fprintf(stderr, "bad cycle_budget\n");
        return 1;
    }

    uint8_t *cipher = NULL;
    size_t cipher_len = 0;
    if (!base64_decode(argv[3], &cipher, &cipher_len)) {
        fprintf(stderr, "bad base64\n");
        return 1;
    }

    uint8_t *plain = (uint8_t *)malloc(cipher_len);
    if (!plain) {
        fprintf(stderr, "oom\n");
        free(cipher);
        return 1;
    }

    bool ok = false;
    uint8_t out32[32];

    // Try all 5 round salts; header checksum tells the right one.
    for (uint32_t ridx = 1; ridx <= 5; ridx++) {
        decrypt_bytes(cipher, plain, cipher_len, seed, ridx);
        if (cipher_len < HEADER_LEN) continue;
        if (memcmp(plain, MAGIC, 4) != 0) continue;
        if (plain[4] != VERSION) continue;
        uint16_t hlen = (uint16_t)plain[6] | ((uint16_t)plain[7] << 8);
        if (hlen != HEADER_LEN) continue;

        // quick validate lengths
        uint32_t plen = (uint32_t)plain[16] | ((uint32_t)plain[17] << 8) | ((uint32_t)plain[18] << 16) | ((uint32_t)plain[19] << 24);
        if (cipher_len != (size_t)HEADER_LEN + (size_t)plen) continue;

        // full emulate does checksum/tag validation
        if (emulate_plain(plain, cipher_len, budget, out32)) {
            ok = true;
            break;
        }
    }

    if (!ok) {
        fprintf(stderr, "failed to decode/decrypt\n");
        free(plain);
        free(cipher);
        return 1;
    }

    hex_print32(out32);

    free(plain);
    free(cipher);
    return 0;
}
