import base64
import codecs

B = b'gGIghgQHUGadFAHVGFIUsaddwg'
C = b'DBDabASsjnBajhvjhDShuGdvW'

def dec(payload: str) -> bytes:
    a = bytes.fromhex(payload)
    a = a[48:] + a[:48]
    enc = codecs.encode(a.decode(), "rot_13")
    enc = enc[::-1]
    enc = base64.b64decode(enc.encode())

    tmp = [0] * len(enc)
    for i in range(len(enc)):
        tmp[i] = enc[i] ^ B[i % len(B)] ^ C[i % len(C)]
    enc = bytes(tmp)

    enc = codecs.encode(enc.decode(), "rot_13")
    enc = enc[::-1]
    enc = base64.b64decode(enc.encode())

    tmp = [0] * len(enc)
    for i in range(len(enc)):
        tmp[i] = enc[i] ^ B[i % len(B)] ^ C[i % len(C)]
    enc = bytes(tmp)
    return enc

def make_payload(plaintext: bytes) -> str:
    y2 = bytes(plaintext[i] ^ B[i % len(B)] ^ C[i % len(C)]
               for i in range(len(plaintext)))
    s2 = base64.b64encode(y2).decode()
    s1 = s2[::-1]
    s0 = codecs.encode(s1, "rot_13")
    x = s0.encode()         
    y1 = bytes(x[i] ^ B[i % len(B)] ^ C[i % len(C)]
               for i in range(len(x)))
    t2 = base64.b64encode(y1).decode()
    t1 = t2[::-1]
    t0 = codecs.encode(t1, "rot_13")
    a1 = t0.encode()
    a0 = a1[-48:] + a1[:-48]  
    payload_hex = a0.hex()
    return payload_hex

if __name__ == "__main__":
    # len must be around 52 ~ 54
    pt = b"Usage: ./chall ls /;ls;ls;ls;ls;ls;ls;cat /flag.txt;"
    payload = make_payload(pt)
    print("payload len:", len(payload))
    print("payload:", payload)
