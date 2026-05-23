from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import random
import hashlib
import os

FLAG = b"REDACTED"
IV = b"vectorrahasia123"

def get_key():
    seed = random.randint(0, 100000)
    key = hashlib.md5(str(seed).encode()).digest()
    return key

def encrypt():
    key = get_key()
    cipher = AES.new(key, AES.MODE_CBC, IV)
    ciphertext = cipher.encrypt(pad(FLAG, AES.block_size))
    print(ciphertext.hex())

if __name__ == "__main__":
    encrypt()
