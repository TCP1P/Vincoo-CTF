from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import os
import random
import hashlib

FLAG = b"SnapanCTF{AES_t3h_3n4k_b3ttt}"
IV = b"vectorrahasia123" # 16 bytes

def get_key():
    # Weak key generation
    seed = random.randint(0, 100000)
    key = hashlib.md5(str(seed).encode()).digest()
    return key, seed

def encrypt():
    key, seed = get_key()
    cipher = AES.new(key, AES.MODE_CBC, IV)
    ciphertext = cipher.encrypt(pad(FLAG, AES.block_size))
    return ciphertext.hex(), seed

def main():
    encrypted, seed = encrypt()
    
    # Paths
    dist_dir = os.path.join(os.path.dirname(__file__), '../dist')
    os.makedirs(dist_dir, exist_ok=True)
    
    # Write out.txt
    with open(os.path.join(dist_dir, 'out.txt'), 'w') as f:
        f.write(encrypted)
        
    # Write chall.py (the challenge file given to participants)
    chall_content = f'''from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import random
import hashlib
import os

FLAG = b"REDACTED"
IV = b"{IV.decode()}"

def get_key():
    # I use random so it's secure, right?
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
'''
    with open(os.path.join(dist_dir, 'chall.py'), 'w') as f:
        f.write(chall_content)
        
    print(f"Generated challenge files in dist/ used seed: {seed}")

if __name__ == "__main__":
    main()
