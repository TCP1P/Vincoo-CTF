from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import os
import hashlib
from tqdm import tqdm

def solve():
    # Read ciphertext
    dist_dir = os.path.join(os.path.dirname(__file__), '../dist')
    
    try:
        with open(os.path.join(dist_dir, 'out.txt'), 'r') as f:
            ciphertext_hex = f.read().strip()
    except FileNotFoundError:
        print("out.txt not found. Run gen.py first.")
        return
        
    ciphertext = bytes.fromhex(ciphertext_hex)
    IV = b"vectorrahasia123"
    
    print("Brute-forcing key (0-100000)...")
    
    for seed in tqdm(range(100001)):
        key = hashlib.md5(str(seed).encode()).digest()
        
        try:
            cipher = AES.new(key, AES.MODE_CBC, IV)
            plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
            
            if plaintext.startswith(b"SnapanCTF{"):
                print(f"\nFound seed: {seed}")
                print(f"Flag: {plaintext.decode()}")
                return
        except (ValueError, KeyError):
            # Padding error or other decryption issues
            continue
            
    print("Flag not found.")

if __name__ == "__main__":
    solve()
