import sys
import os

# Menyesuaikan ya mas ee
# Mas Dim ini kamu harus install hlextend tools dulu buat nampung hashnya
# Karna library tools hlextend udh ga bisa pake pip jadi install on local toolsnya.
sys.path.append('/home/wanzkey/hlextend')

from pwn import *
import hlextend
import hashpumpy
import binascii

# Jalur Koneksi
host = '' #Sesuai Nc
port =  # Sesuai Port
data_to_add = b"Bagi flagnya dong om..."
key_length = 16

r = remote(host, port)

def solve_round(algo_name):
    print(f"\n[+] Ronde: {algo_name}")

    # 1. Ambil Hash dari Server
    r.recvuntil(b'hash: ')
    original_hash = r.recvline().strip().decode()
    print(f"    Original Hash: {original_hash}")

    if algo_name == "MD5":
        new_hash, payload_temp = hashpumpy.hashpump(original_hash, b'A', data_to_add, 15)
        payload = payload_temp[1:] 
        print("    [!] MD5 Bypassed using Length-Trick")

    else:
        if algo_name == "SHA1":
            ext = hlextend.sha1()
        elif algo_name == "SHA256":
            ext = hlextend.sha256()
        elif algo_name == "SHA512":
            ext = hlextend.sha512()

        payload = ext.extend(data_to_add, b"", key_length, original_hash)
        new_hash = ext.hexdigest()

    print(f"    New Hash     : {new_hash}")

    # 2. Send Payload
    evil_text_hex = binascii.hexlify(payload)
    r.sendline(evil_text_hex)
    r.sendline(new_hash.encode())

try:
    for a in ["MD5", "SHA1", "SHA256", "SHA512"]:
        solve_round(a)

    print("\n[!] Voila! Solp Coy!")
    r.interactive()
except Exception as e:
    print(f"\n[-] Error: {e}")
    import traceback
    traceback.print_exc()
    r.interactive()
