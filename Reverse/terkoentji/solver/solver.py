#!/usr/bin/env python3
"""
Solver for "Locked Away" challenge.

Analysis:
1. The password is XOR encoded with key 0x5A
2. The flag is AES-128-CBC encrypted using first 16 chars of password as key
3. Solution: Reverse XOR to get password, then input it to decrypt flag

This solver demonstrates how to extract the password from the binary.
"""

XOR_KEY = 0x5A

# Extracted from static analysis of the binary
encoded_password = bytes([
    0x29, 0x6a, 0x35, 0x6a, 0x35, 0x05, 0x2c, 0x69,
    0x28, 0x23, 0x05, 0x29, 0x69, 0x39, 0x2f, 0x28,
    0x69, 0x05, 0x2a, 0x6e, 0x29, 0x29, 0x2d, 0x6a,
    0x28, 0x3e
])

def xor_decode(data: bytes, key: int) -> str:
    """Decode XOR'd data with single-byte key."""
    return ''.join(chr(b ^ key) for b in data)

def main():
    password = xor_decode(encoded_password, XOR_KEY)
    print(f"[+] XOR Key: 0x{XOR_KEY:02X}")
    print(f"[+] Password: {password}")
    print()
    print("[*] The flag is AES-128-CBC encrypted using first 16 chars of password as key.")
    print("[*] Input the password into the binary to decrypt the flag.")
    print()
    print(f"[*] Run: echo '{password}' | ./terkoentji")

if __name__ == "__main__":
    main()
