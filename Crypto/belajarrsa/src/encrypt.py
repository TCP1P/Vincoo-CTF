"""
RSA encryption script for the challenge.
Uses small exponent e=3 vulnerability.
"""
from Crypto.Util.number import bytes_to_long, getPrime
import json


def generate_rsa_params():
    """Generate RSA parameters with small e=3."""
    # Generate large primes for n - need n > m^3
    # Flag is ~50 bytes = 400 bits, so m^3 ~ 1200 bits
    # Use 1024-bit primes for n ~ 2048 bits > 1200 bits
    p = getPrime(1024)
    q = getPrime(1024)
    n = p * q
    e = 3  # Small exponent - vulnerability!
    return n, e


def encrypt(message: bytes, n: int, e: int) -> int:
    """Encrypt message using RSA."""
    m = bytes_to_long(message)
    c = pow(m, e, n)
    return c


if __name__ == "__main__":
    flag = b"SnapanCTF{0h_t1d4kk_t3rny474_R54_54y4_m4s1h_l3m4h}"
    
    # Generate RSA parameters
    n, e = generate_rsa_params()
    
    # Encrypt the flag
    c = encrypt(flag, n, e)
    
    # Check if m^e < n (cube root attack works directly)
    m = bytes_to_long(flag)
    if m ** e < n:
        print("Note: m^e < n, direct cube root attack possible!")
    else:
        print("Note: m^e >= n, need to try m^e + k*n")
    
    # Save to output file
    output = {
        "n": n,
        "e": e,
        "c": c
    }
    
    with open("../dist/output.txt", "w") as f:
        f.write(f"n = {n}\n")
        f.write(f"e = {e}\n")
        f.write(f"c = {c}\n")
    
    print(f"n = {n}")
    print(f"e = {e}")
    print(f"c = {c}")
    print("\nSaved to ../dist/output.txt")
