"""
Solver script for small exponent RSA challenge.
Uses integer cube root to recover plaintext.
"""
from Crypto.Util.number import long_to_bytes
import gmpy2


def integer_nth_root(x: int, n: int) -> int:
    """Compute integer nth root using gmpy2."""
    return int(gmpy2.iroot(x, n)[0])


def solve_small_e(n: int, e: int, c: int) -> bytes:
    """
    Solve RSA with small exponent.
    Try c, c+n, c+2n, ... until we find valid plaintext.
    """
    for k in range(100000):
        m_candidate = integer_nth_root(c + k * n, e)
        # Verify
        if pow(m_candidate, e) == c + k * n:
            try:
                plaintext = long_to_bytes(m_candidate)
                # Check if it looks like flag
                if b"SnapanCTF" in plaintext or plaintext.isascii():
                    return plaintext
            except:
                pass
    return None


if __name__ == "__main__":
    # Read from output file
    with open("../dist/output.txt", "r") as f:
        content = f.read()
    
    # Parse values
    lines = content.strip().split("\n")
    n = int(lines[0].split(" = ")[1])
    e = int(lines[1].split(" = ")[1])
    c = int(lines[2].split(" = ")[1])
    
    print(f"n = {n}")
    print(f"e = {e}")
    print(f"c = {c}")
    print()
    
    # Solve
    flag = solve_small_e(n, e, c)
    if flag:
        print(f"Flag: {flag.decode()}")
    else:
        print("Failed to find flag!")
