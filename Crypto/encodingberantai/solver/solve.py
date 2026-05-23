"""
Solver script for the challenge.
Reverses the encoding chain: Base64 -> Hex -> ROT13
"""
import base64
import codecs


def from_base64(text: str) -> str:
    """Decode Base64 to text."""
    return base64.b64decode(text.encode()).decode()


def from_hex(hex_str: str) -> str:
    """Convert hexadecimal to text."""
    return bytes.fromhex(hex_str).decode()


def rot13(text: str) -> str:
    """Apply ROT13 decoding (same as encoding)."""
    return codecs.encode(text, 'rot_13')


def decode_message(encoded: str) -> str:
    """
    Reverse encoding chain: Base64 -> Hex -> ROT13
    """
    step1 = from_base64(encoded)
    step2 = from_hex(step1)
    step3 = rot13(step2)
    return step3


if __name__ == "__main__":
    # Read encoded message
    with open("../dist/pesan.txt", "r") as f:
        encoded = f.read().strip()
    
    print(f"Encoded: {encoded}")
    flag = decode_message(encoded)
    print(f"Flag: {flag}")
