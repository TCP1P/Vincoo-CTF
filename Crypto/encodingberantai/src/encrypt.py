"""
Encryption script for the challenge.
Applies multiple encoding layers: ROT13 -> Hex -> Base64
"""
import base64
import codecs


def rot13(text: str) -> str:
    """Apply ROT13 encoding."""
    return codecs.encode(text, 'rot_13')


def to_hex(text: str) -> str:
    """Convert text to hexadecimal."""
    return text.encode().hex()


def to_base64(text: str) -> str:
    """Encode text as Base64."""
    return base64.b64encode(text.encode()).decode()


def encode_message(plaintext: str) -> str:
    """
    Apply encoding chain: ROT13 -> Hex -> Base64
    """
    step1 = rot13(plaintext)
    step2 = to_hex(step1)
    step3 = to_base64(step2)
    return step3


if __name__ == "__main__":
    flag = "SnapanCTF{ini_namanya_encoding_yh_berbeda_dengan_encryption}"
    encoded = encode_message(flag)
    print(f"Encoded message: {encoded}")
    
    # Save to dist folder
    with open("../dist/pesan.txt", "w") as f:
        f.write(encoded)
    print("Saved to ../dist/pesan.txt")
