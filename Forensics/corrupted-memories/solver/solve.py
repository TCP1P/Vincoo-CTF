import os

def solve():
    # Path to the challenge file
    challenge_path = os.path.join(os.path.dirname(__file__), '../dist/memories.png')
    recovered_path = os.path.join(os.path.dirname(__file__), 'recovered.png')

    if not os.path.exists(challenge_path):
        print(f"Error: {challenge_path} not found.")
        return

    print(f"Reading {challenge_path}...")
    with open(challenge_path, 'rb') as f:
        data = bytearray(f.read())

    # Correct PNG signature: 89 50 4E 47 0D 0A 1A 0A
    correct_header = b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A'
    
    print("Fixing magic bytes...")
    data[:8] = correct_header

    print(f"Saving recovered file to {recovered_path}...")
    with open(recovered_path, 'wb') as f:
        f.write(data)

    print("Done! Open 'recovered.png' to see the flag.")

if __name__ == "__main__":
    solve()
