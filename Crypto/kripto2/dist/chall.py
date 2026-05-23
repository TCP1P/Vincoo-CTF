from Crypto.Util.number import getPrime, bytes_to_long
from secret import FLAG
#

def generate_leak(p, q):
    p_str = str(p)
    q_str = str(q)
    # The logic is visible, but the math to reverse it is hard!
    p = p_str[1::2] 
    q = q_str[0::2] 
    return p, q

def main():
    DIGIT_LEN = 200 
    
    p = getPrime(665) 
    q = getPrime(665)
    
    while len(str(p)) != DIGIT_LEN or len(str(q)) != DIGIT_LEN:
        p = getPrime(665)
        q = getPrime(665)

    n = p * q
    e = 65537

    p, q = generate_leak(p, q)

    m = bytes_to_long(FLAG)
    c = pow(m, e, n)

    print(f"n = {n}")
    print(f"e = {e}")
    print(f"ct = {c}")
    print(f"p = '{p}'")
    print(f"q = '{q}'")

if __name__ == "__main__":
    main()