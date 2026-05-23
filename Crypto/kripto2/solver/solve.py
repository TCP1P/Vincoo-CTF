import math
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def modInverse(a, m):
    if math.gcd(a, m) != 1: return -1
    return pow(a, -1, m)

def get_digit(arr, idx, default=None):
    if 0 <= idx < len(arr): return arr[idx]
    return default

def get_digit_zero(arr, idx):
    if 0 <= idx < len(arr): return arr[idx]
    return 0

def solve_challenge():
    n = 2278315968032468931467813661937490514665657030122832411131606537274670604547780610107251880715147685560647464122396690502993870130549927128658842438849773133971719935696761837245890137180917206936552296149900003980759059496801464976880245841134898763479748896868448623703002133515669724923246569822942192126660976547861946392345373821646792824383810580600868694538268083408840456654724160983866834589
    ct_hex = "52c92aeccde16b772b5b9358d2580bc11e15881784c75dae04553e66f7b046cfdf498598d1fa8ffa6538d4dabd6575cf9979afcd8ab0cd05dc9f03aa9adac2f7f253c4ffb94643fb65b5a3b201310f467a0875b374211edbbab1220a3b1a18e2554051b5921b3667f40fbcff76c68333cd3ac3ff57c88514aaceba4b66e528d2bec7cb296b87be413f05e1feef74e91c53bb4955c6b7980a4d62ec924db5faf9083c44e89306"
    
    qlik_raw = "6504606717673503861344492346710283352393357667044866566290357486268993357397259603951807995589051859"
    plik_raw = "5801778746407556364485139004695003971844622093766910298894832436657334800158205808247642551845896087"
    qlik = "".join(filter(str.isdigit, qlik_raw))
    plik = "".join(filter(str.isdigit, plik_raw))
    ct_bytes = bytes.fromhex(ct_hex)
    e = 65537
    len_p = 200
    len_q = 200

    print(f"DEBUG: Starting Reconstruction. qlik_len={len(qlik)}, plik_len={len(plik)}")

    p_digits_template = [-1] * len_p
    q_digits_template = [-1] * len_q

    for i, d in enumerate(qlik):
        if 2 * i < len_q: q_digits_template[2 * i] = int(d)
    for i, d in enumerate(plik):
        j = 2 * i + 1
        if j < len_p: p_digits_template[j] = int(d)

    p_rev = p_digits_template[::-1]
    q_rev = q_digits_template[::-1]
    n_rev = [int(x) for x in str(n)[::-1]]
    
    p_sol = [0] * len_p
    q_sol = [0] * len_q

    q0_known = get_digit(q_rev, 0, default=-1)
    p0_known = get_digit(p_rev, 0, default=-1)
    n0 = get_digit(n_rev, 0, default=0)

    if p0_known != -1:
        p0 = p0_known
        inv_p0 = modInverse(p0, 10)
        q0 = (n0 * inv_p0) % 10
        print(f"DEBUG: Init using p0={p0} -> Calculated q0={q0}")
    elif q0_known != -1:
        # Jika q0 diketahui
        q0 = q0_known
        inv_q0 = modInverse(q0, 10)
        p0 = (n0 * inv_q0) % 10
        print(f"DEBUG: Init using q0={q0} -> Calculated p0={p0}")
    else:
        print("[ERROR] Neither p0 nor q0 is known. Check leaks.")
        return

    p_sol[0] = p0
    q_sol[0] = q0
    carry = (p_sol[0] * q_sol[0]) // 10

    K = max(len_p, len_q)
    for k in range(1, K):
        known_sum = 0
        for i in range(1, k):
            known_sum += get_digit_zero(p_sol, i) * get_digit_zero(q_sol, k - i)
            
        target = (n_rev[k] - ((known_sum + carry) % 10)) % 10
        
        p_template_k = get_digit(p_rev, k, default=None)
        q_template_k = get_digit(q_rev, k, default=None)

        if (p_template_k == -1):
            q_k = q_template_k if q_template_k is not None else 0
            if q_k == -1: q_k = 0 # Safety
            
            rhs = (target - (p_sol[0] * (q_k % 10)) % 10) % 10
            inv_q0 = modInverse(q_sol[0], 10)
            p_k = (rhs * inv_q0) % 10
            
            if k < len_q: q_sol[k] = q_k
            if k < len_p: p_sol[k] = p_k
        else:
            # Solve for Q (assuming P known)
            p_k = p_template_k if p_template_k is not None else 0
            if p_k == -1: p_k = 0 # Safety
            
            rhs = (target - ((p_k % 10) * q_sol[0]) % 10) % 10
            inv_p0 = modInverse(p_sol[0], 10)
            q_k = (rhs * inv_p0) % 10
            
            if k < len_p: p_sol[k] = p_k
            if k < len_q: q_sol[k] = q_k

        carry = (known_sum + p_sol[0] * get_digit_zero(q_sol, k) + get_digit_zero(p_sol, k) * q_sol[0] + carry) // 10

    p_str = "".join(map(str, p_sol[::-1]))
    q_str = "".join(map(str, q_sol[::-1]))

    p = int(p_str)
    q = int(q_str)

    print("\n--- Verification ---")
    if n == p * q:
        print("[SUCCESS] p * q == n")
        try:
            phi = (p - 1) * (q - 1)
            d = pow(e, -1, phi)
            key = RSA.construct((n, e, d, p, q))
            cipher = PKCS1_OAEP.new(key)
            decrypted = cipher.decrypt(ct_bytes)
            print(f"\n[FLAG] >>> {decrypted.decode()} <<<")
        except Exception as ex:
            print("Decryption failed:", ex)
    else:
        print(f"[FAILURE] Diff: {n - (p*q)}")
        

if __name__ == "__main__":
    solve_challenge()