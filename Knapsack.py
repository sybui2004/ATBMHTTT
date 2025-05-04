from math import gcd

# Tìm nghịch đảo modulo
def mod_inv(a, m):
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None

# Hàm mã hóa
def encrypt(public_key, plaintext):
    ciphertext = []
    for block in plaintext:
        c = sum(int(bit) * pk for bit, pk in zip(block, public_key))
        ciphertext.append(c)
    return ciphertext

# Hàm giải mã
def decrypt(ciphertext, private_key, n, m):
    w = private_key
    n_inv = mod_inv(n, m)
    decrypted = []
    for c in ciphertext:
        c_ = (c * n_inv) % m
        bits = []
        for w_i in reversed(w):
            if w_i <= c_:
                bits.insert(0, '1')
                c_ -= w_i
            else:
                bits.insert(0, '0')
        decrypted.append(''.join(bits))
    return decrypted


# Dãy siêu tăng (khóa riêng tư)
w = [1, 2, 4, 10, 20, 40]

# Modulus và multiplier
m = 110  # > sum(w)
n = 31  # gcd(n, m) = 1

# Tạo khóa công khai
public_key = [(n * wi) % m for wi in w]

print("Public Key:", public_key)

# Bản rõ (6-bit mỗi block)
plaintext_blocks = ['100100', '111100', '101110']


# Mã hóa
ciphertext = encrypt(public_key, plaintext_blocks)
print("Ciphertext:", ciphertext)

# Giải mã
decrypted_blocks = decrypt(ciphertext, w, n, m)
print("Decrypted:", decrypted_blocks)
