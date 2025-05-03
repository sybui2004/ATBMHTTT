# RSA
import random
# Kiểm tra số nguyên tố
def is_prime(n):
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0 or n % 3 == 0:
        return False
    i = 5
    while i * i <= n:
        if n % i == 0 or n % (i + 2) == 0:
            return False
        i += 6
    return True

# Tạo số nguyên tố ngẫu nhiên trong một khoảng
def random_prime(start, end):
    while True:
        num = random.randint(start, end)
        if is_prime(num):
            return num
        
# Lũy thừa modulo 
def mod_pow(a, b, mod):
    result = 1
    a = a % mod
    while b:
        if b % 2 == 1:
            result = (result * a) % mod
        a = (a * a) % mod
        b //= 2
    return result

# Ước chung lớn nhất
def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

# Tìm nghịch đảo modular
def mod_inv(e, phi):
    for d in range(2, phi):
        if (e * d) % phi == 1:
            return d
    return -1

# Sinh khóa RSA
def rsa_keygen():
    p = random_prime(1000, 10000) 
    q = random_prime(1000, 10000)
    while q == p:
        q = random_prime(1000, 10000)
    n = p * q
    phi = (p - 1) * (q - 1)

    # Chọn e, điều kiện 1 < e < phi(n) và gcd(e, phi(n)) == 1
    e = 0
    for e in range(2, phi):
        if gcd(e, phi) == 1:
            break

    # Chọn d thỏa mãn e * d ≡ 1 (mod phi(n))
    d = mod_inv(e, phi)

    return e, d, n, p, q

# Mã hóa dùng khóa công khai (n, e)
def rsa_encrypt(m, e, n):
    return mod_pow(m, e, n)

# Giải mã dùng khóa bí mật (n, d)
def rsa_decrypt(c, d, n):
    return mod_pow(c, d, n)

if __name__ == "__main__":
    
    # Sinh khóa
    e, d, n, p, q = rsa_keygen()
    
    print(f"Prime p: {p}")
    print(f"Prime q: {q}")
    print(f"Public Key (n, e): ({n}, {e})")
    print(f"Private Key (n, d): ({n}, {d})")

    # Message
    M = 123
    print(f"Original Message: {M}")

    # Mã hóa message
    C = rsa_encrypt(M, e, n)
    print(f"Encrypted Message: {C}")

    # Giải mã message
    decrypted = rsa_decrypt(C, d, n)
    print(f"Decrypted Message: {decrypted}")