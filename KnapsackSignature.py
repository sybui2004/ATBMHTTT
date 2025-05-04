import hashlib

# Hàm băm SHA-256 sang nhị phân dài 256 bit
def hash_message(message):
    digest = hashlib.sha256(message.encode()).hexdigest()  # Băm message thành hex
    binary = bin(int(digest, 16))[2:]  # Hex sang bin
    return binary.zfill(256)  # Đủ 256 bit

# Tìm nghịch đảo modulo của a modulo m
def mod_inv(a, m):
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None 

# Tạo chữ ký bằng khóa riêng w, nhân với các bit hash = 1
def sign(message, w, n, m):
    binary_hash = hash_message(message)[:len(w)]  # Lấy số bit tương ứng với độ dài khóa riêng
    signature = 0
    for bit, wi in zip(binary_hash, w):
        if bit == '1':
            signature += wi  # Cộng các phần tử tương ứng nếu bit là 1
    return signature 

# Xác minh chữ ký bằng cách so sánh hai lần mã hóa với khóa công khai
def verify(message, signature, public_key, n, m, w):
    h = hash_message(message)[:len(w)]  # Lấy dãy bit của hash

    # Dùng chữ ký (giá trị tổng) để khôi phục lại dãy bit
    bits = []
    s = signature
    for wi in reversed(w):  # Duyệt ngược vì w là dãy siêu tăng
        if wi <= s:
            bits.insert(0, '1')
            s -= wi
        else:
            bits.insert(0, '0')
    bits_str = ''.join(bits)  # Dãy bit tạo ra từ chữ ký

    # Mã hóa lại bits từ chữ ký với khóa công khai
    c_verify = sum(int(bit) * pk for bit, pk in zip(bits_str, public_key))

    # Mã hóa dãy bit hash thực tế để so sánh
    h_enc = sum(int(bit) * pk for bit, pk in zip(h, public_key))

    return c_verify == h_enc  # So sánh xem hai mã hóa có trùng nhau không

message = "Hello"

# Khóa riêng (dãy siêu tăng)
w = [1, 2, 4, 10, 20, 40]

# Tham số modulus và multiplier (thoả mãn: gcd(n, m) = 1 và m > sum(w))
m = 110
n = 31

# Khóa công khai được tạo từ w
public_key = [(n * wi) % m for wi in w]

# Ký thông điệp
signature = sign(message, w, n, m)
print("Signature:", signature)

# Xác minh chữ ký
result = verify(message, signature, public_key, n, m, w)
print("Valid signature:", result)
