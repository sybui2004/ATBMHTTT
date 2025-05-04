# Import thuật toán McEliece từ thư viện pypqc
from pqc.kem import mceliece348864 as kemalg

# Bước 1: Sinh cặp khóa công khai và khóa bí mật
# Cặp khóa này sẽ được sử dụng để mã hóa và giải mã
pk, sk = kemalg.keypair()

print("Khóa công khai (Public Key):", pk)
print("Khóa bí mật (Secret Key):", sk)

# Bước 2: Mã hóa (Encapsulation)
# Bob sử dụng khóa công khai (pk) để mã hóa thông điệp
# 'kem_ct' là bản mã (ciphertext), còn 'ss' là khóa chia sẻ (shared secret) tính trong quá trình mã hóa
ss, kem_ct = kemalg.encap(pk)

print("Ciphertext (Bản mã):", kem_ct)
print("Khóa chia sẻ (Shared Secret) đã mã hóa:", ss)

# Bước 3: Giải mã (Decapsulation)
# Alice sử dụng khóa bí mật (sk) để giải mã bản mã
# Kết quả là khóa chia sẻ đã giải mã, 'ss_result' sẽ được tính từ quá trình giải mã
ss_result = kemalg.decap(kem_ct, sk)

print("Khóa chia sẻ giải mã được (Decapsulated Shared Secret):", ss_result)

# Bước 4: Kiểm tra tính đúng đắn
# So sánh khóa chia sẻ ban đầu ('ss') và khóa chia sẻ đã giải mã ('ss_result')
# Nếu chúng bằng nhau, tức là mã hóa và giải mã thành công
if ss_result != ss:
    print("Không trùng khớp")
else:
    print("Trùng khớp")

