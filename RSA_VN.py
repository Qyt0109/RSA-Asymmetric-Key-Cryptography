import random
import math

# Hàm kiểm tra số nguyên tố
def is_prime(n):
    if n <= 1:
        return False
    for i in range(2, int(math.sqrt(n)) + 1):
        if n % i == 0:
            return False
    return True

# Hàm tính ước chung lớn nhất (GCD) dùng thuật toán Euclid
def gcd(a, b):
    if b == 0:            #(a, 0) thì dừng đệ quy, trả về a chính là ước chung lớn nhất
        return a
    return gcd(b, a % b)  # Nếu b khác 0 thì gọi lại hàm gcd() - Đệ quy
"""
VD: gcd(12, 8)
  = gcd(8, 12 % 8)
  = gcd(8, 4)
  = gcd(4, 8 % 4)
  = gcd(4, 0)
  = 4
=> Ước chung lớn nhất của 12 và 8 là 4
"""

# Hàm tìm nghịch đảo modulo sử dụng giải thuật Euclid mở rộng
def mod_inverse(a, m):
    # Kiểm tra a và m có phải 2 số nguyên tố cùng nhau (gcd(a, m) = 1)
    # Bỏ qua kiểm tra vì truyền vào e với phi(n) đã thoả mãn điều kiện

    # Khởi tạo giá trị
    m0 = m
    x0, x1 = 0, 1
    #print("Giá trị khởi tạo:")
    #print(f"a = {a}, m0 = {m}, x0 = 0, x1 = 1")
    if m == 1:
        return 0
    #print(f"m = {m} != 1, thực hiện vòng lặp:")
    while a > 1:
        #print(f"q = a // m = {a} // {m}")
        q = a // m
        #print(f"= {q}")

        #print(f"a, m = m, a % m = {m}, {a} % {m}")
        a, m = m, a % m
        #print(f"= {a}, {m}")

        #print(f"x0, x1 = x1 - q * x0, x0 = {x1} - {q} * {x0}, {x0}")
        x0, x1 = x1 - q * x0, x0
        #print(f"= {x0}, {x1}")
        #print("------------------------------------------------------")
    #print(f"Kết thúc vòng lặp")
    if x1 < 0:
        #print(f"x1 = {x1} < 0 nên cần cộng thêm với m0 = {m0}")
        x1 += m0
        #print(f"=> x1 = {x1}")
    #print(f"x1 = {x1} chính là nghịch đảo modulo cần tìm")
    return x1
"""
VD: mod_inverse(7, 26) - Tìm nghịch đảo modulo của 7 trong 26
    Nghĩa là tìm x sao cho 7 * x ≡ 1 (mod 26) hay (7 * x) % 26 = 1

    Giá trị khởi tạo:
    a = 7, m0 = 26, x0 = 0, x1 = 1
    m = 26 != 1, thực hiện vòng lặp:
    q = a // m = 7 // 26
    = 0
    a, m = m, a % m = 26, 7 % 26
    = 26, 7
    x0, x1 = x1 - q * x0, x0 = 1 - 0 * 0, 0
    = 1, 0
    ------------------------------------------------------
    q = a // m = 26 // 7
    = 3
    a, m = m, a % m = 7, 26 % 7
    = 7, 5
    x0, x1 = x1 - q * x0, x0 = 0 - 3 * 1, 1
    = -3, 1
    ------------------------------------------------------
    q = a // m = 7 // 5
    = 1
    a, m = m, a % m = 5, 7 % 5
    = 5, 2
    x0, x1 = x1 - q * x0, x0 = 1 - 1 * -3, -3
    = 4, -3
    ------------------------------------------------------
    q = a // m = 5 // 2
    = 2
    a, m = m, a % m = 2, 5 % 2
    = 2, 1
    x0, x1 = x1 - q * x0, x0 = -3 - 2 * 4, 4
    = -11, 4
    ------------------------------------------------------
    q = a // m = 2 // 1
    = 2
    a, m = m, a % m = 1, 2 % 1
    = 1, 0
    x0, x1 = x1 - q * x0, x0 = 4 - 2 * -11, -11
    = 26, -11
    ------------------------------------------------------
    Kết thúc vòng lặp
    x1 = -11 < 0 nên cần cộng thêm với m0 = 26
    => x1 = 15
    x1 = 15 chính là nghịch đảo modulo cần tìm
"""

# Hàm tạo khóa RSA
def generate_rsa_keys(min_range, max_range):
    # Chọn hai số nguyên tố p và q ngẫu nhiên trong khoảng giá trị từ min_range tới max_range
    p = random.randint(min_range, max_range)
    while not is_prime(p):
        p = random.randint(min_range, max_range)

    q = random.randint(min_range, max_range)
    while not is_prime(q):
        q = random.randint(min_range, max_range)

    # Tính n và phi(n) sau khi chọn được hai số nguyên tố p và q
    n = p * q
    phi_n = (p - 1) * (q - 1)

    # Chọn số nguyên e sao cho 1 < e < phi(n) và gcd(e, phi(n)) = 1 (e và phi(n) là hai số nguyên tố cùng nhau)
    e = random.randint(2, phi_n - 1)
    while gcd(e, phi_n) != 1:
        e = random.randint(2, phi_n - 1)

    # Tính nghịch đảo modulo d của e
    d = mod_inverse(e, phi_n)

    # Trả về khóa công khai và khóa bí mật
    public_key = (n, e)
    private_key = (p, q, d)
    return public_key, private_key

# Hàm mã hóa RSA
def rsa_encrypt(message, public_key):
    # Sử dụng khoá công khai - public key (n, e) để mã hoá bản rõ - message (M)
    n, e = public_key
    ciphertext = [pow(ord(m), e, n) for m in message]   # C = M^e mod n
    return ciphertext

# Hàm giải mã RSA
def rsa_decrypt(ciphertext, private_key):
    # Sử dụng khoá bí mật - private key (n, d) để giải mã bản mã - ciphertext (C)
    p, q, d = private_key
    n = p * q
    decrypted_message = [chr(pow(c, d, n)) for c in ciphertext] # M = C^d mod n
    return ''.join(decrypted_message)

# Sinh khoá
public_key, private_key = generate_rsa_keys(10, 100)
print("Khóa công khai (n, e):", public_key)
print("Khóa bí mật (p, q, d):", private_key)
print("--------------------------------------------")

# Mã hoá bản rõ thành bản mã
print("Mã hoá bản rõ sử dụng khoá công khai:", public_key)
message = input("Nhập bản rõ cần mã hóa: ")
message_as_number = [ord(m) for m in message]
print("Bản rõ dưới dạng số tương ứng trong bảng mã Unicode:", message_as_number)
ciphertext = rsa_encrypt(message, public_key)
print("Bản mã sau khi mã hoá RSA:", ciphertext)
print("--------------------------------------------")

# Giải mã bản mã thành bản rõ với khoá bí mật
print("Giải mã bản mã sử dụng khoá bí mật:", private_key)
decrypted_message = rsa_decrypt(ciphertext, private_key)
print("Bản rõ sau khi giải mã RSA:", decrypted_message)
if(decrypted_message == message):
  print("Giải mã THÀNH CÔNG! So sánh bản rõ sau giải mã và bản rõ ban đầu cho kết quả trùng khớp")
else:
  print("Giải mã THẤT BẠI! So sánh bản rõ sau giải mã và bản rõ ban đầu có sai khác")
print("--------------------------------------------")

# Cố tình phá mã bằng cách thử khoá bí mật khác
fake_private_key = (73, 23, 1195)
print("Cố tình phá mã bằng cách thử khoá bí mật khác:", fake_private_key)
decrypted_message = rsa_decrypt(ciphertext, fake_private_key)
print("Bản rõ sau khi giải mã RSA:", decrypted_message)
if(decrypted_message == message):
  print("Giải mã THÀNH CÔNG! So sánh bản rõ sau giải mã và bản rõ ban đầu cho kết quả trùng khớp")
else:
  print("Giải mã THẤT BẠI! So sánh bản rõ sau giải mã và bản rõ ban đầu có sai khác")