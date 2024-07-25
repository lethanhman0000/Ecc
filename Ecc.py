from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import base64

# Tạo và lưu khóa ECC riêng và công khai
def generate_and_save_keys():
    # Tạo khóa riêng ECC sử dụng đường cong SECP256R1
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    # Lấy khóa công khai tương ứng từ khóa riêng
    public_key = private_key.public_key()

    # Chuyển đổi khóa riêng thành định dạng PEM để lưu trữ
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Chuyển đổi khóa công khai thành định dạng PEM để lưu trữ
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Lưu khóa riêng và công khai vào các tệp
    with open('private_key.pem', 'wb') as f:
        f.write(private_pem)
    with open('public_key.pem', 'wb') as f:
        f.write(public_pem)

# Tải khóa ECC riêng và công khai từ các tệp
def load_keys():
    with open('private_key.pem', 'rb') as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
    with open('public_key.pem', 'rb') as f:
        public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())
    return private_key, public_key

# Tạo khóa chung từ khóa riêng và công khai
def generate_shared_key(private_key, public_key):
    # Trao đổi khóa ECC để tạo khóa chung
    shared_key = private_key.exchange(ec.ECDH(), public_key)
    # Tạo một giá trị salt ngẫu nhiên để tăng cường bảo mật
    salt = os.urandom(16)
    # Tạo hàm KDF (Key Derivation Function) để chuyển đổi khóa chung thành khóa AES
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    # Sinh khóa AES từ khóa chung
    key = kdf.derive(shared_key)
    return key, salt

# Hàm mã hóa dữ liệu
def encrypt_data(data, private_key, public_key):
    # Sinh khóa AES và giá trị salt
    key, salt = generate_shared_key(private_key, public_key)
    # Tạo nonce ngẫu nhiên cho chế độ mã hóa GCM
    nonce = os.urandom(16)
    # Tạo đối tượng Cipher với thuật toán AES và chế độ GCM
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    # Mã hóa dữ liệu
    encrypted = encryptor.update(data) + encryptor.finalize()
    # Lấy tag xác thực từ quá trình mã hóa
    tag = encryptor.tag
    # Trả về dữ liệu đã mã hóa, tag, và nonce dưới dạng base64
    return base64.b64encode(salt + nonce + tag + encrypted).decode(), base64.b64encode(key).decode()

# Hàm giải mã dữ liệu
def decrypt_data(encrypted_data, key):
    # Giải mã dữ liệu từ base64
    encrypted_data = base64.b64decode(encrypted_data)
    # Tách các thành phần của dữ liệu đã mã hóa
    salt, nonce, tag, encrypted = encrypted_data[:16], encrypted_data[16:32], encrypted_data[32:48], encrypted_data[48:]
    key = base64.b64decode(key)
    # Tạo đối tượng Cipher với thuật toán AES và chế độ GCM
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    # Giải mã dữ liệu
    return decryptor.update(encrypted) + decryptor.finalize()

# Tạo khóa nếu các tệp khóa chưa tồn tại
if not os.path.exists('private_key.pem') or not os.path.exists('public_key.pem'):
    generate_and_save_keys()

# Tải khóa từ các tệp
private_key, public_key = load_keys()

# Menu chính của chương trình
def main_menu():
    while True:
        print("\nChương trình mã hoá văn bản bằng thuật toán Ecc")
        print("1. Mã hoá")
        print("2. Giải mã")
        print("3. Thoát")
        choice = input("Lựa chọn của bạn: ").strip()

        if choice == '1':
            # Nhập dữ liệu cần mã hóa
            data = input("Nhập đoạn văn bản cần được mã hoá: ").encode()
            # Mã hóa dữ liệu và nhận kết quả mã hóa cùng khóa AES
            encrypted_data, key = encrypt_data(data, private_key, public_key)
            print("Đoạn văn bản đã được mã hoá:", encrypted_data)
            print("Key:", key)

        elif choice == '2':
            # Nhập dữ liệu đã mã hóa và khóa AES
            encrypted_data = input("Nhập đoạn văn bản đã được mã hoá: ")
            key = input("Nhập key: ")
            try:
                # Giải mã dữ liệu và in kết quả
                decrypted_data = decrypt_data(encrypted_data, key)
                print("Giải mã thành công, đoạn văn bản là:", decrypted_data.decode())
            except Exception as e:
                # Xử lý lỗi nếu giải mã không thành công
                print("Giải mã không thành công, nhập lại:", str(e))

        elif choice == '3':
            print("Cảm ơn đã sử dụng chương trình, ngày mới tốt lành ^^.")
            print("Code do Phan Thành Phát và Lê Thanh Mẫn phát triển!!!")
            print("Chân thành cảm ơn Phan Thành Phát đã góp sức vào đề tài này")
            break

        else:
            print("Bạn bấm sai gì rồi, vui lòng bấm lại !!!")

if __name__ == "__main__":
    main_menu()
