from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import base64

# Generate and save ECC private and public keys
def generate_and_save_keys():
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open('private_key.pem', 'wb') as f:
        f.write(private_pem)
    with open('public_key.pem', 'wb') as f:
        f.write(public_pem)

# Load ECC private and public keys
def load_keys():
    with open('private_key.pem', 'rb') as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
    with open('public_key.pem', 'rb') as f:
        public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())
    return private_key, public_key

# Generate a shared key from the private and public keys
def generate_shared_key(private_key, public_key):
    shared_key = private_key.exchange(ec.ECDH(), public_key)
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(shared_key)
    return key, salt

# Encryption function
def encrypt_data(data, private_key, public_key):
    key, salt = generate_shared_key(private_key, public_key)
    nonce = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(data) + encryptor.finalize()
    tag = encryptor.tag
    return base64.b64encode(salt + nonce + tag + encrypted).decode(), base64.b64encode(key).decode()

# Decryption function
def decrypt_data(encrypted_data, key):
    encrypted_data = base64.b64decode(encrypted_data)
    salt, nonce, tag, encrypted = encrypted_data[:16], encrypted_data[16:32], encrypted_data[32:48], encrypted_data[48:]
    key = base64.b64decode(key)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(encrypted) + decryptor.finalize()

# Generate keys if not exist
if not os.path.exists('private_key.pem') or not os.path.exists('public_key.pem'):
    generate_and_save_keys()

# Load keys
private_key, public_key = load_keys()

def main_menu():
    while True:
        print("\nMã hoá văn bản bằng thuật toán ECC")
        print("1. Encrypt")
        print("2. Decrypt")
        print("3. Thoát chương trình")
        choice = input("Lựa chọn của bạn: ").strip()

        if choice == '1':
            data = input("Nhập dòng chữ muốn mã hoá: ").encode()
            encrypted_data, key = encrypt_data(data, private_key, public_key)
            print("Đoạn chữ được mã hoá thành:", encrypted_data)
            print("Key:", key)

        elif choice == '2':
            encrypted_data = input("Nhập dòng chữ được mã khoá: ")
            key = input("Nhập key: ")
            try:
                decrypted_data = decrypt_data(encrypted_data, key)
                print("Đoạn mã ban đầu:", decrypted_data.decode())
            except Exception as e:
                print("Giải mã bị lỗi rồi bạn ơi, vui lòng nhập lại. Lỗi tên là: ", str(e))

        elif choice == '3':
            print("Cảm ơn đã sử dụng chương trình.")
            break

        else:
            print("Chọn sai rồi. Vui lòng chọn lại nha ^^.")

if __name__ == "__main__":
    main_menu()
