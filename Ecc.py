from tinyec import registry
from Crypto.Cipher import AES
import hashlib, secrets, binascii

# Hàm mã hóa tin nhắn bằng AES-GCM
def encrypt_AES_GCM(msg, secretKey):
    # Tạo đối tượng AES mới với chế độ GCM
    aesCipher = AES.new(secretKey, AES.MODE_GCM)
    # Mã hóa tin nhắn và tạo tag xác thực
    ciphertext, authTag = aesCipher.encrypt_and_digest(msg)
    # Trả về dữ liệu mã hóa, nonce, và tag xác thực
    return (ciphertext, aesCipher.nonce, authTag)

# Hàm giải mã tin nhắn bằng AES-GCM
def decrypt_AES_GCM(ciphertext, nonce, authTag, secretKey):
    # Tạo đối tượng AES mới với chế độ GCM và nonce
    aesCipher = AES.new(secretKey, AES.MODE_GCM, nonce=nonce)
    # Giải mã dữ liệu và xác thực tag
    plaintext = aesCipher.decrypt_and_verify(ciphertext, authTag)
    # Trả về tin nhắn gốc
    return plaintext

# Chuyển đổi điểm ECC thành khóa 256-bit
def ecc_point_to_256_bit_key(point):
    # Băm (hash) tọa độ x của điểm ECC
    sha = hashlib.sha256(int.to_bytes(point.x, 32, 'big'))
    # Băm (hash) tọa độ y của điểm ECC
    sha.update(int.to_bytes(point.y, 32, 'big'))
    # Trả về khóa bí mật 256-bit
    return sha.digest()

# Lấy đường cong ECC từ thư viện
curve = registry.get_curve('brainpoolP256r1')

# Mã hóa tin nhắn bằng ECC và AES-GCM
def encrypt_ECC(msg, pubKey):
    # Tạo khóa riêng ngẫu nhiên
    ciphertextPrivKey = secrets.randbelow(curve.field.n)
    # Tính toán khóa chia sẻ từ khóa riêng và khóa công cộng
    sharedECCKey = ciphertextPrivKey * pubKey
    # Chuyển đổi điểm ECC thành khóa bí mật
    secretKey = ecc_point_to_256_bit_key(sharedECCKey)
    # Mã hóa tin nhắn với khóa bí mật
    ciphertext, nonce, authTag = encrypt_AES_GCM(msg, secretKey)
    # Tính toán khóa công cộng của dữ liệu mã hóa
    ciphertextPubKey = ciphertextPrivKey * curve.g
    # Trả về dữ liệu mã hóa, nonce, tag xác thực và khóa công cộng của dữ liệu mã hóa
    return (ciphertext, nonce, authTag, ciphertextPubKey)

# Giải mã tin nhắn mã hóa bằng ECC và AES-GCM
def decrypt_ECC(encryptedMsg, privKey):
    # Tách các thành phần của dữ liệu mã hóa
    (ciphertext, nonce, authTag, ciphertextPubKey) = encryptedMsg
    # Tính toán khóa chia sẻ từ khóa riêng và khóa công cộng của dữ liệu mã hóa
    sharedECCKey = privKey * ciphertextPubKey
    # Chuyển đổi điểm ECC thành khóa bí mật
    secretKey = ecc_point_to_256_bit_key(sharedECCKey)
    # Giải mã tin nhắn với khóa bí mật
    plaintext = decrypt_AES_GCM(ciphertext, nonce, authTag, secretKey)
    # Trả về tin nhắn gốc
    return plaintext

# Nhận dữ liệu đầu vào từ người dùng
msg = input("Enter the message to be encrypted: ").encode('utf-8')
print("Original message:", msg)

# Tạo cặp khóa ECC
privKey = secrets.randbelow(curve.field.n)  # Khóa riêng
pubKey = privKey * curve.g  # Khóa công cộng

# Mã hóa tin nhắn
encryptedMsg = encrypt_ECC(msg, pubKey)
encryptedMsgObj = {
    'ciphertext': binascii.hexlify(encryptedMsg[0]).decode('utf-8'),  # Dữ liệu mã hóa
    'nonce': binascii.hexlify(encryptedMsg[1]).decode('utf-8'),  # Nonce của AES-GCM
    'authTag': binascii.hexlify(encryptedMsg[2]).decode('utf-8'),  # Tag xác thực của AES-GCM
    'ciphertextPubKey': hex(encryptedMsg[3].x) + hex(encryptedMsg[3].y % 2)[2:]  # Khóa công cộng của dữ liệu mã hóa
}
print("Encrypted message:", encryptedMsgObj)

# Giải mã tin nhắn
decryptedMsg = decrypt_ECC(encryptedMsg, privKey)
print("Decrypted message:", decryptedMsg.decode('utf-8'))
#ciphertext là dữ liệu đã mã hóa.
#nonce là giá trị độc nhất để đảm bảo mã hóa không bị lặp lại
#authTag là tag chứng thực để kiểm tra tính toàn vẹn của dữ liệu.
#ciphertextPubKey là khóa công cộng được sử dụng để tính toán khóa chia sẻ trong quá trình giải mã.
