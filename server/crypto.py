import json
import pyotp
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend

USER_DB_PATH = "server/user_db.json"
FIXED_SALT = b"3fa_crypto_salt"


def load_user(username):
    with open(USER_DB_PATH, 'r') as f:
        db = json.load(f)
    return db.get(username)

def derive_password_key(password: str, salt_hex: str) -> bytes:
    salt = bytes.fromhex(salt_hex)
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def decrypt_secret(encrypted_dict, key):
    aesgcm = AESGCM(key)
    nonce = bytes.fromhex(encrypted_dict["nonce"])
    ciphertext = bytes.fromhex(encrypted_dict["ciphertext"])
    return aesgcm.decrypt(nonce, ciphertext, None).decode()

def derive_key_from_totp(totp_secret: str) -> bytes:
    totp = pyotp.TOTP(totp_secret)
    current_code = totp.now().encode()

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=FIXED_SALT,
        iterations=100_000,
        backend=default_backend()
    )
    return kdf.derive(current_code)

def decrypt_message(username: str, password: str, nonce_hex: str, ciphertext_hex: str) -> str:
    user = load_user(username)
    if not user:
        raise ValueError("Usuário não encontrado")

    password_key = derive_password_key(password, user["salt"])
    totp_secret = decrypt_secret(user["totp_encrypted"], password_key)
    key = derive_key_from_totp(totp_secret)

    aesgcm = AESGCM(key)
    nonce = bytes.fromhex(nonce_hex)
    ciphertext = bytes.fromhex(ciphertext_hex)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode()


if __name__ == "__main__":
    user = input("Usuário: ")
    pwd = input("Senha: ")
    nonce = input("Nonce (hex): ")
    ciphertext = input("Mensagem cifrada (hex): ")
    message = decrypt_message(user, pwd, nonce, ciphertext)
    print(f"Mensagem decifrada: {message}")
