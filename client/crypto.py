import os
import json
import pyotp
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

SECRETS_DB_PATH = "client/secrets.json"

# Pode ser armazenado em claro
FIXED_SALT = b"3fa_crypto_salt"


def load_secret(username):
    with open(SECRETS_DB_PATH, 'r') as f:
        secrets = json.load(f)
    return secrets.get(username)


def derive_key_from_totp(username):
    secret = load_secret(username)
    if not secret:
        raise ValueError("Secret TOTP não encontrado para o usuário.")

    totp = pyotp.TOTP(secret)
    current_code = totp.now().encode()

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=FIXED_SALT,
        iterations=100_000,
        backend=default_backend()
    )
    return kdf.derive(current_code)


def encrypt_message(username: str, plaintext: str):
    key = derive_key_from_totp(username)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
    return {
        "nonce": nonce.hex(),
        "ciphertext": ciphertext.hex()
    }


def decrypt_message(username: str, nonce_hex: str, ciphertext_hex: str):
    key = derive_key_from_totp(username)
    aesgcm = AESGCM(key)
    nonce = bytes.fromhex(nonce_hex)
    ciphertext = bytes.fromhex(ciphertext_hex)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode()


if __name__ == "__main__":
    user = input("Usuário: ")
    message = input("Mensagem a cifrar: ")
    encrypted = encrypt_message(user, message)
    print(f"Mensagem cifrada: {encrypted}")
    decrypted = decrypt_message(user, encrypted['nonce'], encrypted['ciphertext'])
    print(f"Mensagem decifrada: {decrypted}")
