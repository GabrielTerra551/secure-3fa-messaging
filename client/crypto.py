import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# Pode ser armazenado em claro
FIXED_SALT = b"3fa_crypto_salt"

def derive_key_from_totp_code(totp_code: str) -> bytes:
    """Deriva uma chave de sessão a partir do código TOTP informado pelo usuário"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=FIXED_SALT,
        iterations=100_000,
        backend=default_backend()
    )
    return kdf.derive(totp_code.encode())


def encrypt_message(totp_code: str, plaintext: str):
    """Cifra uma mensagem usando AES-GCM com chave derivada do TOTP"""
    key = derive_key_from_totp_code(totp_code)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
    return {
        "nonce": nonce.hex(),
        "ciphertext": ciphertext.hex()
    }


def decrypt_message(totp_code: str, nonce_hex: str, ciphertext_hex: str):
    """Decifra uma mensagem usando AES-GCM com chave derivada do TOTP"""
    key = derive_key_from_totp_code(totp_code)
    aesgcm = AESGCM(key)
    nonce = bytes.fromhex(nonce_hex)
    ciphertext = bytes.fromhex(ciphertext_hex)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode()


if __name__ == "__main__":
    totp = input("Código TOTP atual: ")
    message = input("Mensagem a cifrar: ")

    encrypted = encrypt_message(totp, message)
    print(f"Mensagem cifrada: {encrypted}")

    decrypted = decrypt_message(totp, encrypted['nonce'], encrypted['ciphertext'])
    print(f"Mensagem decifrada: {decrypted}")
