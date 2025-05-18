import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

FIXED_SALT = b"3fa_crypto_salt"

def derive_key_from_totp_code(totp_code: str) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=FIXED_SALT,
        iterations=100_000,
        backend=default_backend()
    )
    return kdf.derive(totp_code.encode())

def encrypt_message(totp_code: str, plaintext: str):
    key = derive_key_from_totp_code(totp_code)
    aesgcm = AESGCM(key)
    iv_salt = os.urandom(8)  # Salt para derivar o IV com PBKDF2
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=12,
        salt=iv_salt,
        iterations=100_000,
        backend=default_backend()
    )
    iv = kdf.derive(totp_code.encode())

    ciphertext = aesgcm.encrypt(iv, plaintext.encode(), None)
    return {
        "iv_salt": iv_salt.hex(),
        "ciphertext": ciphertext.hex()
    }
