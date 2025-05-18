from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

FIXED_SALT = b"3fa_crypto_salt"

def derive_key_from_totp_code(totp_code: str) -> bytes:
    """Deriva a chave da sessão a partir do código TOTP informado (verificado anteriormente)."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=FIXED_SALT,
        iterations=100_000,
        backend=default_backend()
    )
    return kdf.derive(totp_code.encode())

def decrypt_message(totp_secret: str, totp_code: str, ciphertext: bytes, nonce: bytes) -> bytes:
    """
    Decifra a mensagem usando AES-GCM com chave derivada do código TOTP.
    Presume que o código TOTP foi previamente validado.
    """
    key = derive_key_from_totp_code(totp_code)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)

# Nenhuma função de linha de comando é necessária aqui — uso interno do servidor
