import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # AES no modo GCM (autenticado)
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC  # KDF para chave e IV
from cryptography.hazmat.primitives import hashes  # Algoritmos de hash (SHA-256)
from cryptography.hazmat.backends import default_backend  # Backend padrão do sistema criptográfico


# Salt fixo usado para derivar a chave da mensagem com base no TOTP
FIXED_SALT = b"3fa_crypto_salt"


# Deriva uma chave de 256 bits (32 bytes) a partir do código TOTP usando PBKDF2
def derive_key_from_totp_code(totp_code: str) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),     # Algoritmo de hash usado no PBKDF2
        length=32,                     # Tamanho da chave desejada (32 bytes = 256 bits)
        salt=FIXED_SALT,               # Salt fixo para manter a derivação consistente
        iterations=100_000,            # Número de iterações (padrão seguro)
        backend=default_backend()
    )
    return kdf.derive(totp_code.encode())  # Retorna a chave derivada


# Cifra a mensagem com AES-GCM usando chave e IV derivados do código TOTP
def encrypt_message(totp_code: str, plaintext: str):
    # Deriva a chave principal da mensagem usando o código TOTP
    key = derive_key_from_totp_code(totp_code)

    # Inicializa o AES em modo GCM
    aesgcm = AESGCM(key)

    # Gera um salt aleatório de 8 bytes que será usado para derivar o IV (nonce)
    iv_salt = os.urandom(8)

    # Deriva o IV (12 bytes) a partir do código TOTP + iv_salt
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=12,                     # AES-GCM exige nonce de 12 bytes
        salt=iv_salt,
        iterations=100_000,
        backend=default_backend()
    )
    iv = kdf.derive(totp_code.encode())  # Deriva o IV com PBKDF2

    # Cifra a mensagem com AES-GCM usando a chave e o IV derivados
    ciphertext = aesgcm.encrypt(iv, plaintext.encode(), None)

    # Retorna o IV salt e a mensagem cifrada, ambos em hexadecimal
    return {
        "iv_salt": iv_salt.hex(),
        "ciphertext": ciphertext.hex()
    }

