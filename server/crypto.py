# === CRIPTOGRAFIA (SERVER) — DERIVAÇÃO E DECIFRAGEM DE MENSAGENS ===

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC  # KDF PBKDF2 para derivar chave e IV
from cryptography.hazmat.primitives.ciphers.aead import AESGCM    # AES no modo GCM (criptografia autenticada)
from cryptography.hazmat.primitives import hashes                 # Algoritmos de hash (SHA256)
from cryptography.hazmat.backends import default_backend          # Backend padrão para operações criptográficas


# Salt fixo usado para derivar a chave a partir do código TOTP
FIXED_SALT = b"3fa_crypto_salt"


# Deriva uma chave AES de 32 bytes (256 bits) a partir do código TOTP
def derive_key_from_totp_code(totp_code: str) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),     # Usa SHA-256 como função de hash interna
        length=32,                     # Tamanho da chave desejada (32 bytes)
        salt=FIXED_SALT,               # Salt fixo garante consistência entre cliente e servidor
        iterations=100_000,            # Número de iterações para resistência contra brute-force
        backend=default_backend()
    )
    return kdf.derive(totp_code.encode())  # Retorna a chave derivada do código TOTP (convertido para bytes)


# Decifra a mensagem cifrada usando AES-GCM com chave derivada do código TOTP e IV derivado com salt aleatório
def decrypt_message(totp_code: str, ciphertext: bytes, iv_salt: bytes) -> bytes:
    key = derive_key_from_totp_code(totp_code)  # Deriva a chave AES de 256 bits a partir do TOTP

    aesgcm = AESGCM(key)  # Inicializa o AES-GCM com a chave derivada

    # Deriva o IV de 12 bytes (nonce) usando PBKDF2 com o TOTP e o salt aleatório
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=12,                    # AES-GCM requer um nonce de 12 bytes
        salt=iv_salt,                # Salt enviado pelo cliente junto com a mensagem
        iterations=100_000,
        backend=default_backend()
    )
    iv = kdf.derive(totp_code.encode())  # IV derivado do TOTP com salt variável

    # Decifra a mensagem usando a chave e o IV derivados
    return aesgcm.decrypt(iv, ciphertext, None)  # Retorna o plaintext como bytes
