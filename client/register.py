import os
import json
import pyotp
import ipinfo
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

USER_DB_PATH = "../server/user_db.json"

IPINFO_TOKEN = os.getenv("IPINFO_TOKEN")
handler = ipinfo.getHandler(IPINFO_TOKEN)

def get_location(ip: str = None):
    details = handler.getDetails(ip)
    return details.country_name or "Unknown"

def hash_password(password: str, salt: bytes) -> bytes:
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_secret(secret: str, key: bytes) -> dict:
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, secret.encode(), None)
    return {
        "nonce": nonce.hex(),
        "ciphertext": ct.hex()
    }

def save_user_to_db(user_record):
    if os.path.exists(USER_DB_PATH):
        with open(USER_DB_PATH, 'r') as f:
            db = json.load(f)
    else:
        db = {}

    db[user_record["username"]] = user_record

    with open(USER_DB_PATH, 'w') as f:
        json.dump(db, f, indent=4)

def registrar():
    username = input("Nome do usuário: ")
    password = input("Senha: ")
    phone = input("Número de telefone (opcional): ")

    print("Obtendo país via IP...")
    location = get_location()

    salt = os.urandom(16)
    password_hash = hash_password(password, salt)

    totp_secret = pyotp.random_base32()

    secret_encrypted = encrypt_secret(totp_secret, password_hash)

    user_record = {
        "username": username,
        "phone": phone,
        "location": location,
        "password_hash": password_hash.hex(),
        "salt": salt.hex(),
        "totp_encrypted": secret_encrypted
    }

    save_user_to_db(user_record)
    print("Usuário registrado com sucesso.")
    print(f"Secret TOTP (adicione no seu autenticador): {totp_secret}")

if __name__ == "__main__":
    registrar()
