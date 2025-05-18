import json
import pyotp
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

USER_DB_PATH = "server/user_db.json"

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

def verify_password(stored_hash_hex, password, salt_hex):
    try:
        derived_key = derive_password_key(password, salt_hex)
        return derived_key.hex() == stored_hash_hex
    except Exception:
        return False

def decrypt_secret(encrypted_dict, key):
    aesgcm = AESGCM(key)
    nonce = bytes.fromhex(encrypted_dict["nonce"])
    ciphertext = bytes.fromhex(encrypted_dict["ciphertext"])
    return aesgcm.decrypt(nonce, ciphertext, None).decode()

def verify_totp(totp_secret: str, code: str) -> bool:
    totp = pyotp.TOTP(totp_secret)
    return totp.verify(code)

def verify_all(username: str, password: str, totp_code: str):
    user = load_user(username)
    if not user:
        return False, "Usuário não encontrado"

    if not verify_password(user["password_hash"], password, user["salt"]):
        return False, "Senha incorreta"

    try:
        key = derive_password_key(password, user["salt"])
        totp_secret = decrypt_secret(user["totp_encrypted"], key)
    except Exception:
        return False, "Falha ao decifrar TOTP secret"

    if not verify_totp(totp_secret, totp_code):
        return False, "Código TOTP inválido"

    return True, "Autenticação válida"

if __name__ == "__main__":
    user = input("Usuário: ")
    pwd = input("Senha: ")
    code = input("Código TOTP: ")
    result, msg = verify_all(user, pwd, code)
    print(msg)