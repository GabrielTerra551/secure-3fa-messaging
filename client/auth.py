import json
import pyotp
from getpass import getpass
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend

USER_DB_PATH = "../server/user_db.json"
SECRETS_DB_PATH = "client/secrets.json"


def load_user(username):
    with open(USER_DB_PATH, 'r') as f:
        db = json.load(f)
    return db.get(username)


def verify_password(stored_hash_hex, password, salt_hex):
    salt = bytes.fromhex(salt_hex)
    stored_hash = bytes.fromhex(stored_hash_hex)

    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1,
        backend=default_backend()
    )
    try:
        kdf.verify(password.encode(), stored_hash)
        return True
    except Exception:
        return False


def load_secret(username):
    with open(SECRETS_DB_PATH, 'r') as f:
        secrets = json.load(f)
    return secrets.get(username)


def authenticate():
    username = input("Nome do usuário: ")
    password = getpass("Senha: ")
    user = load_user(username)

    if not user:
        print("Usuário não encontrado.")
        return False

    if not verify_password(user["password_hash"], password, user["salt"]):
        print("Senha incorreta.")
        return False

    secret = load_secret(username)
    if not secret:
        print("Secret TOTP não encontrado.")
        return False

    totp = pyotp.TOTP(secret)
    code = input("Código TOTP: ")
    if not totp.verify(code):
        print("Código TOTP inválido.")
        return False

    print("Autenticação 3FA bem-sucedida!")
    return True


if __name__ == "__main__":
    authenticate()
