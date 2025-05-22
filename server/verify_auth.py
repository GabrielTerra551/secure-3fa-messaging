import json                          # Para ler o arquivo de usuários JSON
import pyotp                         # Biblioteca para geração/validação de TOTP
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt  # Derivação segura da senha
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # Decifração autenticada com AES-GCM
from cryptography.hazmat.backends import default_backend


USER_DB_PATH = "server/user_db.json"

def load_user(username):
    with open(USER_DB_PATH, 'r') as f:
        db = json.load(f)
    return db.get(username)

# Deriva a chave da senha usando Scrypt e o salt salvo
def derive_password_key(password: str, salt_hex: str) -> bytes:
    salt = bytes.fromhex(salt_hex)
    kdf = Scrypt(
        salt=salt,
        length=32,  # Gera chave de 32 bytes (256 bits)
        n=2**14,
        r=8,
        p=1,
        backend=default_backend()
    )
    return kdf.derive(password.encode())


# Decifra o secret TOTP armazenado com AES-GCM
def decrypt_secret(encrypted_dict, key):
    aesgcm = AESGCM(key)
    nonce = bytes.fromhex(encrypted_dict["nonce"])         # Nonce salvo na etapa de registro
    ciphertext = bytes.fromhex(encrypted_dict["ciphertext"])
    return aesgcm.decrypt(nonce, ciphertext, None).decode()  # Retorna o secret TOTP original


# Valida se o código TOTP fornecido bate com o código gerado para o secret
def verify_totp(totp_secret: str, code: str) -> bool:
    totp = pyotp.TOTP(totp_secret)
    expected = totp.now()
    print(f"[DEBUG] Código esperado: {expected} — Código recebido: {code}")
    return totp.verify(code, valid_window=1)  # Tolerância de 1 intervalo (30s)


# Verifica todos os fatores de autenticação: senha, TOTP e localização
def verify_all(username: str, password: str, totp_code: str, location: str):
    user = load_user(username)
    if not user:
        return False, "Usuário não encontrado"

    # Verifica se a localização atual do cliente corresponde ao país registrado
    if user["location"] != location:
        print(f"{user['location']} != {location}")
        return False, "Localização não corresponde ao registro"

    try:
        # Deriva a chave da senha fornecida
        key = derive_password_key(password, user["salt"])
        
        # Compara o hash da senha fornecida com o armazenado
        if key.hex() != user["password_hash"]:
            return False, "Senha incorreta"

        # Decifra o secret TOTP usando a chave da senha
        totp_secret = decrypt_secret(user["totp_encrypted"], key)
        print(f"[DEBUG] Secret decifrado: {totp_secret}")

    except Exception as e:
        return False, f"Falha ao decifrar TOTP secret: {e}"


    if not verify_totp(totp_secret, totp_code):
        return False, "Código TOTP inválido"

    return True, "Autenticação válida"
