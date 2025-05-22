# === REGISTRO DE USUÁRIO COM COMENTÁRIOS EXPLICATIVOS ===

import os
import pyotp
import ipinfo
import requests

# Importa a função de derivação de chave Scrypt
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

# Importa o AES no modo GCM (criptografia autenticada)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Backend necessário para o funcionamento dos KDFs e algoritmos de cifra
from cryptography.hazmat.backends import default_backend


# Caminho (relativo) para o arquivo JSON de usuários do servidor (referência interna apenas)
USER_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "server", "user_db.json")


# Inicializa o handler da API do IPInfo (sem token → funcional, mas com limitação de requisições por IP)
handler = ipinfo.getHandler()

# Função auxiliar que retorna o país a partir do IP atual (ou IP manual, se fornecido)
def get_location(ip: str = None):
    details = handler.getDetails(ip)
    return details.country_name or "Unknown"


# Deriva o hash da senha usando Scrypt (resistente a brute force e ataques com hardware dedicado)
def hash_password(password: str, salt: bytes) -> bytes:
    kdf = Scrypt(
        salt=salt,
        length=32,      # 32 bytes = 256 bits (chave de criptografia forte)
        n=2**14,        # Parâmetros seguros de custo computacional
        r=8,
        p=1,
        backend=default_backend()
    )
    return kdf.derive(password.encode())  # Aplica o KDF na senha e retorna a chave derivada


# Cifra o secret TOTP com AES-GCM (modo autenticado)
def encrypt_secret(secret: str, key: bytes) -> dict:
    aesgcm = AESGCM(key)                  # Inicializa o AES com a chave derivada
    nonce = os.urandom(12)                # Gera IV aleatório de 12 bytes (recomendado para GCM)
    ct = aesgcm.encrypt(nonce, secret.encode(), None)  # Cifra o secret
    return {
        "nonce": nonce.hex(),             # Armazena nonce e ciphertext como strings hex
        "ciphertext": ct.hex()
    }


# Envia os dados do usuário para o servidor via POST para o endpoint /register
def enviar_para_servidor(user_record):
    response = requests.post("http://localhost:5000/register", json=user_record)
    if response.status_code == 200:
        print("✅ Registro enviado com sucesso ao servidor.")
    else:
        print(f"❌ Erro ao registrar no servidor: {response.text}")


# Função principal de cadastro
def registrar():
    # Coleta os dados do usuário
    username = input("Nome do usuário: ")
    password = input("Senha: ")
    phone = input("Número de telefone (opcional): ")

    print("Obtendo país via IP...")
    location = get_location()  # Detecta a localização automaticamente

    salt = os.urandom(16)  # Gera salt aleatório (16 bytes)
    password_hash = hash_password(password, salt)  # Deriva o hash da senha com Scrypt

    totp_secret = pyotp.random_base32()  # Gera um secret TOTP válido (base32, padrão de apps como Google Authenticator)

    # Cifra o secret com a chave derivada da senha
    secret_encrypted = encrypt_secret(totp_secret, password_hash)

    # Prepara o dicionário com os dados do usuário a serem enviados
    user_record = {
        "username": username,
        "phone": phone,
        "location": location,
        "password_hash": password_hash.hex(),  # Hexadecimal para transmissão
        "salt": salt.hex(),                    # Salt pode ser armazenado em claro (conforme enunciado)
        "totp_encrypted": secret_encrypted     # Contém o nonce e o ciphertext do secret TOTP
    }

    # Envia os dados ao servidor
    enviar_para_servidor(user_record)

    # Exibe o secret TOTP para que o usuário possa cadastrar no app autenticador
    print("Usuário registrado com sucesso.")
    print(f"Secret TOTP (adicione no seu autenticador): {totp_secret}")