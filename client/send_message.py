import json
import requests
from client import crypto

SERVER_URL = "http://localhost:5000/receive"  # Ajuste conforme necessário

def send_encrypted_message():
    print("=== Autenticação 3FA ===")

    username = input("Confirme o nome do usuário autenticado: ")
    message = input("Mensagem a ser enviada: ")

    print("Cifrando mensagem...")
    result = crypto.encrypt_message(username, message)

    payload = {
        "username": username,
        "iv_salt": result["iv_salt"],
        "ciphertext": result["ciphertext"]
    }

    print("Enviando para o servidor...")
    try:
        response = requests.post(SERVER_URL, json=payload)
        print(f"Resposta do servidor: {response.status_code} - {response.text}")
    except Exception as e:
        print(f"Erro ao enviar mensagem: {e}")
