import json
import base64
import requests

from utils.ipinfo_lookup import get_location
from getpass import getpass
from client import register, auth, crypto

SERVER_URL = "http://localhost:5000/receive"  # Altere conforme necessário

def menu():
    print("\n== Sistema de Autenticação 3FA ==")
    print("1. Registrar novo usuário")
    print("2. Autenticar e enviar mensagem")
    print("0. Sair")

def registrar_usuario():
    register.registrar()

def autenticar_e_enviar():
    print("\n--- Autenticação 3FA ---")
    username = input("Nome de usuário: ")
    password = getpass("Senha: ")

    totp_code = input("Código TOTP atual (App Authenticator): ")

    mensagem = input("Mensagem a ser enviada (texto plano): ").encode()

    try:
        # Derivação de chave e cifragem
        result = crypto.encrypt_message(totp_code, mensagem.decode())
        ciphertext = bytes.fromhex(result["ciphertext"])
        nonce = bytes.fromhex(result["nonce"])
        location = get_location()

        # Codificar binários para envio
        data = {
            "username": username,
            "password": password,
            "totp_code": totp_code,
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "nonce": base64.b64encode(nonce).decode(),
            "location": location,
        }

        response = requests.post(SERVER_URL, json=data)

        if response.status_code == 200:
            print("\n✅ Mensagem decifrada no servidor:")
            print(response.json()["message"])
        else:
            print("\n❌ Erro:")
            print(response.json())

    except Exception as e:
        print(f"\nErro ao enviar mensagem: {e}")

def main():
    while True:
        menu()
        opcao = input("Escolha uma opção: ")

        if opcao == "1":
            registrar_usuario()
        elif opcao == "2":
            autenticar_e_enviar()
        elif opcao == "0":
            break
        else:
            print("Opção inválida.")

if __name__ == "__main__":
    main()
