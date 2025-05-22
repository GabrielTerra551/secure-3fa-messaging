# === FLASK APP - CAMADA SERVIDOR ===
from flask import Flask, request, jsonify         # Framework web + parsing de JSON
import base64                                      # Usado inicialmente para codificação (não usado neste script final)
import os
import json

# Importa a função de verificação 3FA
from server.verify_auth import verify_all

# Importa a função que decifra mensagens com AES-GCM
from server.crypto import decrypt_message

# Cria a instância do aplicativo Flask
app = Flask(__name__)


@app.route("/receive", methods=["POST"])
def receive_message():
    data = request.get_json()  # Extrai o corpo da requisição JSON

    # Verifica se todos os campos obrigatórios estão presentes
    required_fields = ["username", "password", "totp_code", "ciphertext", "iv_salt", "location"]
    if not all(field in data for field in required_fields):
        return jsonify({"error": "Missing fields"}), 400


    username = data["username"]
    password = data["password"]
    totp_code = data["totp_code"]
    location = data["location"]

    # Decode base64 inputs
    try:
        ciphertext = bytes.fromhex(data["ciphertext"])   # Conversão segura da mensagem cifrada
        iv_salt = bytes.fromhex(data["iv_salt"])         # Salt usado para derivar o IV
    except Exception as e:
        return jsonify({"error": f"Invalid base64 encoding: {e}"}), 400


    # Autenticação 3FA
    try:
        secret = verify_all(username, password, totp_code, location)
        if not secret[0]:  # Retorno do tipo (True, msg) ou (False, erro)
            return jsonify({"error":"Authentication failed: " + secret[1]}), 403
    except Exception as e:
        return jsonify({"error": f"Authentication failed: {str(e)}"}), 403

    # Decifrar mensagem
    try:
        mensagem = decrypt_message(totp_code, ciphertext, iv_salt)
        return jsonify({"message": mensagem.decode()}), 200
    except Exception as e:
        return jsonify({"error": f"Decryption failed: {str(e)}"}), 500

USER_DB_PATH = os.path.join(os.path.dirname(__file__), "user_db.json")

@app.route("/register", methods=["POST"])
def register_user():
    data = request.get_json()

    required_fields = ["username", "phone", "location", "password_hash", "salt", "totp_encrypted"]
    if not all(field in data for field in required_fields):
        return jsonify({"error": "Missing registration fields"}), 400

    # Carregar ou criar banco de dados
    if os.path.exists(USER_DB_PATH):
        with open(USER_DB_PATH, "r") as f:
            db = json.load(f)
    else:
        db = {}

    username = data["username"]
    db[username] = data

    with open(USER_DB_PATH, "w") as f:
        json.dump(db, f, indent=4)

    return jsonify({"message": "Usuário registrado com sucesso"}), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)