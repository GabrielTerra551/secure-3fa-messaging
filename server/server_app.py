from flask import Flask, request, jsonify
import base64
import os
import json

from server.verify_auth import verify_all

from server.crypto import decrypt_message

app = Flask(__name__)

@app.route("/receive", methods=["POST"])
def receive_message():
    data = request.get_json()

    required_fields = required_fields = ["username", "password", "totp_code", "ciphertext", "iv_salt", "location"]
    if not all(field in data for field in required_fields):
        return jsonify({"error": "Missing fields"}), 400

    username = data["username"]
    password = data["password"]
    totp_code = data["totp_code"]
    location = data["location"]

    # Decode base64 inputs
    try:
        ciphertext = bytes.fromhex(data["ciphertext"])  # hex decoding
        iv_salt = bytes.fromhex(data["iv_salt"])  
    except Exception as e:
        return jsonify({"error": f"Invalid base64 encoding: {e}"}), 400

    # Autenticação 3FA
    try:
        secret = verify_all(username, password, totp_code, location)
        if not secret[0]:
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