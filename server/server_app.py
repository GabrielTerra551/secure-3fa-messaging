from flask import Flask, request, jsonify
import base64

from server.verify_auth import verify_all

from server.crypto import decrypt_message

app = Flask(__name__)

@app.route("/receive", methods=["POST"])
def receive_message():
    data = request.get_json()

    required_fields = ["username", "password", "totp_code", "ciphertext", "nonce"]
    if not all(field in data for field in required_fields):
        return jsonify({"error": "Missing fields"}), 400

    username = data["username"]
    password = data["password"]
    totp_code = data["totp_code"]

    # Decode base64 inputs
    try:
        ciphertext = base64.b64decode(data["ciphertext"])
        nonce = base64.b64decode(data["nonce"])
    except Exception as e:
        return jsonify({"error": f"Invalid base64 encoding: {e}"}), 400

    # Autenticação 3FA
    try:
        secret = verify_all(username, password, totp_code)
    except Exception as e:
        return jsonify({"error": f"Authentication failed: {str(e)}"}), 403

    # Decifrar mensagem
    try:
        mensagem = decrypt_message(secret, totp_code, ciphertext, nonce)
        return jsonify({"message": mensagem.decode()}), 200
    except Exception as e:
        return jsonify({"error": f"Decryption failed: {str(e)}"}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
