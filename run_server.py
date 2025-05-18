from server import server_app

if __name__ == "__main__":
    print("🟢 Iniciando servidor Flask na porta 5000...")
    server_app.app.run(host="0.0.0.0", port=5000)
