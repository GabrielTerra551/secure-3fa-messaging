import pyotp
import qrcode

def generate_qr_code(username: str, secret: str, issuer: str = "3FA-System"):
    """
    Gera um QR Code compatível com Google Authenticator.
    """
    otp_uri = pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer)
    qr = qrcode.make(otp_uri)
    filename = f"{username}_totp_qrcode.png"
    qr.save(filename)
    print(f"QR Code salvo como: {filename}")

# Exemplo de uso:
if __name__ == "__main__":
    example_secret = pyotp.random_base32()
    generate_qr_code("usuario_demo", example_secret)
