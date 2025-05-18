import ipinfo

# Requer token gerado em https://ipinfo.io/signup
IPINFO_TOKEN = "SEU_TOKEN_AQUI"  # Substitua por seu token real

handler = ipinfo.getHandler(IPINFO_TOKEN)

def get_location_from_ip(ip_address=None):
    """
    Retorna cidade e país a partir do IP.
    Se nenhum IP for passado, usa o IP externo do cliente.
    """
    details = handler.getDetails(ip_address)
    return {
        "city": details.city,
        "country": details.country_name
    }

# Exemplo de uso:
if __name__ == "__main__":
    location = get_location_from_ip()
    print(f"Localização aproximada: {location}")
