import ipinfo
import os


handler = ipinfo.getHandler()

def get_location(ip: str = None):
    details = handler.getDetails(ip)
    return details.country_name or "Unknown"
