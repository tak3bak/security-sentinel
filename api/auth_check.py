import requests

def check_license(token):
    GATEWAY_URL = "http://127.0.0.1:5000/v1/verify-token"
    HEADERS = {"X-API-Key": "nmdk_secure_key_12345"}
    try:
        response = requests.get(f"{GATEWAY_URL}?token={token}", headers=HEADERS, timeout=5)
        return response.json().get("valid", False)
    except:
        return False
