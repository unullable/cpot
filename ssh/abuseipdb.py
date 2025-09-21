import os
import requests
from urllib.parse import urlencode
from dotenv import load_dotenv

BASE = "https://api.abuseipdb.com/api/v2/report"

def load_key() -> str:
    load_dotenv()
    return os.getenv("API_KEY")


def report_abuse(ip: str, msg: str) -> int:
    headers = {
        "Key" : load_key(),
        "Accept" : "application/json",
        "Content-Type" : "application/x-www-form-urlencoded"
    }

    data = urlencode({
        "ip": ip,
        "categories": "15,19",
        "comment": msg
    })

    resp = requests.post(BASE, headers=headers, data=data)
    return resp.status_code
