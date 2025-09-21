import json
import requests
import sys

class Telegram:
    def __init__(self):
        self.bot_token = ""
        self.chat_id = ""
        self.message = ""
        self.load_config()
        self.url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"

    def send_notification(self, report: str):
        data = {
            "chat_id": self.chat_id,
            "text": f"⚠️ {report}"
        }
        try:
            response = requests.post(
                self.url,
                headers={"Content-Type": "application/json"},
                data=json.dumps(data)
            )
        except requests.RequestException as e:
            print(f"HTTP Exception: {e}")
            sys.exit(1)

    def load_config(self):
        try:
            with open('./config.json', 'r') as f:
                config = json.load(f)
            self.bot_token = str(config.get("bot_token", ""))
            self.chat_id = str(config.get("chat_id", ""))
        except Exception as e:
            print(f"Exception: {e}")
            sys.exit(1)
