import logging
import requests
import time
import base64
import urllib.parse
import hmac
import hashlib
from config.azure_config import get_azure_config
from azure_services.CommunicationService import CommunicationService

class NotificationService:
    def __init__(self):
        config = get_azure_config()
        self.namespace = config["NOTIFICATION_HUB_NAMESPACE"]
        self.hub_name = config["NOTIFICATION_HUB_NAME"]
        self.connection_string = config["NOTIFICATION_HUB_CONNECTION_STRING"]

        # Yeni eklenen ayrıştırma kodu
        parts = dict(item.split('=', 1) for item in self.connection_string.split(';'))
        self.sas_key_name = parts['SharedAccessKeyName']
        self.sas_key_value = parts['SharedAccessKey']

        self.endpoint = f"https://{self.namespace}.servicebus.windows.net/{self.hub_name}/messages/?api-version=2015-01"

    def send_notification(self, message: str, device_id: str = None, values: list = None):
        try:
            payload = {
                "aps": {
                    "alert": message,
                    "sound": "default"
                },
                "deviceId": device_id,
                "message": message
            }

            sas_token = self._generate_sas_token()

            headers = {
                "Authorization": sas_token,
                "Content-Type": "application/json;charset=utf-8",
                "ServiceBusNotification-Format": "apple"
            }

            response = requests.post(self.endpoint, json=payload, headers=headers)

            if response.status_code == 201:
                logging.info("Notification sent successfully to Notification Hub.")
            else:
                logging.error(f"Failed to send notification. Status code: {response.status_code}, Response: {response.text}")
        except Exception as e:
            logging.error(f"Failed to send notification to Notification Hub: {str(e)}")

    def _generate_sas_token(self):
        target_uri = f"https://{self.namespace}.servicebus.windows.net/{self.hub_name}"
        encoded_uri = urllib.parse.quote(target_uri.lower(), safe='')
        expiry = str(self.get_expiry())
        to_sign = f"{encoded_uri}\n{expiry}"
        signature = urllib.parse.quote(self.sign_string(to_sign))

        sas_token = f'SharedAccessSignature sig={signature}&se={expiry}&skn={self.sas_key_name}&sr={encoded_uri}'
        return sas_token

    @staticmethod
    def get_expiry():
        # Token geçerlilik süresi 5 dakika olarak ayarlandı (300 saniye).
        return int(round(time.time() + 3000))

    @staticmethod
    def encode_base64(data):
        return base64.b64encode(data)

    def sign_string(self, to_sign):
        key = self.sas_key_value.encode('utf-8')
        to_sign = to_sign.encode('utf-8')
        signed_hmac_sha256 = hmac.HMAC(key, to_sign, hashlib.sha256)
        digest = signed_hmac_sha256.digest()
        encoded_digest = self.encode_base64(digest)
        return encoded_digest