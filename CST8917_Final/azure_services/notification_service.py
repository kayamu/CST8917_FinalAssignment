import logging
import requests
from config.azure_config import get_azure_config
from azure_services.communication_service import CommunicationService

class NotificationService:
    def __init__(self):
        config = get_azure_config()
        self.hub_name = config["NOTIFICATION_HUB_NAME"]
        self.connection_string = config["NOTIFICATION_HUB_CONNECTION_STRING"]
        self.endpoint = f"https://{self.hub_name}.servicebus.windows.net/{self.hub_name}/messages"
        self.communication_service = CommunicationService()

    def send_notification(self, message: str, device_id: str = None, values: list = None):
        """
        Send a notification to the Azure Notification Hub using REST API.
        """
        try:
            # Create the notification payload
            payload = {
                "message": message,
                "deviceId": device_id,
                "values": values
            }

            # Extract the SAS token from the connection string
            sas_token = self._generate_sas_token()

            # Send the notification
            headers = {
                "Authorization": sas_token,
                "Content-Type": "application/json",
                "ServiceBusNotification-Format": "template"
            }
            response = requests.post(self.endpoint, json=payload, headers=headers)

            if response.status_code == 201:
                logging.info("Notification sent successfully to Notification Hub.")
            else:
                logging.error(f"Failed to send notification. Status code: {response.status_code}, Response: {response.text}")
        except Exception as e:
            logging.error(f"Failed to send notification to Notification Hub: {str(e)}")

    def _generate_sas_token(self):
        """
        Generate a Shared Access Signature (SAS) token for Notification Hub.
        """
        import urllib.parse
        import hmac
        import hashlib
        import base64
        from datetime import datetime, timedelta

        # Parse the connection string
        parts = dict(item.split("=", 1) for item in self.connection_string.split(";"))
        key_name = parts["SharedAccessKeyName"]
        key_value = parts["SharedAccessKey"]
        uri = urllib.parse.quote_plus(self.endpoint)

        # Set expiration time for the token
        expiry = int((datetime.utcnow() + timedelta(hours=1)).timestamp())

        # Create the string to sign
        string_to_sign = f"{uri}\n{expiry}"
        signed_hmac_sha256 = hmac.new(
            base64.b64decode(key_value),
            string_to_sign.encode("utf-8"),
            hashlib.sha256
        )
        signature = base64.b64encode(signed_hmac_sha256.digest()).decode("utf-8")

        # Return the SAS token
        return f"SharedAccessSignature sr={uri}&sig={urllib.parse.quote_plus(signature)}&se={expiry}&skn={key_name}"

