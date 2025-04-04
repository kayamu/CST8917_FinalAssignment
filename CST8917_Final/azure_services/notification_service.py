import json
import requests
import logging
import json

from config.azure_config import get_azure_config
from config.azure_config import get_azure_config
from config.sas_utils import generate_sas_token
from azure.communication.email import EmailClient
from azure.core.credentials import AzureKeyCredential
from config.azure_config import get_azure_config

class NotificationService:

    def send_user_notification(service_bus_message):
        try:
            # Parse the message from the queue
            message_body = json.loads(service_bus_message.get_body().decode("utf-8"))

            userId = message_body.get("userId")
            image_name = message_body.get("imageName")
            resized_url = message_body.get("resizedImageUrl")
            recipient_email = message_body.get("email")

            if not all([userId, image_name, resized_url, recipient_email]):
                logging.error("[Notification] Missing required message fields.")
                return

            # Azure Communication Service config
            config = get_azure_config()
            connection_string = config["COMMUNICATION_SERVICE_CONNECTION_STRING"]
            client = EmailClient.from_connection_string(connection_string)

            # Build the message
            message = {
                "senderAddress": "DoNotReply@7273f83d-9db5-4ca7-801d-1d9d967d1598.azurecomm.net",  # change to your verified sender
                "recipients": {
                    "to": [{"address": recipient_email}]
                },
                "content": {
                    "subject": "Your image has been resized!",
                    "plainText": f"Hi! Your image '{image_name}' has been resized.\nYou can view it here:\n{resized_url}",
                    "html": f"""
                    <html>
                        <body>
                            <h2>Hello!</h2>
                            <p>Your image <strong>{image_name}</strong> has been resized successfully.</p>
                            <p>View it here: <a href="{resized_url}">{resized_url}</a></p>
                        </body>
                    </html>
                    """
                }
            }

            # Send email
            poller = client.begin_send(message)
            result = poller.result()

            if hasattr(result, "message_id"):
                logging.info(f"[Notification] Email sent to {recipient_email}, messageId: {result.message_id}")
            else:
                logging.info(f"[Notification] Email sent to {recipient_email}, raw result: {result}")


        except Exception as ex:
            logging.exception(f"[Notification Error] {str(ex)}")

    def trigger_notification(user_id: str, message: str):
        config = get_azure_config()
        hub_namespace = "cst8922notificationhubns"
        hub_name = config["NOTIFICATION_HUB_NAME"]
        full_uri = f"https://{hub_namespace}.servicebus.windows.net/{hub_name}/messages/?api-version=2015-01"
        
        sas_token = generate_sas_token(
            uri=full_uri,
            key_name="DefaultFullSharedAccessSignature",
            key_value="Cw3HHhBKkropHFKKYuHiC3/OnkGQdTaJxT4kcAm57J8="
        )

        headers = {
            "Authorization": sas_token,
            "Content-Type": "application/json;charset=utf-8",
            "ServiceBusNotification-Format": "gcm",
            "ServiceBusNotification-Tags": "all"
        }

        payload = {
            "notification": {
                "title": "Health Alert",
                "body": message
            },
            "priority": "high"
        }

        logging.info(f"[trigger_notification] Sending payload to Notification Hub: {payload}")

        response = requests.post(full_uri, headers=headers, json=payload)
        response.raise_for_status()

        logging.info(f"[trigger_notification] Notification sent successfully: {response.status_code}")