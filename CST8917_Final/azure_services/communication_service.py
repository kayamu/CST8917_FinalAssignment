import logging
from azure.communication.email import EmailClient
from config.azure_config import get_azure_config

class CommunicationService:
    def __init__(self):
        # Load Azure Communication Service configuration
        config = get_azure_config()
        self.connection_string = config["COMMUNICATION_SERVICE_CONNECTION_STRING"]
        self.sender_email = config["COMMUNICATION_SERVICE_SENDER_EMAIL"]
        self.email_client = EmailClient.from_connection_string(self.connection_string)

    def send_email(self, recipient_email: str, subject: str, body: str, html_body: str = None):
        """
        Sends an email using Azure Communication Services with optional HTML content.
        """
        try:
            # Validate recipient email
            if not recipient_email or "@" not in recipient_email:
                raise ValueError(f"Invalid recipient email address: {recipient_email}")

            # Build the email message
            message = {
                "content": {
                    "subject": subject,
                    "plainText": body,
                },
                "recipients": {
                    "to": [{"address": recipient_email}],
                },
                "senderAddress": self.sender_email,
            }

            # Add HTML content if provided
            if html_body:
                message["content"]["html"] = html_body

            # Send the email using begin_send
            poller = self.email_client.begin_send(message)
            result = poller.result()

            if hasattr(result, "message_id"):
                logging.info(f"Email sent successfully. Message ID: {result.message_id}")
            else:
                logging.info(f"Email sent successfully. Raw result: {result}")

            return result
        except Exception as e:
            logging.exception(f"Failed to send email to {recipient_email}: {str(e)}")
            raise