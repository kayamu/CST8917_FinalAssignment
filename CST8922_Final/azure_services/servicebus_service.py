import logging
import json
import os  # Dosya uzantısını almak için gerekli
from azure.servicebus import ServiceBusClient, ServiceBusMessage
from config.azure_config import get_azure_config
from azure_services.cosmosdb_service import CosmosDBService
from azure_services.blob_storage_service import BlobStorageService
from azure_services.iot_hub_service import IoTHubService

class ServiceBusService:
    def __init__(self):
        # Load Azure Service Bus configuration
        config = get_azure_config()
        self.connection_string = config["SERVICE_BUS_CONNECTION_STRING"]
        self.service_bus_client = ServiceBusClient.from_connection_string(self.connection_string)

    def main(self, msg: ServiceBusMessage):
        """
        Azure Function triggered by a Service Bus Queue message.
        """
        try:
            # Get the message body
            message_body = msg.get_body().decode('utf-8')
            logging.info(f"Service Bus Queue message received: {message_body}")
            
            # Process the telemetry message
            self.process_telemetry_message(ServiceBusMessage(message_body))
        except Exception as e:
            logging.exception(f"Failed to process Service Bus Queue message: {str(e)}")        
    
    def send_message(self, queue_name: str, message_body: str):
        """
        Send a message to the specified Service Bus Queue.
        """
        try:
            with self.service_bus_client:
                sender = self.service_bus_client.get_queue_sender(queue_name=queue_name)
                with sender:
                    message = ServiceBusMessage(message_body)
                    sender.send_messages(message)
                    logging.info(f"Message sent to queue '{queue_name}': {message_body}")
        except Exception as e:
            logging.exception(f"Failed to send message to queue '{queue_name}': {str(e)}")
            raise

    def receive_messages(self, queue_name: str, max_message_count: int = 1):
        """
        Receive messages from the specified Service Bus Queue.
        """
        try:
            with self.service_bus_client:
                receiver = self.service_bus_client.get_queue_receiver(queue_name=queue_name)
                with receiver:
                    messages = receiver.receive_messages(max_message_count=max_message_count)
                    for message in messages:
                        logging.info(f"Message received from queue '{queue_name}': {message.body}")
                        receiver.complete_message(message)  # Mark the message as processed
                    return [message.body for message in messages]
        except Exception as e:
            logging.exception(f"Failed to receive messages from queue '{queue_name}': {str(e)}")
            raise


 