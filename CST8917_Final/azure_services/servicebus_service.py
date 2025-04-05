import logging
import json
from azure.servicebus import ServiceBusClient, ServiceBusMessage
from config.azure_config import get_azure_config
from azure_services.cosmosdb_service import CosmosDBService

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

    def process_telemetry_message(self, message: ServiceBusMessage):
        """
        Process a telemetry message from the Service Bus Queue and write it to the database.
        """
        try:
            telemetry_data = json.loads(message.body)
            device_id = telemetry_data.get("deviceId")
            if not device_id:
                logging.error("Invalid telemetry data: Missing deviceId.")
                return

            # Write telemetry data to the database
            cosmos_service = CosmosDBService()
            result = cosmos_service.update_document(
                {"Devices.deviceId": device_id},
                {"$push": {"Devices.$.telemetryData": telemetry_data}}
            )
            if result.modified_count == 0:
                logging.error(f"Failed to update telemetry data for deviceId={device_id}.")
            else:
                logging.info(f"Telemetry data successfully written for deviceId={device_id}.")
        except Exception as e:
            logging.exception(f"Failed to process telemetry message: {str(e)}")

