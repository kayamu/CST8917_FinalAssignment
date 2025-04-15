import logging
import json
from azure_services.CosmosdbService import CosmosDBService
from azure_services.IothubService import IoTHubService
from config.azure_config import get_azure_config
from azure_services.NotificationService import NotificationService
from azure_services.CommunicationService import CommunicationService
from datetime import datetime, timezone

class ServiceBusListener:
    def main(self, msg: str):
        """
        Azure Function triggered by a Service Bus Queue message.
        Processes telemetry data sent through the queue.
        """
        try:
            # msg is already a string, no need to call get_body()
            message_body = msg
            logging.info(f"Service Bus Queue message received")
            
            # Process the telemetry message
            self.process_telemetry_message(message_body)
        except Exception as e:
            logging.exception(f"Failed to process Service Bus Queue message: {str(e)}")      

    def process_telemetry_message(self, message_body: str):
        """
        Process a telemetry message from the Service Bus Queue and write it to the database.
        Also checks for condition violations and triggers notifications if needed.
        """
        try:
            telemetry_data = json.loads(message_body)
            device_id = telemetry_data.get("deviceId")
            if not device_id:
                logging.error("Invalid telemetry data: Missing deviceId.")
                return

            cosmos_service = CosmosDBService()

            # Find the user associated with the deviceId
            user = cosmos_service.find_document({"Devices.deviceId": device_id})
            if not user:
                logging.error(f"Device with deviceId={device_id} not found in any user's Devices list.")
                return

            # Find the specific device in the user's Devices list
            device = next((d for d in user["Devices"] if d["deviceId"] == device_id), None)
            if not device:
                logging.error(f"Device with deviceId={device_id} not found in user's Devices list.")
                return

            # Check conditions for telemetry values
            try:
                self.check_conditions(device_id, telemetry_data["values"])
            except Exception as e:
                logging.exception("Failed to check conditions for telemetry values.")

            # Update the telemetryData array for the device
            result = cosmos_service.update_document(
                {"_id": user["_id"], "Devices.deviceId": device_id},
                {"$push": {"Devices.$.telemetryData": telemetry_data}}
            )
            if result.modified_count == 0:
                logging.error(f"Failed to update telemetry data for deviceId={device_id}.")
                return

            # Forward telemetry data to IoT Hub Event Grid
            try:
                iot_service = IoTHubService()
                iot_service.send_telemetry_to_event_hub(device_id, telemetry_data)
            except Exception as e:
                logging.exception("Failed to send telemetry data to IoT Hub.")
                return

            logging.info(f"Telemetry data successfully processed for deviceId={device_id}.")
        except Exception as e:
            logging.exception(f"Failed to process telemetry message: {str(e)}")

    def check_conditions(self, device_id: str, values: list):
        """
        Check conditions for telemetry values and trigger alerts if thresholds are exceeded.
        
        Args:
            device_id: The device ID that sent the telemetry
            values: List of telemetry values to check against conditions
        """
        cosmos_service = CosmosDBService()
        config = get_azure_config()
        collection_name = config["CONDITION_COLLECTION_NAME"]

        for value in values:
            value_type = value.get("valueType")
            value_data = value.get("value")

            if not value_type or value_data is None:
                logging.warning(f"Skipping invalid value: {value}")
                continue

            try:
                # Convert value_data to an integer
                value_data = int(value_data)
            except ValueError:
                logging.warning(f"Value {value_data} is not a valid integer. Skipping.")
                continue

            try:
                # Query conditions for the given valueType
                conditions = cosmos_service.find_documents(
                    {"valueType": value_type}, collection_name
                )
            except Exception as e:
                logging.error(f"Error while querying conditions for valueType={value_type}: {str(e)}")
                continue

            if not conditions:
                continue

            for condition in conditions:
                scope = condition.get("scope", "general")
                condition_user_id = condition.get("userId")
                condition_device_id = condition.get("deviceId")

                user = cosmos_service.find_document({"Devices.deviceId": device_id})
                # Apply scope logic
                if scope == "user":
                    if not user or user.get("userId") != condition_user_id:
                        continue

                elif scope == "device":
                    # Ensure the condition's deviceId matches the telemetry data's deviceId
                    if condition_device_id != device_id:
                        continue

                # Compare the value with the condition's min and max values
                min_value = condition.get("minValue")
                max_value = condition.get("maxValue")

                if min_value is not None and value_data < min_value:
                    message = f"Value {value_data} for {value_type} is below the minimum threshold ({min_value})."
                    logging.warning(message)
                    self.notify_user(condition, message, user, device_id, values)

                if max_value is not None and value_data > max_value:
                    message = f"Value {value_data} for {value_type} is above the maximum threshold ({max_value})."
                    logging.warning(message)
                    self.notify_user(condition, message, user, device_id, values)

    def notify_user(self, condition: dict, message: str, user: dict = None, device_id: str = None, values: list = None):
        """
        Notify the user based on the specified notification methods in the condition.
        
        Args:
            condition: The condition that triggered the notification
            message: The notification message to send
            user: The user to notify
            device_id: The device ID related to the notification
            values: The telemetry values that triggered the notification
        """
        methods = condition.get("notificationMethods", ["Log"])
        notification_service = NotificationService()
        communication_service = CommunicationService()
        cosmos_service = CosmosDBService()
        config = get_azure_config()
        alert_collection_name = config["ALERT_COLLECTION_NAME"]

        for method in methods:
            if method == "Notification":
                logging.info(f"Sending notification: {message}")
            #    notification_service.send_notification(message, device_id, values)

            elif method == "Email":
                if user and "email" in user:
                    logging.info(f"Sending email to {user['email']}")
                    communication_service.send_email(
                        recipient_email=user["email"],
                        subject="Alert Notification",
                        body=message
                    )
                else:
                    logging.error("User email not found. Cannot send email notification.")

            elif method == "SMS":
                if user and "phoneNumber" in user:
                    logging.info(f"Sending SMS to {user['phoneNumber']}")
                else:
                    logging.error("User phone number not found. Cannot send SMS notification.")

            elif method == "Log":
                try:
                    # Create the alert document
                    alert_document = {
                        "deviceId": device_id,
                        "message": message,
                        "condition": condition,
                        "user_id": user.get("userId") if user else None,
                        "telemetry_data": values,
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    }

                    # Insert the alert into the specified collection
                    cosmos_service.insert_document(alert_document, alert_collection_name)
                    logging.info(f"Alert successfully logged to collection")
                except Exception as e:
                    logging.error(f"Failed to log alert to collection: {str(e)}")

            else:
                logging.error(f"Unknown notification method: {method}")

