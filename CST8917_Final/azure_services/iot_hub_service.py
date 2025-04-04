import logging
from azure.iot.hub import IoTHubRegistryManager
from config.azure_config import get_azure_config
from azure_services.eventtopic_service import forward_event


class IoTHubService:
    def __init__(self):
        """
        Initializes the IoTHubService instance with a registry manager.
        """
        config = get_azure_config()
        connection_string = config["IOTHUB_CONNECTION_STRING"]
        self.registry_manager = IoTHubRegistryManager(connection_string)

    def register_device_in_iot_hub(self, device_data: dict):
        """
        Registers a device in IoT Hub.
        """
        try:
            device_id = device_data.get("deviceId")
            if not device_id:
                raise ValueError("Device ID is required for IoT Hub registration.")
            
            # Check if the device already exists in IoT Hub
            try:
                existing_device = self.registry_manager.get_device(device_id)
                if existing_device:
                    logging.info(f"Device {device_id} already exists in IoT Hub.")
                    return {"message": f"Device {device_id} already exists in IoT Hub."}
            except Exception as e:
                # If the device does not exist, proceed to create it
                logging.info(f"Device {device_id} does not exist in IoT Hub. Proceeding to create it.")

            # Create a new device in IoT Hub
            device = self.registry_manager.create_device_with_sas(
                device_id=device_id,
                primary_key=None,
                secondary_key=None,
                status="enabled"
            )
            logging.info(f"Device {device_id} registered in IoT Hub successfully.")
            return {"message": f"Device {device_id} registered successfully in IoT Hub."}
        except Exception as e:
            logging.exception(f"Failed to register device in IoT Hub: {str(e)}")
            raise e

    def delete_device_from_iot_hub(self, device_id: str):
        """
        Deletes a device from IoT Hub.
        """
        try:
            if not device_id:
                raise ValueError("Device ID is required for IoT Hub deletion.")
            
            # Delete the device from IoT Hub
            self.registry_manager.delete_device(device_id)
            logging.info(f"Device {device_id} deleted from IoT Hub successfully.")
        except Exception as e:
            logging.exception(f"Failed to delete device from IoT Hub: {str(e)}")
            raise e

    def send_telemetry_to_event_hub(self, device_id: str, telemetry_data: dict):
        """
        Sends telemetry data to Azure Event Grid.
        """
        try:
            # Add device_id to telemetry data
            telemetry_data["device_id"] = device_id

            # Forward the telemetry data to Event Grid
            forward_event(telemetry_data)
            logging.info(f"Telemetry data for device {device_id} sent to Event Grid successfully.")
        except Exception as e:
            logging.exception(f"Failed to send telemetry data for device {device_id} to Event Grid: {str(e)}")
            raise e