import json
import logging
import datetime
import azure.functions as func
from config.jwt_utils import authenticate_user
from azure_services.cosmosdb_service import CosmosDBService
from azure_services.iot_hub_service import IoTHubService

def register_device(req: func.HttpRequest) -> func.HttpResponse:
    logging.info("Processing register_device request.")
    
    # Authenticate the user
    user_id = authenticate_user(req)
    if isinstance(user_id, func.HttpResponse):  # Check if authentication failed
        return user_id
    
    # Parse the request body
    try:
        req_body = req.get_json()
    except ValueError:
        return func.HttpResponse(
            json.dumps({"message": "Invalid JSON body"}), 
            status_code=400, 
            mimetype="application/json"
        )
    
    # Validate required fields
    device_id = req_body.get("deviceId")
    device_name = req_body.get("deviceName")
    sensor_type = req_body.get("sensorType")
    location = req_body.get("location", {})
    if not device_id or not device_name or not sensor_type or not location.get("name"):
        return func.HttpResponse(
            json.dumps({"message": "Missing required fields"}), 
            status_code=400, 
            mimetype="application/json"
        )
    
    # IoT Hub: Register the device
    try:
        iot_service = IoTHubService()
        result = iot_service.register_device_in_iot_hub(req_body)
        if "already exists" in result["message"]:
            return func.HttpResponse(
                json.dumps({"message": "Device already exists in IoT Hub"}), 
                status_code=409, 
                mimetype="application/json"
            )
    except Exception as e:
        logging.exception("Failed to register device in IoT Hub.")
        return func.HttpResponse(
            json.dumps({"message": f"Failed to register device in IoT Hub: {str(e)}"}), 
            status_code=500, 
            mimetype="application/json"
        )
    
    # CosmosDB: Add the device to the user's Devices array
    cosmos_service = CosmosDBService()
    user = cosmos_service.find_document({"_id": user_id})
    if not user:
        return func.HttpResponse(
            json.dumps({"message": "User not found"}), 
            status_code=404, 
            mimetype="application/json"
        )
    
    # Prepare the device object
    device_object = {
        "deviceId": device_id,
        "deviceName": device_name,
        "sensorType": sensor_type,
        "location": {
            "name": location.get("name"),
            "longitude": location.get("longitude", ""),
            "latitude": location.get("latitude", "")
        },
        "registrationDate": datetime.datetime.utcnow().isoformat(),  # Add registration date
        "telemetryData": []  # Initialize with an empty telemetryData array
    }

    # Add the device to the user's Devices array
    result = cosmos_service.update_document(
        {"_id": user_id},
        {"$push": {"Devices": device_object}}
    )
    
    return func.HttpResponse(
        json.dumps({"message": "Device registered successfully"}), 
        status_code=201, 
        mimetype="application/json"
    )

def get_devices(req: func.HttpRequest) -> func.HttpResponse:
    logging.info("Processing get_devices request.")
    
    # Authenticate the user
    user_id = authenticate_user(req)
    if isinstance(user_id, func.HttpResponse):  # Check if authentication failed
        return user_id
    
    # Fetch the user's devices from CosmosDB
    cosmos_service = CosmosDBService()
    user = cosmos_service.find_document({"_id": user_id})
    if not user:
        return func.HttpResponse(
            json.dumps({"message": "User not found"}), 
            status_code=404, 
            mimetype="application/json"
        )
    
    # Get the devices array from the user document
    devices = user.get("Devices", [])
    
    # Extract query parameters
    device_id = req.params.get("deviceId")
    device_name = req.params.get("deviceName")
    telemetry_date = req.params.get("telemetryDate")
    sensor_type = req.params.get("sensorType")
    value_type = req.params.get("valueType")
    value_min = req.params.get("valueMin")
    value_max = req.params.get("valueMax")
    
    # Filter devices based on query parameters
    filtered_devices = []
    for device in devices:
        if device_id and device.get("deviceId") != device_id:
            continue
        if device_name and device.get("deviceName") != device_name:
            continue
        
        # Filter telemetry data
        telemetry_data = device.get("telemetryData", [])
        matching_telemetry = []
        for telemetry in telemetry_data:
            if telemetry_date and telemetry.get("event_date") != telemetry_date:
                continue
            if sensor_type and not any(value.get("valueType") == sensor_type for value in telemetry.get("values", [])):
                continue
            if value_type or value_min or value_max:
                for value in telemetry.get("values", []):
                    if value_type and value.get("valueType") != value_type:
                        continue
                    if value_min and value.get("value") < float(value_min):
                        continue
                    if value_max and value.get("value") > float(value_max):
                        continue
                    matching_telemetry.append(telemetry)
                    break
            else:
                matching_telemetry.append(telemetry)
        
        if matching_telemetry:
            device["telemetryData"] = matching_telemetry
            filtered_devices.append(device)
        elif not telemetry_date and not sensor_type and not value_type and not value_min and not value_max:
            filtered_devices.append(device)
    
    # If a specific deviceId is provided, return only that device
    if device_id and not filtered_devices:
        return func.HttpResponse(
            json.dumps({"message": "Device not found"}), 
            status_code=404, 
            mimetype="application/json"
        )
    
    return func.HttpResponse(
        json.dumps(filtered_devices), 
        status_code=200, 
        mimetype="application/json"
    )

def update_device(req: func.HttpRequest) -> func.HttpResponse:
    logging.info("Processing update_device request.")
    
    # Authenticate the user
    user_id = authenticate_user(req)
    if isinstance(user_id, func.HttpResponse):  # Check if authentication failed
        return user_id
    
    # Parse the request body
    try:
        req_body = req.get_json()
    except ValueError:
        return func.HttpResponse(
            json.dumps({"message": "Invalid JSON body"}), 
            status_code=400, 
            mimetype="application/json"
        )
    
    # Validate required fields
    device_id = req_body.get("deviceId")
    update_data = req_body.get("update", {})
    if not device_id or not update_data:
        return func.HttpResponse(
            json.dumps({"message": "Missing required fields"}), 
            status_code=400, 
            mimetype="application/json"
        )
    
    # Fetch the user's devices from CosmosDB
    cosmos_service = CosmosDBService()
    user = cosmos_service.find_document({"_id": user_id})
    if not user:
        return func.HttpResponse(
            json.dumps({"message": "User not found"}), 
            status_code=404, 
            mimetype="application/json"
        )
    
    # Check if the device belongs to the user
    devices = user.get("Devices", [])
    device = next((d for d in devices if d["deviceId"] == device_id), None)
    if not device:
        return func.HttpResponse(
            json.dumps({"message": "Device not found"}), 
            status_code=404, 
            mimetype="application/json"
        )
    
    # Update the device in the user's Devices array
    result = cosmos_service.update_document(
        {"_id": user_id, "Devices.deviceId": device_id},
        {"$set": {f"Devices.$.{key}": value for key, value in update_data.items()}}
    )
    if result.modified_count == 0:
        return func.HttpResponse(
            json.dumps({"message": "Device not updated"}), 
            status_code=400, 
            mimetype="application/json"
        )
    
    return func.HttpResponse(
        json.dumps({"message": "Device updated successfully"}), 
        status_code=200, 
        mimetype="application/json"
    )

def delete_device(req: func.HttpRequest) -> func.HttpResponse:
    logging.info("Processing delete_device request.")
    
    # Authenticate the user
    user_id = authenticate_user(req)
    if isinstance(user_id, func.HttpResponse):  # Check if authentication failed
        return user_id
    
    # Parse the request body
    try:
        req_body = req.get_json()
    except ValueError:
        return func.HttpResponse(
            json.dumps({"message": "Invalid JSON body"}), 
            status_code=400, 
            mimetype="application/json"
        )
    
    # Validate required fields
    device_id = req_body.get("deviceId")
    if not device_id:
        return func.HttpResponse(
            json.dumps({"message": "Missing required fields"}), 
            status_code=400, 
            mimetype="application/json"
        )
    
    # Fetch the user's devices from CosmosDB
    cosmos_service = CosmosDBService()
    user = cosmos_service.find_document({"_id": user_id})
    if not user:
        return func.HttpResponse(
            json.dumps({"message": "User not found"}), 
            status_code=404, 
            mimetype="application/json"
        )
    
    # Check if the device belongs to the user
    devices = user.get("Devices", [])
    device = next((d for d in devices if d["deviceId"] == device_id), None)
    if not device:
        return func.HttpResponse(
            json.dumps({"message": "Device not found"}), 
            status_code=404, 
            mimetype="application/json"
        )
    
    # Delete the device from IoT Hub
    try:
        iot_service = IoTHubService()
        iot_service.delete_device_from_iot_hub(device_id)
    except Exception as e:
        logging.exception("Failed to delete device from IoT Hub.")
        return func.HttpResponse(
            json.dumps({"message": f"Failed to delete device from IoT Hub: {str(e)}"}), 
            status_code=500, 
            mimetype="application/json"
        )
    
    # Remove the device from the user's Devices array
    result = cosmos_service.update_document(
        {"_id": user_id},
        {"$pull": {"Devices": {"deviceId": device_id}}}
    )
    if result.modified_count == 0:
        return func.HttpResponse(
            json.dumps({"message": "Failed to remove device from user's Devices array"}), 
            status_code=400, 
            mimetype="application/json"
        )
    
    return func.HttpResponse(
        json.dumps({"message": "Device deleted successfully"}), 
        status_code=200, 
        mimetype="application/json"
    )

def main(req: func.HttpRequest) -> func.HttpResponse:
    """
    POST  -> register_device (cihaz kaydı)
    GET   -> get_devices
    PUT/PATCH -> update_device
    DELETE -> delete_device
    """
    method = req.method.upper()
    if method == "POST":
        return register_device(req)
    elif method == "GET":
        return get_devices(req)
    elif method in ["PUT", "PATCH"]:
        return update_device(req)
    elif method == "DELETE":
        return delete_device(req)
    else:
        return func.HttpResponse(
            json.dumps({"message": "Method not allowed"}), 
            status_code=405, 
            mimetype="application/json"
        )
