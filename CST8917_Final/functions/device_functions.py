import json
import logging
import datetime
import azure.functions as func
from config.jwt_utils import authenticate_user
from azure_services.cosmosdb_service import CosmosDBService
from azure_services.iot_hub_service import IoTHubService

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
        return delete_device_request (req)
    else:
        return func.HttpResponse(
            json.dumps({"message": "Method not allowed"}), 
            status_code=405, 
            mimetype="application/json"
        )

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
    device_id = str(req_body.get("deviceId"))
    device_name = req_body.get("deviceName")
    sensor_type = req_body.get("sensorType")
    location = req_body.get("location", {})
    telemetry_data = req_body.get("telemetryData", [])
    status_data = req_body.get("status", [])
    
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
        "telemetryData": telemetry_data,
        "status": status_data
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
    logging.info("Processing get_devices request with filter parameters.")
    
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
    
    # Get query parameters for filtering
    device_id = req.params.get("deviceId")
    device_name = req.params.get("deviceName")
    sensor_type = req.params.get("sensorType")
    location = req.params.get("location")
    
    # Apply filters if parameters are provided
    filtered_devices = devices
    
    # Filter by deviceId if provided
    if device_id:
        filtered_devices = [d for d in filtered_devices if d.get("deviceId") == device_id]
        if not filtered_devices:
            return func.HttpResponse(
                json.dumps({"message": f"No device found with ID: {device_id}"}), 
                status_code=404, 
                mimetype="application/json"
            )
        # Return single device if deviceId is specified
        return func.HttpResponse(
            json.dumps({"device": filtered_devices[0]}), 
            status_code=200, 
            mimetype="application/json"
        )
    
    # Apply additional filters if no specific device ID was requested
    if device_name:
        filtered_devices = [d for d in filtered_devices if d.get("deviceName", "").lower() == device_name.lower()]
    
    if sensor_type:
        filtered_devices = [d for d in filtered_devices if d.get("sensorType", "").lower() == sensor_type.lower()]
    
    if location:
        filtered_devices = [d for d in filtered_devices 
                           if d.get("location", {}).get("name", "").lower() == location.lower()]
    
    # Return filtered devices with additional metadata
    response_data = {
        "devices": filtered_devices,
        "count": len(filtered_devices),
        "userId": user_id,
        "filters": {
            "deviceName": device_name,
            "sensorType": sensor_type,
            "location": location
        },
        "timestamp": datetime.datetime.utcnow().isoformat()
    }
    
    return func.HttpResponse(
        json.dumps(response_data), 
        status_code=200, 
        mimetype="application/json"
    )

def update_device(req: func.HttpRequest) -> func.HttpResponse:
    logging.info("Processing update_device request.")
    
    # Authenticate the user
    user_id = authenticate_user(req)
    if isinstance(user_id, func.HttpResponse):  # Check if authentication failed
        return user_id
    
    # Get deviceId from query parameters or request body
    device_id = req.params.get("deviceId")
    
    # Parse the request body
    try:
        req_body = req.get_json()
        # If deviceId wasn't in query params, try to get it from body
        if not device_id:
            device_id = req_body.get("deviceId")
        
        # Use the body as update data, or get it from the update field if present
        update_data = req_body.get("update", req_body)
        # Remove deviceId from update data if it's there to prevent changing the ID
        if "deviceId" in update_data:
            del update_data["deviceId"]
        
    except ValueError:
        req_body = {}
        update_data = {}
    
    # Validate required fields
    if not device_id:
        return func.HttpResponse(
            json.dumps({"message": "Missing deviceId parameter"}), 
            status_code=400, 
            mimetype="application/json"
        )
    
    if not update_data:
        return func.HttpResponse(
            json.dumps({"message": "No update data provided"}), 
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
            json.dumps({"message": f"Device with ID '{device_id}' not found"}), 
            status_code=404, 
            mimetype="application/json"
        )
    
    # Update the device in the user's Devices array
    try:
        result = cosmos_service.update_document(
            {"_id": user_id, "Devices.deviceId": device_id},
            {"$set": {f"Devices.$.{key}": value for key, value in update_data.items()}}
        )
        
        if result.modified_count == 0:
            return func.HttpResponse(
                json.dumps({"message": "Device not updated - no changes detected"}), 
                status_code=400, 
                mimetype="application/json"
            )
        
        return func.HttpResponse(
            json.dumps({"message": "Device updated successfully"}), 
            status_code=200, 
            mimetype="application/json"
        )
    except Exception as e:
        logging.exception(f"Error updating device: {str(e)}")
        return func.HttpResponse(
            json.dumps({"message": f"Failed to update device: {str(e)}"}),
            status_code=500,
            mimetype="application/json"
        )

def delete_device_request(req: func.HttpRequest) -> func.HttpResponse:
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


