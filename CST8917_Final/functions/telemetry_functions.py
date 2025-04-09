import uuid
import datetime
import json
import logging
import azure.functions as func
from azure_services.cosmosdb_service import CosmosDBService
from azure_services.iot_hub_service import IoTHubService
from azure_services.blob_storage_service import BlobStorageService
from azure_services.notification_service import NotificationService
from azure_services.communication_service import CommunicationService
from config.jwt_utils import authenticate_user, get_azure_config

import base64  # Base64 encoding için gerekli

def main(req: func.HttpRequest) -> func.HttpResponse:
    """
    Bu ana fonksiyon gelen HTTP request methoduna göre ilgili telemetry fonksiyonunu çağırır.
    POST  -> post_telemetry (authorization gerektirmez)
    GET   -> get_telemetry (authorization gerektirir)
    DELETE -> delete_telemetry (authorization gerektirir)
    """
    method = req.method.upper()
    if method == "POST":
        return post_telemetry(req)
    elif method == "GET":
        return get_telemetry(req)
    elif method == "DELETE":
        return delete_telemetry(req)
    else:
        return func.HttpResponse("Method not allowed", status_code=405)

def post_telemetry(req: func.HttpRequest) -> func.HttpResponse:
    logging.info("Processing telemetry data request.")
    
    # Check content-type to determine how to process the request
    content_type = req.headers.get('Content-Type', '')
    
    try:
        # First check if deviceId is provided as a query parameter
        device_id_from_query = req.params.get("deviceId")
        
        if 'multipart/form-data' in content_type:
            # Process form data (existing functionality)
            try:
                device_id = req.form.get("deviceId") or device_id_from_query
                values = req.form.get("values")  # Get values as a JSON string
                event_date = datetime.datetime.now(datetime.timezone.utc).isoformat()
                image = req.files.get("image")  # Get the uploaded image file

                # Parse values from JSON string to Python object
                if values:
                    values_data = json.loads(values)  # Convert JSON string to Python object
                    
                    # Check if values is already a list of telemetry items with deviceId
                    if isinstance(values_data, list) and all(isinstance(item, dict) and "deviceId" in item for item in values_data):
                        # This is a list of complete telemetry items
                        # Process as JSON data with multiple items
                        logging.info("Detected multiple telemetry items in values field")
                        return process_multiple_telemetry(values_data)
                    
                    # Normal case - values is just sensor readings
                    if not isinstance(values_data, list):  # Ensure values is a list
                        values_data = [values_data]
                    
                    values = values_data
            except Exception as e:
                logging.error(f"Invalid form data: {str(e)}")
                return func.HttpResponse("Invalid form data", status_code=400)
                
            # Validate required fields - device_id can be empty if it's included in the values
            if not device_id and not (isinstance(values, list) and all("deviceId" in item for item in values)):
                logging.error(f"Missing required fields: deviceId={device_id}, values={values}")
                return func.HttpResponse(
                    json.dumps({"message": "Missing required fields or invalid data"}), 
                    status_code=400, 
                    mimetype="application/json"
                )
                
            # Process single telemetry item with possible image
            return process_single_telemetry(device_id, values, event_date, image)
            
        else:
            # Process as JSON data
            try:
                req_body = req.get_json()
            except ValueError:
                logging.error("Invalid JSON in request body")
                return func.HttpResponse(
                    json.dumps({"message": "Invalid JSON in request body"}),
                    status_code=400,
                    mimetype="application/json"
                )
            
            # Handle both single object and array formats
            items_to_process = []
            if isinstance(req_body, list):
                items_to_process = req_body
            else:
                items_to_process = [req_body]
            
            # Override deviceId with query parameter if provided
            if device_id_from_query:
                for item in items_to_process:
                    item["deviceId"] = device_id_from_query
            
            # Process all telemetry items
            return process_multiple_telemetry(items_to_process)
            
    except Exception as e:
        logging.exception(f"Error in post_telemetry: {str(e)}")
        return func.HttpResponse(
            json.dumps({"message": f"Error processing request: {str(e)}"}),
            status_code=500,
            mimetype="application/json"
        )

def process_single_telemetry(device_id, values, event_date, image=None):
    """Process a single telemetry item with possible image attachment"""
    # Check if values contains complete telemetry items with deviceId
    if isinstance(values, list) and all(isinstance(item, dict) and "deviceId" in item for item in values):
        # This is actually multiple telemetry items, redirect to the appropriate handler
        return process_multiple_telemetry(values)
    
    # Search for the deviceId across all users in the database
    cosmos_service = CosmosDBService()
    logging.info(f"Searching for deviceId={device_id} across all users in CosmosDB.")
    user = cosmos_service.find_document({"Devices.deviceId": device_id})

    if not user:
        logging.error(f"Device with deviceId={device_id} not found in any user.")
        return func.HttpResponse(
            json.dumps({"message": "Device not found"}), 
            status_code=404, 
            mimetype="application/json"
        )
   
    event_id = str(uuid.uuid4())  # Generate a unique event ID
    
    # Generate telemetry data structure
    telemetry_data = {
        "deviceId": device_id,
        "userId": user["_id"],
        "eventId": event_id,
        "event_date": event_date,
        "values": values,
    }

    # Send telemetry data to Service Bus Queue
    try:
        from azure_services.servicebus_service import ServiceBusService
        service_bus = ServiceBusService()
        azure_config = get_azure_config()
        queue_name = azure_config.get("SERVICE_BUS_QUEUE_NAME")
        service_bus.send_message(queue_name, json.dumps(telemetry_data))
        logging.info(f"Telemetry data sent to Service Bus Queue: {queue_name}")

        # Process the image if provided
        blob_filename = None
        if image:
            try:
                blob_filename = process_image(image, device_id, event_id, telemetry_data)
                logging.info(f"Image processed successfully: {blob_filename}")
            except Exception as e:
                logging.error(f"Failed to process the image: {str(e)}")
                return func.HttpResponse(
                    json.dumps({"message": "Failed to process the image"}), 
                    status_code=500, 
                    mimetype="application/json"
                )
    except Exception as e:
        logging.exception("Failed to send telemetry data to Service Bus Queue.")
        return func.HttpResponse(
            json.dumps({"message": f"Failed to send telemetry data to Service Bus Queue: {str(e)}"}), 
            status_code=500,
            mimetype="application/json"
        )
    
    response_data = {
        "message": "Telemetry data sent to Service Bus Queue successfully",
        "eventId": event_id
    }
    
    if blob_filename:
        response_data["imageUrl"] = blob_filename
        
    return func.HttpResponse(
        json.dumps(response_data), 
        status_code=202,  # 202 Accepted, because the data is queued for processing
        mimetype="application/json"
    )

def process_multiple_telemetry(items_to_process):
    """Process multiple telemetry items from JSON data"""
    processed_items = 0
    results = []
    
    for item in items_to_process:
        try:
            device_id = item.get("deviceId")
            values = item.get("values")
            event_date = datetime.datetime.now(datetime.timezone.utc).isoformat()
            
            # Validate required fields
            if not device_id or not values:
                logging.warning(f"Missing required fields in item: {item}")
                results.append({
                    "status": "error", 
                    "message": "Missing deviceId or values"
                })
                continue
            
            # Ensure values is a list
            if not isinstance(values, list):
                values = [values]
            
            # Search for the deviceId across all users in the database
            cosmos_service = CosmosDBService()
            logging.info(f"Searching for deviceId={device_id} across all users in CosmosDB.")
            user = cosmos_service.find_document({"Devices.deviceId": device_id})
            
            if not user:
                logging.error(f"Device with deviceId={device_id} not found in any user.")
                results.append({
                    "status": "error", 
                    "message": "Device not found", 
                    "deviceId": device_id
                })
                continue
            
            event_id = str(uuid.uuid4())  # Generate a unique event ID
            
            # Generate telemetry data structure
            telemetry_data = {
                "deviceId": device_id,
                "userId": user["_id"],
                "eventId": event_id,
                "event_date": event_date,
                "values": values,
            }
            
            # Send telemetry data to Service Bus Queue
            from azure_services.servicebus_service import ServiceBusService
            service_bus = ServiceBusService()
            azure_config = get_azure_config()
            queue_name = azure_config.get("SERVICE_BUS_QUEUE_NAME")
            service_bus.send_message(queue_name, json.dumps(telemetry_data))
            
            processed_items += 1
            results.append({
                "status": "success",
                "message": "Telemetry data sent to queue",
                "deviceId": device_id,
                "eventId": event_id
            })
            
            logging.info(f"Telemetry data sent to Service Bus Queue: {queue_name} for deviceId={device_id}")
        
        except Exception as e:
            logging.exception(f"Failed to process telemetry item: {str(e)}")
            results.append({
                "status": "error", 
                "message": str(e),
                "deviceId": item.get("deviceId", "unknown")
            })
    
    # Return appropriate response based on processing results
    if processed_items == 0:
        return func.HttpResponse(
            json.dumps({"message": "Failed to process all telemetry items", "details": results}),
            status_code=400,
            mimetype="application/json"
        )
    
    response = {
        "message": "Telemetry data sent to Service Bus Queue successfully",
        "processed": processed_items,
        "details": results
    }
    
    if len(items_to_process) > 1:
        response["message"] = f"Processed {processed_items} out of {len(items_to_process)} telemetry items"
    
    return func.HttpResponse(
        json.dumps(response),
        status_code=202,  # 202 Accepted
        mimetype="application/json"
    )

def process_image(image, device_id, event_id, telemetry_data):
    """
    Processes the uploaded image: uploads it to Blob Storage, generates a SAS token,
    analyzes it for fire detection, and updates the telemetry data with the results.

    Args:
        image: The uploaded image file.
        device_id: The ID of the device that uploaded the image.
        user_id: The ID of the user associated with the device.
        telemetry_data: The telemetry data dictionary to update.

    Returns:
        A tuple containing the image URL with SAS token and the fire detection result.
    """
    try:
        # Upload the image to Blob Storage
        blob_service = BlobStorageService()
        file_extension = image.filename.split(".")[-1]
        event_date = telemetry_data["event_date"]
        blob_filename = f"{event_date.replace(':', '').replace('-', '').replace('.', '')}_{event_id}_{device_id}.{file_extension}"
        blob_service.upload_image(image.read(), blob_filename)

        return blob_filename
    except Exception as e:
        logging.exception("Failed to process the image.")
        raise


def get_telemetry(req: func.HttpRequest) -> func.HttpResponse:
    logging.info("Processing get_telemetry request.")
    
    # Authenticate the user
    user_id = authenticate_user(req)
    if isinstance(user_id, func.HttpResponse):  # If authentication fails, return the error response
        return user_id
    
    # Get query parameters
    device_id = req.params.get("deviceId")
    event_id = req.params.get("eventId")
    sensor_type = req.params.get("sensorType")
    event_date = req.params.get("eventDate")


    # Retrieve the user's devices
    cosmos_service = CosmosDBService()
    user = cosmos_service.find_document({"_id": user_id})
    if not user:
        return func.HttpResponse(
            json.dumps({"message": "User not found"}), 
            status_code=404, 
            mimetype="application/json"
        )
    
    user_devices = user.get("Devices", [])
    if not user_devices:
        return func.HttpResponse("No devices found for the user", status_code=404)

    # Find the specified device
    device = next((d for d in user_devices if d["deviceId"] == device_id), None)
    if not device:
        return func.HttpResponse(
            json.dumps({"message": "Device not found"}), 
            status_code=404, 
            mimetype="application/json"
        )

    # Filter telemetry data
    telemetry_data = device.get("telemetryData", [])
    filtered_data = []

    for telemetry in telemetry_data:
        # Apply filters
        if event_id and telemetry.get("eventId") != event_id:
            continue
        if sensor_type:
            if not any(value.get("valueType") == sensor_type for value in telemetry.get("values", [])):
                continue
        if event_date and telemetry.get("event_date") != event_date:
            continue

        
        filtered_data.append(telemetry)

    # Return the filtered telemetry data
    return func.HttpResponse(
        json.dumps(filtered_data), 
        status_code=200, 
        mimetype="application/json"
    )

def delete_telemetry(req: func.HttpRequest) -> func.HttpResponse:
    logging.info("Processing delete_telemetry request.")
    
    # Kullanıcı kimliğini doğrula
    user_id = authenticate_user(req)
    if isinstance(user_id, func.HttpResponse):  # Eğer doğrulama başarısızsa, hata yanıtını döndür
        return user_id
    
    # İstek gövdesini al
    try:
        req_body = req.get_json()
    except ValueError:
        return func.HttpResponse("Invalid JSON body", status_code=400)
    
    # Gerekli alanları kontrol et
    event_id = req_body.get("eventId")
    if not event_id:
        return func.HttpResponse(
            json.dumps({"message": "Missing required fields"}), 
            status_code=400, 
            mimetype="application/json"
        )
    
    # Kullanıcının cihazlarını al
    cosmos_service = CosmosDBService()
    user = cosmos_service.find_document({"_id": user_id})
    if not user:
        return func.HttpResponse("User not found in CosmosDB", status_code=404)
    
    user_devices = user.get("Devices", [])
    if not user_devices:
        return func.HttpResponse("No devices found for the user", status_code=404)
    
    # Kullanıcının cihazlarındaki telemetri verilerini tarayarak eventId'yi bul ve sil
    for device in user_devices:
        telemetry_data = device.get("telemetryData", [])
        for telemetry in telemetry_data:
            if telemetry.get("eventId") == event_id:
                # Telemetri verisini sil
                result = cosmos_service.update_document(
                    {"_id": user["_id"], "Devices.deviceId": device["deviceId"]},
                    {"$pull": {"Devices.$.telemetryData": {"eventId": event_id}}}
                )
                if result.modified_count > 0:
                    return func.HttpResponse(
                        json.dumps({"message": "Telemetry data deleted successfully"}), 
                        status_code=200, 
                        mimetype="application/json"
                    )
                else:
                    return func.HttpResponse(
                        json.dumps({"message": "Failed to delete telemetry data"}), 
                        status_code=400, 
                        mimetype="application/json"
                    )
    
    return func.HttpResponse(
        json.dumps({"message": "Telemetry data not found"}), 
        status_code=404, 
        mimetype="application/json"
    )

