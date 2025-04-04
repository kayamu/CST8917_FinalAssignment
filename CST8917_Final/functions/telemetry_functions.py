import uuid
import datetime
import json
import logging
import azure.functions as func
from azure_services.cosmosdb_service import CosmosDBService
from azure_services.iot_hub_service import IoTHubService
from azure_services.blob_storage_service import BlobStorageService
from azure_services.notification_service import NotificationService
#from azure_services.communication_service import CommunicationService
from config.jwt_utils import decode_token, authenticate_user, get_azure_config

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
    
    # Parse the request body
    try:
        device_id = req.form.get("deviceId") # Get deviceId from form data
        values = req.form.get("values")  # Get values as a JSON string
        image = req.files.get("image")  # Get the uploaded image file

        # Parse values from JSON string to Python object
        if values:
            values = json.loads(values)  # Convert JSON string to Python object
            if not isinstance(values, list):  # Ensure values is a list
                values = [values]
    except Exception as e:
        logging.error(f"Invalid request body: {str(e)}")
        return func.HttpResponse("Invalid request body", status_code=400)
    
    # Validate required fields
    if not device_id or not values:
        logging.error(f"Missing required fields: deviceId={device_id}, values={values}")
        return func.HttpResponse(
            json.dumps({"message": "Missing required fields or invalid data"}), 
            status_code=400, 
            mimetype="application/json"
        )
    
    # Generate telemetry data structure
    telemetry_data = {
        "deviceId": device_id,
        "eventId": str(uuid.uuid4()),  # Generate a unique event ID
        "event_date": datetime.datetime.now(datetime.timezone.utc).isoformat(),  # Current system date in ISO format with timezone
        "values": values,  # List of key-value pairs
    }
    
    # CosmosDB: Find the user associated with the deviceId
    cosmos_service = CosmosDBService()
    logging.info(f"Searching for user with deviceId={device_id} in CosmosDB.")


    try:
        user = cosmos_service.find_document({"Devices.deviceId": device_id})
    except Exception as e:
        logging.exception(f"Error while querying CosmosDB for deviceId={device_id}: {str(e)}")

        return func.HttpResponse(
            json.dumps({"message": "Error while querying database"}), 
            status_code=500, 
            mimetype="application/json"
        )

    if not user:
        logging.error(f"Device with deviceId={device_id} not found in any user's Devices list.")
        return func.HttpResponse(
            json.dumps({"message": "Device not found in CosmosDB"}), 
            status_code=404, 
            mimetype="application/json"
        )

    logging.info(f"Device found in user: {user['email']}")

    # Find the specific device in the user's Devices list
    device = next((d for d in user["Devices"] if d["deviceId"] == device_id), None)
    if not device:
        logging.error(f"Device with deviceId={device_id} not found in user's Devices list.")
        return func.HttpResponse("Device not found in user's Devices list", status_code=404)
    
    # If an image is provided, upload it to Azure Blob Storage and analyze it
    fire_detection_result = "No image provided"
    if image:
        try:
            blob_service = BlobStorageService()
            file_extension = image.filename.split(".")[-1]  # Extract file extension
            event_date = telemetry_data["event_date"]  # Use event_date for the filename
            blob_filename = f"{event_date.replace(':', '').replace('-', '').replace('.', '')}_{device_id}.{file_extension}"
            blob_path = f"{user['_id']}/{blob_filename}"  # Use user_id for the directory
            image_url = blob_service.upload_image(image.read(), blob_path)  # Read image bytes and upload
            telemetry_data["image"] = image_url  # Add the image URL to telemetry data

            # Analyze the image for fire detection
            from azure_services.cognitive_serivce import analyze_image_for_fire
            fire_detection_result = analyze_image_for_fire(image_url)
            telemetry_data["fire_detection_result"] = fire_detection_result  # Add the result to telemetry data
        except Exception as e:
            logging.exception("Failed to upload image to Blob Storage or analyze it.")
            return func.HttpResponse(f"Failed to process image: {str(e)}", status_code=500)
    
    # Check conditions for telemetry values
    try:
        check_conditions(device_id, values)
    except Exception as e:
        logging.exception("Failed to check conditions for telemetry values.")
        return func.HttpResponse(f"Failed to check conditions: {str(e)}", status_code=500)
    
    # Update the telemetryData array for the device
    try:
        result = cosmos_service.update_document(
            {"_id": user["_id"], "Devices.deviceId": device_id},
            {"$push": {"Devices.$.telemetryData": telemetry_data}}
        )
        if result.modified_count == 0:
            logging.error(f"Failed to update telemetry data for deviceId={device_id}.")
            return func.HttpResponse(
                json.dumps({"message": "Failed to add telemetry data to the device"}), 
                status_code=400, 
                mimetype="application/json"
            )
    except Exception as e:
        logging.exception(f"Error while updating telemetry data for deviceId={device_id}: {str(e)}")
        return func.HttpResponse(f"Error while updating telemetry data: {str(e)}", status_code=500)
    
    # IoT Hub: Send telemetry data to the event topic
    try:
        iot_service = IoTHubService()
        iot_service.send_telemetry_to_event_hub(device_id, telemetry_data)
    except Exception as e:
        logging.exception("Failed to send telemetry data to IoT Hub.")
        return func.HttpResponse(f"Failed to send telemetry data to IoT Hub: {str(e)}", status_code=500)
    
    logging.info(f"Telemetry data successfully added for deviceId={device_id}.")
    return func.HttpResponse(
        json.dumps({
            "message": "Telemetry data added successfully",
            "fire_detection_result": fire_detection_result  # Include fire detection result in the response
        }), 
        status_code=201, 
        mimetype="application/json"
    )

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

def check_conditions(device_id: str, values: list):
    """
    Check telemetry values against conditions in the Conditions collection.
    """
    logging.info(f"Starting condition check for deviceId={device_id}.")
    cosmos_service = CosmosDBService()
    config = get_azure_config()
    collection_name = config["CONDITION_COLLECTION_NAME"]  # Read the Conditions collection name

    logging.debug(f"Using collection: {collection_name}")

    for value in values:
        logging.debug(f"Processing value: {value}")
        value_type = value.get("valueType")
        value_data = value.get("value")

        if not value_type or value_data is None:
            logging.warning(f"Skipping invalid value: {value}")
            continue

        logging.info(f"Checking conditions for valueType={value_type}, value={value_data}.")


        try:
            conditions = cosmos_service.find_documents(
                {"valueType": value_type, "$or": [{"deviceId": device_id}, {"deviceId": None}]}, collection_name
            )
            logging.debug(f"Found {len(conditions)} conditions for valueType={value_type}.")
        except Exception as e:
            logging.error(f"Error while querying conditions for valueType={value_type}: {str(e)}")
            continue

        if not conditions:
            logging.info(f"No conditions found for valueType={value_type}.")
            continue

        for condition in conditions:
            logging.debug(f"Evaluating condition: {condition}")
            min_value = condition.get("minValue")
            max_value = condition.get("maxValue")

            # Compare the value with the condition's min and max values
            if min_value is not None:
                logging.debug(f"Checking if value {value_data} < minValue {min_value}.")
                if value_data < min_value:
                    logging.warning(
                        f"Value {value_data} for {value_type} is below the minimum threshold ({min_value})."
                    )

            if max_value is not None:
                logging.debug(f"Checking if value {value_data} > maxValue {max_value}.")
                if value_data > max_value:
                    logging.warning(
                        f"Value {value_data} for {value_type} is above the maximum threshold ({max_value})."
                    )

    logging.info(f"Condition check completed for deviceId={device_id}.")


