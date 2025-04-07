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
from config.jwt_utils import decode_token, authenticate_user, get_azure_config
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
    
    # Parse the request body
    try:
        device_id = req.form.get("deviceId")  # Get deviceId from form data
        values = req.form.get("values")  # Get values as a JSON string
        event_date = datetime.datetime.now(datetime.timezone.utc).isoformat()  # Fixed: Removed trailing comma
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

    # Generate telemetry data structure
    telemetry_data = {
        "deviceId": device_id,
        "userId": user["_id"],  # User ID from the database
        "eventId": str(uuid.uuid4()),  # Generate a unique event ID
        "event_date": event_date,  # Correctly formatted event_date
        "values": values,  # List of key-value pairs
    }

    # Proceed with processing the telemetry data
    fire_detection_result = "No image provided"
    if image:
        try:
            image_url, fire_detection_result = handle_fire_detection_and_notification(image, device_id, user, telemetry_data)
        except Exception as e:
            logging.exception("Failed to upload image to Blob Storage or analyze it.")
            return func.HttpResponse(f"Failed to process image: {str(e)}", status_code=500)

    # Send telemetry data to Service Bus Queue
    try:
        from azure_services.servicebus_service import ServiceBusService
        service_bus = ServiceBusService()
        azure_config = get_azure_config()
        queue_name = azure_config.get("SERVICE_BUS_QUEUE_NAME")
        service_bus.send_message(queue_name, json.dumps(telemetry_data))
        logging.info(f"Telemetry data sent to Service Bus Queue: {queue_name}")
    except Exception as e:
        logging.exception("Failed to send telemetry data to Service Bus Queue.")
        return func.HttpResponse(f"Failed to send telemetry data to Service Bus Queue: {str(e)}", status_code=500)
    
    return func.HttpResponse(
        json.dumps({"message": "Telemetry data sent to Service Bus Queue successfully"}), 
        status_code=202,  # 202 Accepted, because the data is queued for processing
        mimetype="application/json"
    )

def handle_fire_detection_and_notification(image, device_id, user, telemetry_data):
    """
    Handles fire detection from the uploaded image and sends an email notification if fire is detected.

    Args:
        image: The uploaded image file.
        device_id: The ID of the device that uploaded the image.
        user: The user document from the database.
        telemetry_data: The telemetry data dictionary to update.

    Returns:
        A tuple containing the image URL with SAS token and the fire detection result.
    """
    try:
        # Process the image
        image_url_with_sas, fire_detection_result = process_image(image, device_id, user["_id"], telemetry_data)

        # Check if fire is detected
        if "Fire detected" in fire_detection_result:
            try:
                communication_service = CommunicationService()
                user_email = user.get("email")
                if user_email:
                    subject = "Fire Alert Detected!"
                    plain_text_body = (
                        f"A fire has been detected in the image uploaded from device {device_id}.\n\n"
                        f"Details:\n- Event Date: {telemetry_data['event_date']}\n"
                        f"- Fire Detection Result: {fire_detection_result}\n"
                        f"- Image URL: {image_url_with_sas}"
                    )
                    html_body = f"""
                    <html>
                        <body>
                            <h2>Fire Alert Detected!</h2>
                            <p>A fire has been detected in the image uploaded from device <strong>{device_id}</strong>.</p>
                            <p><strong>Details:</strong></p>
                            <ul>
                                <li><strong>Event Date:</strong> {telemetry_data['event_date']}</li>
                                <li><strong>Fire Detection Result:</strong> {fire_detection_result}</li>
                                <li><strong>Image URL:</strong> <a href="{image_url_with_sas}">{image_url_with_sas}</a></li>
                            </ul>
                        </body>
                    </html>
                    """

                    # Send the email
                    communication_service.send_email(
                        recipient_email=user_email,
                        subject=subject,
                        body=plain_text_body,
                        html_body=html_body
                    )
                    logging.info(f"Fire alert email sent to {user_email}.")
            except Exception as e:
                logging.exception("Failed to send fire alert email.")
        return image_url_with_sas, fire_detection_result
    except Exception as e:
        logging.exception("Failed to process image or send notification.")
        raise


def process_image(image, device_id, user_id, telemetry_data):
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
        blob_filename = f"{event_date.replace(':', '').replace('-', '').replace('.', '')}_{device_id}.{file_extension}"
        blob_path = f"{user_id}/{blob_filename}"
        blob_service.upload_image(image.read(), blob_path)

        # Generate a SAS token for the image
        image_url_with_sas = blob_service.generate_sas_url(blob_path)
        telemetry_data["image"] = image_url_with_sas

        # Analyze the image for fire detection
        from azure_services.cognitive_serivce import analyze_image_for_fire
        fire_detection_result = analyze_image_for_fire(image_url_with_sas)
        telemetry_data["fire_detection_result"] = fire_detection_result

        logging.info(f"Image processed successfully. Fire detection result: {fire_detection_result}")
        return image_url_with_sas, fire_detection_result
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

