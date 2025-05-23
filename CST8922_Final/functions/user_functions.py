import json
import logging
import uuid
import azure.functions as func
from config.jwt_utils import create_token, authenticate_user
from config.password_utils import hash_password, verify_password
from azure_services.CosmosdbService import CosmosDBService


def main(req: func.HttpRequest) -> func.HttpResponse:
    method = req.method.upper()
    if method == "LOGIN":
        return login_user(req)
    elif method == "POST":
        return create_user(req)
    elif method == "GET":
        return get_user(req)
    elif method == "PUT":
        return update_user_put(req)
    elif method == "PATCH":
        return update_password(req)
    elif method == "DELETE":
        return delete_user(req)

    else:
        return func.HttpResponse("Method not allowed", status_code=405)

def create_user(req: func.HttpRequest, user_type: str = "user") -> func.HttpResponse:
    logging.info(f"Processing create_user request with userType={user_type}.")
    try:
        req_body = req.get_json()
    except ValueError:
        return func.HttpResponse("Invalid JSON body", status_code=400)
    
    # Extract required fields from the request body
    username = req_body.get("username")
    name = req_body.get("name")
    surname = req_body.get("surname")
    address = req_body.get("address")  # Optional address field
    phone = req_body.get("phone")  # Optional phone field
    email = req_body.get("email")
    emergency_contact = req_body.get("emergencyContact")  # Optional emergency contact field
    password = req_body.get("password")
    devices = req_body.get("Devices", [])  # Optional devices field

    missing_fields = []
    if not username:
        missing_fields.append("username")
    if not name:
        missing_fields.append("name")
    if not surname:
        missing_fields.append("surname")
    if not email:
        missing_fields.append("email")
    if not password:
        missing_fields.append("password")
    
    if missing_fields:
        return func.HttpResponse(
            json.dumps({"message": f"Missing required fields: {', '.join(missing_fields)}"}), 
            status_code=400, 
            mimetype="application/json"
        )


    # Check for unique username and email
    cosmos_service = CosmosDBService()
    existing_user = cosmos_service.find_document({"$or": [{"username": username}, {"email": email}]})
    if existing_user:
        conflict_field = "username" if existing_user.get("username") == username else "email"
        return func.HttpResponse(
            json.dumps({"message": f"{conflict_field.capitalize()} already exists"}), 
            status_code=409, 
            mimetype="application/json"
        )
    
    # Hash the provided password
    hashed_pw = hash_password(password)
    # Generate a unique userId using uuid (ignoring any provided userId)
    user_id = str(uuid.uuid4())
    # Generate a token for the newly created user
    token = create_token(user_id)


    # Prepare the user document according to the specified structure.
    user_doc = {
        "_id": user_id,            # ShardKey (userId) generated as a UUID
        "userId": user_id,
        "username": username,
        "name": name,
        "surname": surname,
        "address": address,        # Optional address field
        "phone": phone,            # Optional phone field
        "email": email,
        "emergencyContact": emergency_contact,  # Optional emergency contact field
        "password": hashed_pw,
        "authToken": token,         # Default authentication token is None
        "Devices": devices,        # Devices list (each device will have a telemetryData array)
        "type": user_type          # Adding userType (default: "user")
    }
    
    try:
        # Insert the user document into Cosmos DB
        insert_result = cosmos_service.insert_document(user_doc)
        
        # Only include string representation of the result
        response_body = {
            "message": f"{user_type.capitalize()} created successfully", 
            "token": token,
            "userId": user_id
        }
        return func.HttpResponse(json.dumps(response_body), status_code=201, mimetype="application/json")
    except Exception as e:
        logging.error(f"Error in create_user: {str(e)}")
        # Still return success if we know the user was created
        response_body = {
            "message": f"{user_type.capitalize()} created successfully", 
            "token": token,
            "userId": user_id,
            "warning": "Response processing error occurred"
        }
        return func.HttpResponse(json.dumps(response_body), status_code=201, mimetype="application/json")


def get_user_info(user_id: str):
    cosmos_service = CosmosDBService()
    user = cosmos_service.find_document({"_id": user_id})
    if not user:
        return None  # Return None instead of HttpResponse
    # Remove sensitive information before returning
    user.pop("password", None)
    user["_id"] = str(user["_id"])
    return user
    
def get_user(req: func.HttpRequest) -> func.HttpResponse:
    logging.info("Processing get_user request.")
    
    # Validate token and get user_id
    user_id = authenticate_user(req)
    if isinstance(user_id, func.HttpResponse):  # If validation failed, return the error response
        return user_id
    
    user = get_user_info(user_id)

    try:
        user = get_user_info(user_id)
        if not user:
            return func.HttpResponse(
                json.dumps({"message": "User not found"}), 
                status_code=404, 
                mimetype="application/json"
            )
        return func.HttpResponse(json.dumps(user), status_code=200, mimetype="application/json")
    except Exception as e:
        logging.exception(f"Error while querying CosmosDB for user_id: {user_id}")
        return func.HttpResponse(f"Error querying database: {str(e)}", status_code=500)

def update_user_put(req: func.HttpRequest) -> func.HttpResponse:
    logging.info("Processing update_user_put request.")
    
    try:
        # Validate token and get user_id
        logged_in_user_id = authenticate_user(req)
        if isinstance(logged_in_user_id, func.HttpResponse):
            return logged_in_user_id
        
        try:
            req_body = req.get_json()
        except ValueError:
            req_body = {}

        # Ensure the request body is a dictionary
        if not isinstance(req_body, dict):
            return func.HttpResponse(
                json.dumps({"message": "Invalid request body format"}), 
                status_code=400, 
                mimetype="application/json"
            )

        user = get_user_info(logged_in_user_id)
        if user is None:
            return func.HttpResponse(
                json.dumps({"message": "User not found"}),
                status_code=404,
                mimetype="application/json"
            )
            
        # Check if user is admin - note: field should match what's in create_user
        admin_user = False
        if user.get("type") == "admin":  # Use "type" to match create_user
            admin_user = True

        # Support both query parameters and JSON body
        target_user_id = req_body.get("userId") or req.params.get("userId", user.get("_id"))
        
        # Remove userId if present to avoid conflicts
        if "userId" in req_body:
            del req_body["userId"]

        if not req_body:
            return func.HttpResponse(
                json.dumps({"message": "Missing update data"}), 
                status_code=400, 
                mimetype="application/json"
            )
        
        cosmos_service = CosmosDBService()
        # Check if the logged-in user is an admin
        if not admin_user and target_user_id != logged_in_user_id:
            return func.HttpResponse(
                json.dumps({"message": "Access denied: Cannot update other users"}),
                status_code=403, 
                mimetype="application/json"
            )
        
        # Update document in Cosmos DB
        result = cosmos_service.update_document({"_id": target_user_id}, {"$set": req_body})
        
        return func.HttpResponse(
            json.dumps({"message": "User updated successfully"}), 
            status_code=200, 
            mimetype="application/json"
        )
            
    except Exception as e:
        logging.exception(f"Error in update_user_put: {str(e)}")
        return func.HttpResponse(
            json.dumps({"message": f"Internal server error: {str(e)}"}),
            status_code=500,
            mimetype="application/json"
        )

def update_password(req: func.HttpRequest) -> func.HttpResponse:
    logging.info("Processing update_password request.")
    # This function does NOT require an Authorization header.
    try:
        req_body = req.get_json()
    except ValueError:
        return func.HttpResponse("Invalid JSON body", status_code=400)
    
    # Expecting email, oldPassword, and newPassword in the request body.
    email = req_body.get("email")
    old_password = req_body.get("oldPassword")
    new_password = req_body.get("newPassword")
    if not email or not old_password or not new_password:
        return func.HttpResponse(
            json.dumps({"message": "Missing required fields"}), 
            status_code=400, 
            mimetype="application/json"
        )
    
    cosmos_service = CosmosDBService()
    user = cosmos_service.find_document({"email": email})
    if not user:
        return func.HttpResponse("User not found", status_code=404)
    
    stored_password = user.get("password")
    # Verify the provided old password with the stored hashed password
    if not verify_password(old_password, stored_password):
        return func.HttpResponse(
            json.dumps({"message": "Old password does not match"}), 
            status_code=401, 
            mimetype="application/json"
        )
    
    # Hash the new password and update the user document
    hashed_new_pw = hash_password(new_password)
    # Fix: Use $set operator for MongoDB update
    result = cosmos_service.update_document({"email": email}, {"$set": {"password": hashed_new_pw}})
    if result.modified_count == 0:
        return func.HttpResponse("Password not updated", status_code=400)
    
    return func.HttpResponse(
        json.dumps({"message": "Password updated successfully"}), 
        status_code=200, 
        mimetype="application/json"
    )

def delete_user(req: func.HttpRequest) -> func.HttpResponse:
    logging.info("Processing delete_user request.")
    
    try:
        # Validate token and get user_id
        logged_in_user_id = authenticate_user(req)
        if isinstance(logged_in_user_id, func.HttpResponse):
            return logged_in_user_id
        
        try:
            req_body = req.get_json()
        except ValueError:
            req_body = {}

        user = get_user_info(logged_in_user_id)
        if isinstance(user, func.HttpResponse):
            return user
            
        # Check if user is admin - note: field should match what's in create_user
        admin_user = False
        if user.get("type") == "admin":  # Use "type" to match create_user
            admin_user = True

        # Support both query parameters and JSON body
        target_user_id = req_body.get("userId") or req.params.get("userId", user.get("_id"))

        cosmos_service = CosmosDBService()
        if not admin_user and target_user_id != logged_in_user_id:
            return func.HttpResponse(
                json.dumps({"message": "Access denied: Cannot delete other users"}),
                status_code=403,
                mimetype="application/json"
            )
        
        # Get the user document to find associated devices
        user_document = get_user_info(target_user_id)
        if isinstance(user_document, func.HttpResponse):
            return user_document
            
        # Extract all device IDs from the user document
        devices = user_document.get("Devices", [])
        device_ids = []
        for device in devices:
            if "deviceId" in device:
                device_ids.append(device["deviceId"])
        
        # Delete devices from IoT Hub if there are any
        if device_ids:
            try:
                from azure_services.IothubService import IoTHubService
                iot_service = IoTHubService()
                iot_service.delete_device_from_iot_hub(device_ids)
                logging.info(f"Successfully deleted {len(device_ids)} devices from IoT Hub")
            except Exception as iot_e:
                logging.error(f"Error deleting devices from IoT Hub: {str(iot_e)}")
                # Continue with user deletion even if device deletion fails
        
        # Delete the user from Cosmos DB
        result = cosmos_service.delete_document({"_id": target_user_id})
        
        return func.HttpResponse(
            json.dumps({"message": "User deleted successfully"}), 
            status_code=200, 
            mimetype="application/json"
        )
            
    except Exception as e:
        logging.exception(f"Error in delete_user: {str(e)}")
        return func.HttpResponse(
            json.dumps({"message": f"Internal server error: {str(e)}"}),
            status_code=500,
            mimetype="application/json"
        )

def login_user(req: func.HttpRequest) -> func.HttpResponse:
    logging.info("Processing login_user request.")
    
    # Parse the request body
    try:
        req_body = req.get_json()
    except ValueError:
        return func.HttpResponse("Invalid JSON body", status_code=400)
    
    # Check required fields
    email = req_body.get("email")
    password = req_body.get("password")
    if not email or not password:
        return func.HttpResponse(
            json.dumps({"message": "Missing required fields"}), 
            status_code=400, 
            mimetype="application/json"
        )
    
    # Retrieve the user from CosmosDB
    cosmos_service = CosmosDBService()
    user = cosmos_service.find_document({"email": email})
    if not user:
        # If not found by email, search by username
        user = cosmos_service.find_document({"username": email})
        if not user:
            return func.HttpResponse(
                json.dumps({"message": "User not found"}), 
                status_code=404, 
                mimetype="application/json"
            )
    # Verify the password
    stored_password = user.get("password")
    if not verify_password(password, stored_password):
        return func.HttpResponse(
            json.dumps({"message": "Invalid email or password"}), 
            status_code=401, 
            mimetype="application/json"
        )
    
    # Generate a new token
    user_id = user.get("userId")
    new_token = create_token(user_id)
    
    # Update the token in the user's document
    update_result = cosmos_service.update_document(
        {"_id": user_id},
        {"$set": {"authToken": new_token}}  # Added $set operator
    )
    
    # Return the new token as a response
    response_body = {"message": "Login successful", "token": new_token}
    return func.HttpResponse(json.dumps(response_body), status_code=200, mimetype="application/json")

