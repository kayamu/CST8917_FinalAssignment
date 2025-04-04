import json
import logging
import uuid
import azure.functions as func
from config.jwt_utils import create_token, decode_token
from config.password_utils import hash_password, verify_password
from azure_services.cosmosdb_service import CosmosDBService

def main(req: func.HttpRequest) -> func.HttpResponse:
    """
    Main function for user-related requests.
    Dispatches based on HTTP method:
      POST   -> create_user (no authorization required)
      GET    -> get_user (authorization required)
      PUT    -> update_user_put (authorization required)
      PATCH  -> update_password (no authorization required)
      DELETE -> delete_user (authorization required)
      LOGIN  -> login_user (no authorization required)
      ADMIN  -> create_admin_user (no authorization required)
      USERS  -> get_users (authorization required, admin only)
    """
    method = req.method.upper()
    if method == "POST":
        return create_user(req)
    elif method == "GET":
        return get_user(req)
    elif method == "PUT":
        return update_user_put(req)
    elif method == "PATCH":
        return update_password(req)
    elif method == "DELETE":
        return delete_user(req)
    elif method == "LOGIN":
        return login_user(req)
    elif method == "ADMIN":
        return create_admin_user(req)
    elif method == "USERS":
        return get_users(req)
    else:
        return func.HttpResponse("Method not allowed", status_code=405)

def create_user(req: func.HttpRequest, user_type: str = "user") -> func.HttpResponse:
    logging.info(f"Processing create_user request with userType={user_type}.")
    try:
        req_body = req.get_json()
    except ValueError:
        return func.HttpResponse("Invalid JSON body", status_code=400)
    
    # Generate a unique userId using uuid (ignoring any provided userId)
    user_id = str(uuid.uuid4())
    
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
    if not name:
        missing_fields.append("name")
    if not surname:
        missing_fields.append("surame")
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
    
    # Hash the provided password
    hashed_pw = hash_password(password)
    
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
        "authToken": None,         # Default authentication token is None
        "Devices": devices,             # Devices list (each device will have a telemetryData array)
        "type": user_type          # Adding userType (default: "user")
    }
    
    cosmos_service = CosmosDBService()
    # Insert the user document into Cosmos DB
    insert_result = cosmos_service.insert_document(user_doc)
    
    # Generate an authentication token for the new user using userId as payload
    token = create_token(user_id)
    # Update the document with the generated token
    cosmos_service.update_document(
        {"_id": user_id, "type": user_type}, 
        {"$set": {"authToken": token}}  # Use $set operator to update the authToken field
    )
    
    response_body = {"message": f"{user_type.capitalize()} created successfully", "token": token}
    return func.HttpResponse(json.dumps(response_body), status_code=201, mimetype="application/json")

def create_admin_user(req: func.HttpRequest) -> func.HttpResponse:
    logging.info("Processing create_admin_user request.")
    return create_user(req, user_type="admin")

def get_user(req: func.HttpRequest) -> func.HttpResponse:
    logging.info("Processing get_user request.")
    
    # Check for Authorization header
    auth_header = req.headers.get("Authorization")
    if not auth_header:
        logging.error("Authorization header is missing.")
        return func.HttpResponse(
            json.dumps({"message": "Unauthorized"}), 
            status_code=401, 
            mimetype="application/json"
        )
    
    # Extract token from the Authorization header
    token = auth_header.split("Bearer ")[-1]
    logging.info(f"Extracted token: {token}")
    
    # Decode the token
    payload = decode_token(token)
    if not payload:
        logging.error("Token decoding failed or token is invalid.")
        return func.HttpResponse("Invalid token", status_code=401)
    
    # Extract user_id from the token payload
    user_id = payload.get("user_id")
    if not user_id:
        logging.error("Token payload does not contain user_id.")
        return func.HttpResponse("Invalid token payload: user_id missing", status_code=401)
    
    logging.info(f"Decoded user_id from token: {user_id}")
    
    # Query CosmosDB for the user document
    cosmos_service = CosmosDBService()
    try:
        user = cosmos_service.find_document({"_id": user_id})
        if not user:
            logging.error(f"User not found in CosmosDB for user_id: {user_id}")
            return func.HttpResponse(
                json.dumps({"message": "User not found"}), 
                status_code=404, 
                mimetype="application/json"
            )
    except Exception as e:
        logging.exception(f"Error while querying CosmosDB for user_id: {user_id}")
        return func.HttpResponse(f"Error querying database: {str(e)}", status_code=500)
    
    logging.info(f"User found in CosmosDB: {user}")
    
    # Remove sensitive information and convert _id to string for JSON serialization
    user.pop("password", None)
    user["_id"] = str(user["_id"])
    logging.info(f"Final user object to return: {user}")
    
    return func.HttpResponse(json.dumps(user), status_code=200, mimetype="application/json")

def update_user_put(req: func.HttpRequest) -> func.HttpResponse:
    logging.info("Processing update_user_put request.")
    # This function requires authorization.
    auth_header = req.headers.get("Authorization")
    if not auth_header:
        return func.HttpResponse("Authorization header missing", status_code=401)
    
    token = auth_header.split("Bearer ")[-1]
    payload = decode_token(token)
    if not payload:
        return func.HttpResponse("Invalid token", status_code=401)
    
    user_id = payload.get("user_id")
    try:
        req_body = req.get_json()
    except ValueError:
        return func.HttpResponse("Invalid JSON body", status_code=400)
    
    # Allowed fields for update: firstName, lastName, email, phone
    update_data = {}
    if "firstName" in req_body:
        update_data["firstName"] = req_body["firstName"]
    if "lastName" in req_body:
        update_data["lastName"] = req_body["lastName"]
    if "email" in req_body:
        update_data["email"] = req_body["email"]
    if "phone" in req_body:
        update_data["phone"] = req_body["phone"]
    
    if not update_data:
        return func.HttpResponse(
            json.dumps({"message": "No update data provided"}), 
            status_code=400, 
            mimetype="application/json"
        )
    
    # Wrap update_data with $set operator
    update_query = {"$set": update_data}
    
    cosmos_service = CosmosDBService()
    try:
        result = cosmos_service.update_document({"_id": user_id}, update_query)
        if result.modified_count == 0:
            return func.HttpResponse(
                json.dumps({"message": "User not updated"}), 
                status_code=400, 
                mimetype="application/json"
            )
    except Exception as e:
        logging.error(f"Error while updating user: {str(e)}")
        return func.HttpResponse(f"Error updating user: {str(e)}", status_code=500)
    
    return func.HttpResponse(
        json.dumps({"message": "User updated successfully"}), 
        status_code=200, 
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
    result = cosmos_service.update_document({"email": email}, {"password": hashed_new_pw})
    if result.modified_count == 0:
        return func.HttpResponse("Password not updated", status_code=400)
    
    return func.HttpResponse(
        json.dumps({"message": "Password updated successfully"}), 
        status_code=200, 
        mimetype="application/json"
    )

def delete_user(req: func.HttpRequest) -> func.HttpResponse:
    logging.info("Processing delete_user request.")
    auth_header = req.headers.get("Authorization")
    if not auth_header:
        return func.HttpResponse("Authorization header missing", status_code=401)
    
    token = auth_header.split("Bearer ")[-1]
    payload = decode_token(token)
    if not payload:
        return func.HttpResponse("Invalid token", status_code=401)
    
    user_id = payload.get("user_id")
    cosmos_service = CosmosDBService()
    result = cosmos_service.delete_document({"_id": user_id})
    if result.deleted_count == 0:
        return func.HttpResponse(
            json.dumps({"message": "User not deleted"}), 
            status_code=400, 
            mimetype="application/json"
        )
    
    return func.HttpResponse(
        json.dumps({"message": "User deleted successfully"}), 
        status_code=200, 
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
    #if update_result.modified_count == 0:
    #    return func.HttpResponse("Failed to update user token", status_code=500)
    
    # Return the new token as a response
    response_body = {"message": "Login successful", "token": new_token}
    return func.HttpResponse(json.dumps(response_body), status_code=200, mimetype="application/json")

def get_users(req: func.HttpRequest) -> func.HttpResponse:
    logging.info("Processing get_users request.")
    
    # Check for Authorization header
    auth_header = req.headers.get("Authorization")
    if not auth_header:
        logging.error("Authorization header is missing.")
        return func.HttpResponse("Authorization header missing", status_code=401)
    
    # Extract token from the Authorization header
    token = auth_header.split("Bearer ")[-1]
    logging.info(f"Extracted token: {token}")
    
    # Decode the token
    payload = decode_token(token)
    if not payload:
        logging.error("Token decoding failed or token is invalid.")
        return func.HttpResponse("Invalid token", status_code=401)
    
    # Extract user_id from the token payload
    user_id = payload.get("user_id")
    if not user_id:
        logging.error("Token payload does not contain user_id.")
        return func.HttpResponse("Invalid token payload: user_id missing", status_code=401)
    
    logging.info(f"Decoded user_id from token: {user_id}")
    
    # Query CosmosDB for the admin user
    cosmos_service = CosmosDBService()
    try:
        admin_user = cosmos_service.find_document({"_id": user_id, "type": "admin"})
        if not admin_user:
            logging.error(f"User with user_id: {user_id} is not an admin.")
            return func.HttpResponse("Access denied: Only admins can access this resource", status_code=403)
    except Exception as e:
        logging.exception(f"Error while querying CosmosDB for admin user_id: {user_id}")
        return func.HttpResponse(f"Error querying database: {str(e)}", status_code=500)
    
    logging.info(f"Admin user verified: {admin_user}")
    
    # Build the query based on query parameters
    query = {}
    user_type = req.params.get("userType")
    device_name = req.params.get("deviceName")
    device_id = req.params.get("deviceId")
    telemetry_date = req.params.get("telemetryDate")
    sensor_type = req.params.get("sensorType")
    value_type = req.params.get("valueType")
    value_min = req.params.get("valueMin")
    value_max = req.params.get("valueMax")
    
    if user_type:
        query["type"] = user_type
    else:
        query["type"] = {"$in": ["user", "admin"]}  # Default to both user and admin types
    
    # Query CosmosDB for users
    try:
        users = cosmos_service.find_documents(query)
        filtered_users = []
        for user in users:
            # Filter by device and telemetry information
            if device_name or device_id or telemetry_date or sensor_type or value_type or value_min or value_max:
                devices = user.get("Devices", [])
                matching_devices = []
                for device in devices:
                    if device_name and device.get("deviceName") != device_name:
                        continue
                    if device_id and device.get("deviceId") != device_id:
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
                        matching_devices.append(device)
                
                if matching_devices:
                    user["Devices"] = matching_devices
                    filtered_users.append(user)
            else:
                filtered_users.append(user)
        
        # Remove sensitive information and convert _id to string for JSON serialization
        for user in filtered_users:
            user.pop("password", None)
            user["_id"] = str(user["_id"])
        logging.info(f"Total users found: {len(filtered_users)}")
    except Exception as e:
        logging.exception("Error while querying CosmosDB for users.")
        return func.HttpResponse(f"Error querying database: {str(e)}", status_code=500)
    
    return func.HttpResponse(json.dumps(filtered_users), status_code=200, mimetype="application/json")

