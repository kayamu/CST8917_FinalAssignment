import json
import logging
import azure.functions as func
from config.jwt_utils import decode_token, authenticate_user
from azure_services.cosmosdb_service import CosmosDBService
from functions.user_functions import create_user, update_user_put
from config.azure_config import get_azure_config
from azure.storage.blob import BlobServiceClient


def main(req: func.HttpRequest) -> func.HttpResponse:
    """
    Main method to route admin-related requests to the appropriate function.
    """
    logging.info("Processing admin main request.")
    
    # Extract the method type from the query parameters or request body
    method = req.params.get("method")
    if not method:
        try:
            req_body = req.get_json()
            method = req_body.get("method")
        except ValueError:
            return func.HttpResponse(
                json.dumps({"message": "Method not specified"}), 
                status_code=400, 
                mimetype="application/json"
            )
    
    # Route to the appropriate function based on the method type
    if method == "ADMIN":
        return create_admin_user(req)
    elif method == "USERS":
        return get_users(req)
    elif method == "CHANGE_TYPE":
        return change_user_type(req)
    elif method == "LIST_PROCESSED_IMAGES":
        return list_processed_images(req)
    elif method == "TRANSFER_DEVICE":
        return transfer_device(req)
    else:
        return func.HttpResponse(
            json.dumps({"message": "Invalid method"}), 
            status_code=400, 
            mimetype="application/json"
        )

def get_users(req: func.HttpRequest) -> func.HttpResponse:
    logging.info("Processing get_users request.")
    
    user_id = authenticate_user(req)
    if isinstance(user_id, func.HttpResponse):  # If validation failed, return the error response
        return user_id
    
    cosmos_service = CosmosDBService()
    try:
        admin_user = cosmos_service.find_document({"_id": user_id, "type": "admin"})
        if not admin_user:
            logging.error(f"User with user_id: {user_id} is not an admin.")
            return func.HttpResponse("Access denied: Only admins can access this resource", status_code=403)
    except Exception as e:
        logging.exception(f"Error while querying CosmosDB for admin user_id: {user_id}")
        return func.HttpResponse(f"Error querying database: {str(e)}", status_code=500)
    
    # Build filter query based on optional parameters
    query_filter = {}
    
    # Extract query parameters
    user_id_filter = req.params.get('userId')
    username_filter = req.params.get('username')
    email_filter = req.params.get('email')
    phone_filter = req.params.get('phone')
    
    # Add filters to query if provided
    if user_id_filter:
        query_filter["userId"] = user_id_filter
    if username_filter:
        query_filter["username"] = username_filter
    if email_filter:
        query_filter["email"] = email_filter
    if phone_filter:
        query_filter["phone"] = phone_filter
    
    # Fetch users with optional filters
    try:
        users = cosmos_service.find_documents(query_filter)
        
        # Clean the user data (remove password and format _id)
        for user in users:
            user.pop("password", None)
            user["_id"] = str(user["_id"])
        
        return func.HttpResponse(json.dumps(users), status_code=200, mimetype="application/json")
    except Exception as e:
        logging.exception("Error while querying CosmosDB for users.")
        return func.HttpResponse(f"Error querying database: {str(e)}", status_code=500)

def change_user_type(req: func.HttpRequest) -> func.HttpResponse:
    logging.info("Processing change_user_type request.")
    
    # Check for Authorization header
    auth_header = req.headers.get("Authorization")
    if not auth_header:
        return func.HttpResponse("Authorization header missing", status_code=401)
    
    token = auth_header.split("Bearer ")[-1]
    payload = decode_token(token)
    if not payload:
        return func.HttpResponse("Invalid token", status_code=401)
    
    user_id = payload.get("user_id")
    if not user_id:
        return func.HttpResponse("Invalid token payload: user_id missing", status_code=401)
    
    cosmos_service = CosmosDBService()
    admin_user = cosmos_service.find_document({"_id": user_id, "type": "admin"})
    if not admin_user:
        return func.HttpResponse("Access denied: Only admins can change user types", status_code=403)
    
    # Call the existing update_user_put method
    return update_user_put(req)

def create_admin_user(req: func.HttpRequest) -> func.HttpResponse:
    logging.info("Processing create_admin_user request.")
    return create_user(req, user_type="admin")

def list_processed_images(req: func.HttpRequest) -> func.HttpResponse:
    """
    Lists all files and directories in the processed-images blob container.
    Requires admin authentication.
    """
    logging.info("Processing list_processed_images request.")
    
    # Authenticate user and verify admin permissions
    user_id = authenticate_user(req)
    if isinstance(user_id, func.HttpResponse):  # If validation failed, return the error response
        return user_id
    
    cosmos_service = CosmosDBService()
    try:
        admin_user = cosmos_service.find_document({"_id": user_id, "type": "admin"})
        if not admin_user:
            logging.error(f"User with user_id: {user_id} is not an admin.")
            return func.HttpResponse(
                json.dumps({"message": "Access denied: Only admins can access this resource"}),
                status_code=403, 
                mimetype="application/json"
            )
    except Exception as e:
        logging.exception(f"Error while querying CosmosDB for admin user_id: {user_id}")
        return func.HttpResponse(
            json.dumps({"message": f"Error querying database: {str(e)}"}),
            status_code=500, 
            mimetype="application/json"
        )
    
    # Get Azure configuration
    azure_config = get_azure_config()
    connection_string = azure_config.get("BLOB_STORAGE_CONNECTION_STRING")
    container_name = azure_config.get("BLOB_CONTAINER_PROCESSED_IMAGES")
    
    # Optional path prefix for listing files in a specific directory
    prefix = req.params.get('prefix', '')
    
    try:
        # Create blob service client
        blob_service_client = BlobServiceClient.from_connection_string(connection_string)
        container_client = blob_service_client.get_container_client(container_name)
        
        # List blobs with the specified prefix
        blobs = container_client.list_blobs(name_starts_with=prefix)
        
        # Extract file and directory information
        file_list = []
        directories = set()
        
        for blob in blobs:
            # Process blob paths to extract directory information
            blob_name = blob["name"]
            file_info = {
                "name": blob_name,
                "size": blob["size"],
                "last_modified": blob["last_modified"].isoformat() if "last_modified" in blob else None,
                "content_type": blob.get("content_settings", {}).get("content_type", "application/octet-stream")
            }
            file_list.append(file_info)
            
            # Extract directory paths
            if '/' in blob_name:
                path_parts = blob_name.split('/')
                for i in range(len(path_parts) - 1):
                    directory = '/'.join(path_parts[:i+1]) + '/'
                    directories.add(directory)
        
        # Prepare the result
        result = {
            "files": file_list,
            "directories": sorted(list(directories))
        }
        
        return func.HttpResponse(
            json.dumps(result),
            status_code=200,
            mimetype="application/json"
        )
        
    except Exception as e:
        logging.exception(f"Error listing blobs from container: {container_name}")
        return func.HttpResponse(
            json.dumps({"message": f"Error listing blobs: {str(e)}"}),
            status_code=500,
            mimetype="application/json"
        )

def transfer_device(req: func.HttpRequest) -> func.HttpResponse:
    """
    Transfers a device from one user to another.
    Required parameters:
    - deviceId: ID of the device to transfer
    - newUserId: ID of the user to receive the device
    Only admins can perform this operation.
    """
    logging.info("Processing transfer_device request.")
    
    # Authenticate the user and verify admin permissions
    user_id = authenticate_user(req)
    if isinstance(user_id, func.HttpResponse):  # If validation failed, return the error response
        return user_id
    
    cosmos_service = CosmosDBService()
    try:
        # Verify the requesting user is an admin
        admin_user = cosmos_service.find_document({"_id": user_id, "type": "admin"})
        if not admin_user:
            logging.error(f"User with user_id: {user_id} is not an admin.")
            return func.HttpResponse(
                json.dumps({"message": "Access denied: Only admins can transfer devices"}),
                status_code=403, 
                mimetype="application/json"
            )
    except Exception as e:
        logging.exception(f"Error while querying CosmosDB for admin user_id: {user_id}")
        return func.HttpResponse(
            json.dumps({"message": f"Error querying database: {str(e)}"}),
            status_code=500, 
            mimetype="application/json"
        )
    
    # Get request parameters from query string
    device_id = req.params.get("deviceId")
    new_user_id = req.params.get("newUserId")
    
    # Fallback to request body if parameters aren't in query string
    if not device_id or not new_user_id:
        try:
            req_body = req.get_json()
            device_id = device_id or req_body.get("deviceId")
            new_user_id = new_user_id or req_body.get("newUserId")
        except ValueError:
            pass  # No JSON body or invalid JSON
    
    # Validate required parameters
    if not device_id:
        return func.HttpResponse(
            json.dumps({"message": "deviceId is required"}),
            status_code=400, 
            mimetype="application/json"
        )
    
    if not new_user_id:
        return func.HttpResponse(
            json.dumps({"message": "newUserId is required"}),
            status_code=400, 
            mimetype="application/json"
        )
    
    # Verify the new user exists
    try:
        new_user = cosmos_service.find_document({"userId": new_user_id})
        if not new_user:
            return func.HttpResponse(
                json.dumps({"message": f"New user with ID {new_user_id} not found"}),
                status_code=404, 
                mimetype="application/json"
            )
    except Exception as e:
        logging.exception(f"Error while querying CosmosDB for new user_id: {new_user_id}")
        return func.HttpResponse(
            json.dumps({"message": f"Error querying database: {str(e)}"}),
            status_code=500, 
            mimetype="application/json"
        )
    
    # Find the device in all users
    old_user = None
    device = None
    
    try:
        # Search for the device in all users
        all_users = cosmos_service.find_documents({})
        
        for user in all_users:
            for i, d in enumerate(user.get("Devices", [])):
                if d.get("deviceId") == device_id:
                    device = user["Devices"].pop(i)  # Remove the device from user
                    old_user = user
                    break
            
            if device:
                break
        
        if not device:
            return func.HttpResponse(
                json.dumps({"message": f"Device with ID {device_id} not found in any user"}),
                status_code=404, 
                mimetype="application/json"
            )
    except Exception as e:
        logging.exception(f"Error while searching for device with ID: {device_id}")
        return func.HttpResponse(
            json.dumps({"message": f"Error searching for device: {str(e)}"}),
            status_code=500, 
            mimetype="application/json"
        )
    
    # Add the device to the new user
    if not new_user.get("Devices"):
        new_user["Devices"] = []
    
    new_user["Devices"].append(device)
    
    # Update both users in the database
    try:
        # Update old user document
        if old_user:
            # Create a proper filter query using _id
            cosmos_service.update_document({"_id": old_user["_id"]}, {"$set": old_user})
        
        # Update new user document
        cosmos_service.update_document({"_id": new_user["_id"]}, {"$set": new_user})
        
        return func.HttpResponse(
            json.dumps({
                "message": "Device transferred successfully",
                "deviceId": device_id,
                "oldUserId": old_user["userId"] if old_user else None,
                "newUserId": new_user["userId"]
            }),
            status_code=200, 
            mimetype="application/json"
        )
    except Exception as e:
        logging.exception("Error updating users in database")
        return func.HttpResponse(
            json.dumps({"message": f"Error updating users: {str(e)}"}),
            status_code=500, 
            mimetype="application/json"
        )

