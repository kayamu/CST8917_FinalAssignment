import json
import logging
import azure.functions as func
from config.jwt_utils import decode_token, authenticate_user
from azure_services.cosmosdb_service import CosmosDBService
from functions.user_functions import create_user, update_user_put


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

