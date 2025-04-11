import logging
import json
import azure.functions as func
from bson import ObjectId
from azure_services.cosmosdb_service import CosmosDBService
from config.jwt_utils import authenticate_user
from config.azure_config import get_azure_config

def json_serializer(obj):
    """
    Custom JSON serializer to handle ObjectId and other non-serializable types.
    """
    if isinstance(obj, ObjectId):
        return str(obj)
    raise TypeError(f"Type {type(obj)} not serializable")

def main(req: func.HttpRequest) -> func.HttpResponse:
    """
    Main function to handle HTTP requests for AlertLogs.
    """
    logging.info("Starting main function for AlertLogs API.")

    # Authenticate the user
    logging.info("Authenticating the user.")
    user_id = authenticate_user(req)
    if not isinstance(user_id, str):
        logging.error("Authentication failed or invalid user_id.")
        return func.HttpResponse(
            json.dumps({"error": "Unauthorized or invalid user_id"}), 
            status_code=401, 
            mimetype="application/json"
        )
    logging.info(f"Authentication successful for user_id={user_id}.")

    # Determine the HTTP method
    method = req.method.upper()
    logging.info(f"HTTP method received: {method}")

    # Route the request based on the HTTP method
    if method == "GET":
        logging.info("Processing GET request.")
        response, status_code = get_alert_logs(req, user_id)
    elif method == "DELETE":
        logging.info("Processing DELETE request.")
        response, status_code = delete_alert_log(req, user_id)
    else:
        logging.error(f"Unsupported HTTP method: {method}")
        return func.HttpResponse(
            json.dumps({"error": "Method not allowed"}), 
            status_code=405, 
            mimetype="application/json"
        )

    # Serialize the response and return
    try:
        logging.info("Serializing the response.")
        response_body = json.dumps(response, default=json_serializer)
        logging.debug(f"Response serialized successfully: {response_body}")
    except Exception as e:
        logging.error(f"Error while serializing the response: {str(e)}")
        return func.HttpResponse(
            json.dumps({"error": "Internal server error"}), 
            status_code=500, 
            mimetype="application/json"
        )

    logging.info(f"Returning response with status_code={status_code}.")
    return func.HttpResponse(
        response_body, 
        status_code=status_code, 
        mimetype="application/json"
    )

def get_alert_logs(req, user_id):
    """
    Fetch alert logs for the authenticated user.
    """
    logging.info(f"Fetching alert logs for user_id={user_id}.")
    cosmos_service = CosmosDBService()
    config = get_azure_config()
    collection_name = config["ALERT_COLLECTION_NAME"]

    # Parse query parameters
    device_id = req.params.get("deviceId")
    query = {"user_id": user_id}
    if device_id:
        query["deviceId"] = device_id

    logging.debug(f"Query to be executed: {query}")

    try:
        alert_logs = cosmos_service.find_documents(query, collection_name)
        logging.info(f"Found {len(alert_logs)} alert logs matching the query.")
    except Exception as e:
        logging.error(f"Error while fetching alert logs: {str(e)}")
        return {"message": "Failed to fetch alert logs"}, 500

    logging.debug(f"Alert logs fetched: {alert_logs}")
    return {"alert_logs": alert_logs}, 200

def delete_alert_log(req, user_id):
    """
    Delete an alert log by its ID for the authenticated user.
    """
    logging.info("Starting alert log deletion process.")
    cosmos_service = CosmosDBService()
    config = get_azure_config()
    collection_name = config["ALERT_COLLECTION_NAME"]

    # Parse the request body
    try:
        req_body = req.get_json()
        alert_log_id = req_body.get("alertLogId")
        if not alert_log_id:
            logging.error("Missing alertLogId in the request body.")
            return {"message": "Missing required fields"}, 400
    except ValueError:
        logging.error("Invalid JSON body.")
        return {"message": "Invalid request body"}, 400

    logging.info(f"Deleting alert log with alertLogId={alert_log_id} for user_id={user_id}.")

    # Build the query to find the alert log
    try:
        query = {"_id": ObjectId(alert_log_id), "user_id": user_id}
    except Exception as e:
        logging.error(f"Invalid alertLogId format: {str(e)}")
        return {"error": "Invalid alertLogId format"}, 400

    logging.info(f"Query to delete the alert log: {query}")

    try:
        result = cosmos_service.delete_document(query, collection_name)
        if result.deleted_count > 0:
            logging.info(f"Alert log with alertLogId={alert_log_id} deleted successfully.")
            return {"message": "Alert log deleted successfully"}, 200
        else:
            logging.warning(f"No alert log found with alertLogId={alert_log_id}.")
            return {"message": "Alert log not found"}, 404
    except Exception as e:
        logging.error(f"Error while deleting alert log: {str(e)}")
        return {"error": "Failed to delete alert log"}, 500