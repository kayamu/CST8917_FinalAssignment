import logging
import json
import azure.functions as func
from bson import ObjectId  # Import for handling ObjectId
from azure_services.cosmosdb_service import CosmosDBService
from config.jwt_utils import authenticate_user
from config.azure_config import get_azure_config  # Import for reading Azure configuration

def json_serializer(obj):
    """
    Custom JSON serializer to handle ObjectId and other non-serializable types.
    """
    if isinstance(obj, ObjectId):
        return str(obj)
    raise TypeError(f"Type {type(obj)} not serializable")

def main(req: func.HttpRequest) -> func.HttpResponse:
    """
    Main function to handle HTTP requests.
    """
    logging.info("Starting main function for Conditions API.")

    # Authenticate the user
    logging.info("Authenticating the user.")
    user_id = authenticate_user(req)
    if not isinstance(user_id, str):  # Ensure user_id is a valid string
        logging.error("Authentication failed or invalid user_id.")
        return func.HttpResponse(
            json.dumps({"error": "Unauthorized or invalid user_id"}), 
            status_code=401, 
            mimetype="application/json"
        )
    logging.info(f"Authentication successful for user_id={user_id}.")

    # Parse the request body
    try:
        logging.info("Parsing the request body.")
        req_body = req.get_json()  # Try to parse the JSON body
        logging.debug(f"Request body parsed successfully: {req_body}")
    except ValueError:
        logging.warning("No JSON body provided. Using an empty dictionary as request body.")
        req_body = {}  # If no JSON body is provided, use an empty dictionary

    # Determine the HTTP method
    method = req.method.upper()
    logging.info(f"HTTP method received: {method}")

    # Route the request based on the HTTP method
    if method == "GET":
        logging.info("Processing GET request.")
        response, status_code = get_conditions(req_body, user_id)
    elif method == "POST":
        logging.info("Processing POST request.")
        response, status_code = post_condition(req_body, user_id)
    elif method == "PUT":
        logging.info("Processing PUT request.")
        response, status_code = put_condition(req_body, user_id)
    elif method == "DELETE":
        logging.info("Processing DELETE request.")
        response, status_code = delete_condition(req_body, user_id)
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


def get_conditions(req_body, user_id):
    """
    Fetch conditions based on userId or deviceId.
    """
    logging.info(f"Fetching conditions for userId={user_id}.")
    cosmos_service = CosmosDBService()
    config = get_azure_config()  # Load Azure configuration
    collection_name = config["CONDITION_COLLECTION_NAME"]  # Get the Conditions collection name

    # Extract deviceId from the request body
    device_id = req_body.get("deviceId")
    if device_id:
        logging.info(f"DeviceId provided: {device_id}")
    else:
        logging.info("No DeviceId provided. Fetching all conditions for the user.")

    # Build the query
    query = {"type": "condition"} 
    if device_id:
        query["deviceId"] = device_id

    logging.debug(f"Query to be executed: {query}")

    try:
        # Fetch conditions from the specified collection
        conditions = cosmos_service.find_documents(query, collection_name)
        logging.info(f"Found {len(conditions)} conditions matching the query.")
    except Exception as e:
        logging.error(f"Error while fetching conditions: {str(e)}")
        return {"message": "Failed to fetch conditions"}, 500

    logging.debug(f"Conditions fetched: {conditions}")
    return {"conditions": conditions}, 200


def post_condition(req_body, user_id):
    """
    Create one or multiple conditions. If deviceId is provided, verify the device exists.
    """
    cosmos_service = CosmosDBService()
    config = get_azure_config()
    collection_name = config["CONDITION_COLLECTION_NAME"]  # Read the collection name from azure_config

    # Normalize input to always be a list
    if not isinstance(req_body, list):
        req_body = [req_body]

    created_conditions = []
    errors = []

    for condition_data in req_body:
        device_id = condition_data.get("deviceId")
        if device_id:
            # Fetch the user document
            user = cosmos_service.find_document({"userId": user_id}, config["COLLECTION_NAME"])
            if not user:
                errors.append({"error": "User not found", "condition": condition_data})
                continue

            # Check if the device exists in the user's Devices list
            device = next((d for d in user.get("Devices", []) if d["deviceId"] == device_id), None)
            if not device:
                errors.append({"error": f"Device with deviceId {device_id} not found for the user", "condition": condition_data})
                continue

        # Create the condition
        condition = {
            "type": "condition",
            "userId": user_id,  # Automatically add userId from the authenticated user
            "deviceId": device_id,  # Include deviceId if provided
            "valueType": condition_data.get("valueType"),
            "minValue": condition_data.get("minValue"),
            "maxValue": condition_data.get("maxValue"),
            "exactValue": condition_data.get("exactValue"),
            "unit": condition_data.get("unit"),  # Add the Unit field
        }

        try:
            cosmos_service.insert_document(condition, collection_name)  # Use the specified collection
            created_conditions.append(condition)
        except Exception as e:
            errors.append({"error": str(e), "condition": condition_data})

    response = {"created_conditions": created_conditions}
    if errors:
        response["errors"] = errors
        return response, 400

    return response, 201


def put_condition(req_body, user_id):
    """
    Update an existing condition.
    """
    logging.info("Starting condition update process.")
    cosmos_service = CosmosDBService()
    config = get_azure_config()
    collection_name = config["CONDITION_COLLECTION_NAME"]  # Get the Conditions collection name

    # Validate the request body
    condition_id = req_body.get("conditionId")
    if not condition_id:
        logging.error("Missing conditionId in the request body.")
        return {"message": "Missing required fields"}, 400

    logging.info(f"Updating condition with conditionId={condition_id}.")

    # Build the query to find the condition
    try:
        query = {"_id": ObjectId(condition_id), "type": "condition", "userId": user_id}
    except Exception as e:
        logging.error(f"Invalid conditionId format: {str(e)}")
        return {"error": "Invalid conditionId format"}, 400

    logging.info(f"Query to find the condition: {query}")

    # Prepare the fields to update
    update_fields = {key: value for key, value in req_body.items() if key not in ["conditionId", "type"]}
    if not update_fields:
        logging.error("No fields provided to update.")
        return {"message": "No fields to update provided"}, 400

    logging.info(f"Fields to update: {update_fields}")

    try:
        # Perform the update
        result = cosmos_service.update_document(query, {"$set": update_fields}, collection_name)
        logging.debug(f"Update result: {result.raw_result}")
        if result.modified_count > 0:
            logging.info(f"Condition with conditionId={condition_id} updated successfully.")
            return {"message": "Condition updated successfully"}, 200
        else:
            logging.warning(f"No condition found with conditionId={condition_id} or no changes made.")
            return {"message": "Condition not found or no changes made"}, 404
    except Exception as e:
        logging.error(f"Error while updating condition: {str(e)}")
        return {"error": "Failed to update condition"}, 500


def delete_condition(req_body, user_id):
    """
    Delete a condition.
    """
    logging.info("Starting condition deletion process.")
    cosmos_service = CosmosDBService()
    config = get_azure_config()
    collection_name = config["CONDITION_COLLECTION_NAME"]  # Get the Conditions collection name

    # Validate the request body
    condition_id = req_body.get("conditionId")
    if not condition_id:
        logging.error("Missing conditionId in the request body.")
        return {"message": "Missing required fields"}, 400

    logging.info(f"Deleting condition with conditionId={condition_id}.")

    # Build the query to find the condition
    try:
        query = {"_id": ObjectId(condition_id), "type": "condition", "userId": user_id}
    except Exception as e:
        logging.error(f"Invalid conditionId format: {str(e)}")
        return {"error": "Invalid conditionId format"}, 400

    logging.info(f"Query to delete the condition: {query}")

    try:
        # Perform the deletion
        result = cosmos_service.delete_document(query, collection_name)
        logging.debug(f"Delete result: {result.raw_result}")
        if result.deleted_count > 0:
            logging.info(f"Condition with conditionId={condition_id} deleted successfully.")
            return {"message": "Condition deleted successfully"}, 200
        else:
            logging.warning(f"No condition found with conditionId={condition_id}.")
            return {"message": "Condition not found"}, 404
    except Exception as e:
        logging.error(f"Error while deleting condition: {str(e)}")
        return {"error": "Failed to delete condition"}, 500


