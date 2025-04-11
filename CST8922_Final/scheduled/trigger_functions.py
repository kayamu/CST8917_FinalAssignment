import os
import datetime
import logging
from azure.storage.blob import BlobServiceClient
from config.azure_config import get_azure_config
from azure_services.CosmosdbService import CosmosDBService

def scheduled_cleanup(timer_info):
    try:
        # Load configuration
        config = get_azure_config()

        # Initialize BlobServiceClient using the connection string from config
        blob_service_client = BlobServiceClient.from_connection_string(
            config["BLOB_STORAGE_CONNECTION_STRING"]
        )
        container_name = config["BLOB_CONTAINER_NAME"]
        container_client = blob_service_client.get_container_client(container_name)

        # Initialize CosmosDBService
        cosmos_service = CosmosDBService()

        # Get current UTC time
        now = datetime.datetime.utcnow()

        # Query all users from the CosmosDB collection
        users = cosmos_service.find_documents({})

        for user in users:
            updated_images = []
            for image in user.get("uploadedImages", []):
                upload_date = datetime.datetime.fromisoformat(image["uploadDate"])
                age = now - upload_date

                # Check if image is older than 1 day
                if age.total_seconds() > 86400:
                    # Delete original and resized images from blob storage
                    try:
                        blob_name_original = f"{user['_id']}/{image['imageName']}"
                        container_client.delete_blob(blob_name_original)
                        logging.info(f"Deleted blobs: {blob_name_original}")
                    except Exception as e:
                        logging.error(f"Failed to delete blob(s): {str(e)}")
                else:
                    updated_images.append(image)

            # Update user document with only fresh images
            cosmos_service.update_document(
                {"_id": user["_id"]},
                {"$set": {"uploadedImages": updated_images}}
            )

    except Exception as e:
        logging.error(f"[Cleanup Error] {str(e)}")

def handle_error(error: Exception, context: dict = None):
    source = context.get("source", "Unknown")
    logging.exception(f"Error in {source}: {str(error)}")