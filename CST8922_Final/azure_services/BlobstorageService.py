from azure.storage.blob import BlobServiceClient, generate_blob_sas, BlobSasPermissions
from datetime import datetime, timedelta
from config.azure_config import get_azure_config
import logging

class BlobStorageService:
    def __init__(self):
        config = get_azure_config()
        self.connection_string = config["BLOB_STORAGE_CONNECTION_STRING"]
        self.container_name = config["BLOB_CONTAINER_NAME"]
        self.blob_service_client = BlobServiceClient.from_connection_string(self.connection_string)

    def upload_image(self, image_data, blob_path):
        try:
            blob_client = self.blob_service_client.get_blob_client(container=self.container_name, blob=blob_path)
            blob_client.upload_blob(image_data, overwrite=True)
            logging.info(f"Image uploaded to Blob Storage: {blob_path}")
        except Exception as e:
            logging.exception("Failed to upload image to Blob Storage.")
            raise

    def generate_sas_url(self, container_or_path, blob_name=None):
        if blob_name is None:
            # If only one parameter provided, assume it's a full path
            if '/' in container_or_path:
                container_name, blob_name = container_or_path.split('/', 1)
            else:
                # Handle error case
                raise ValueError("Invalid path format. Expected 'container/blob' format")
        else:
            # If two parameters provided, use them directly
            container_name = container_or_path
            
        try:
            sas_token = generate_blob_sas(
                account_name=self.blob_service_client.account_name,
                container_name=container_name,
                blob_name=blob_name,
                account_key=self.blob_service_client.credential.account_key,
                permission=BlobSasPermissions(read=True),
                expiry=datetime.utcnow() + timedelta(hours=1)  # SAS token valid for 1 hour
            )
            blob_url = f"https://{self.blob_service_client.account_name}.blob.core.windows.net/{container_name}/{blob_name}?{sas_token}"
            return blob_url
        except Exception as e:
            logging.exception("Failed to generate SAS token for Blob.")
            raise
