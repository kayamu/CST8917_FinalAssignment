from azure.storage.blob import BlobServiceClient, generate_blob_sas, BlobSasPermissions
import uuid
from datetime import datetime, timedelta
from config.azure_config import get_azure_config
from azure_services.cognitive_serivce import analyze_image_for_fire

class BlobStorageService:
    def __init__(self):
        # Get Blob Storage configuration from azure_config
        config = get_azure_config()
        self.blob_service_client = BlobServiceClient.from_connection_string(config["BLOB_STORAGE_CONNECTION_STRING"])
        self.container_name = config["BLOB_CONTAINER_NAME"]
        self.container_client = self.blob_service_client.get_container_client(self.container_name)

    def upload_image(self, image_bytes: bytes, filename: str = None) -> str:
        if not filename:
            filename = f"{uuid.uuid4()}.jpg"  # Generate a random filename if not provided
        blob_client = self.container_client.get_blob_client(filename)
        blob_client.upload_blob(image_bytes, overwrite=True)  # Upload the image

        # Generate SAS token for the uploaded blob
        sas_token = generate_blob_sas(
            account_name=self.blob_service_client.account_name,
            container_name=self.container_name,
            blob_name=filename,
            account_key=self.blob_service_client.credential.account_key,
            permission=BlobSasPermissions(read=True),
            expiry=datetime.utcnow() + timedelta(hours=1)  # SAS token valid for 1 hour
        )

        # Construct the URL with SAS token
        blob_url_with_sas = f"{blob_client.url}?{sas_token}"

        # Analyze the image for fire
        fire_detection_result = analyze_image_for_fire(blob_url_with_sas)
        print(f"Fire detection result: {fire_detection_result}")

        return blob_url_with_sas  # Return the URL with SAS token