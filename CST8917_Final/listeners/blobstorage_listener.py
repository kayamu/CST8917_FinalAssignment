import os
import re
import logging
import asyncio
import time
import urllib.parse
from azure_services.cognitive_service import CognitiveServices
from azure_services.cosmosdb_service import CosmosDBService
from config.azure_config import get_azure_config
from azure.storage.blob import BlobServiceClient, generate_blob_sas, BlobSasPermissions
from azure.storage.blob.aio import BlobServiceClient as AsyncBlobServiceClient
from datetime import datetime, timedelta

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class BlobListener:
    """
    Class to handle blob storage events and processing.
    """
    
    def __init__(self):
        """
        Initialize the BlobListener class.
        """
        logger.info("Initializing BlobListener")
        config = get_azure_config()
        self.storage_account_name = config["BLOB_STORAGE_NAME"]
        self.blob_container = config["BLOB_CONTAINER_NAME"]
        self.processed_container = config["BLOB_CONTAINER_PROCESSED_IMAGES"]
        self.connection_string = config["BLOB_STORAGE_CONNECTION_STRING"]
        self.account_key = self._extract_account_key_from_connection_string(self.connection_string)
        logger.info(f"BlobListener initialized with account: {self.storage_account_name}, source container: {self.blob_container}, destination container: {self.processed_container}")
        
        self.cognitive_service = CognitiveServices()

    def _extract_account_key_from_connection_string(self, connection_string):
        """Extract the account key from the connection string."""
        parts = connection_string.split(';')
        for part in parts:
            if part.startswith('AccountKey='):
                return part.replace('AccountKey=', '')
        return None

    def generate_sas_url(self, container_name, blob_name):
        """
        Generate a SAS URL for blob access with proper URL encoding.
        
        Args:
            container_name: The container name
            blob_name: The blob name
            
        Returns:
            str: The SAS URL
        """
        # Generate SAS token with proper permissions
        sas_token = generate_blob_sas(
            account_name=self.storage_account_name,
            account_key=self.account_key,
            container_name=container_name,
            blob_name=blob_name,
            permission=BlobSasPermissions(read=True),
            expiry=datetime.utcnow() + timedelta(hours=1)
        )
        
        # URL encode the blob name to handle special characters
        encoded_blob_name = urllib.parse.quote(blob_name)
        
        # Build the full URL
        url = f"https://{self.storage_account_name}.blob.core.windows.net/{container_name}/{encoded_blob_name}?{sas_token}"
        return url

    async def process_blob(self, blob_data, blob_name, blob_container=None):
        """
        Process a blob that has been triggered by a blob storage event.
        
        Args:
            blob_data: The blob data stream
            blob_name: The name of the blob
            blob_container: The container name where the blob is stored (defaults to self.blob_container)
            
        Returns:
            dict: Analysis result from the cognitive service
        """
        start_time = time.time()
        
        # Use the default container if none is provided
        if blob_container is None:
            blob_container = self.blob_container
            
        logger.info(f"Starting blob processing for: {blob_name} in container: {blob_container}")
        
        # Check if the blob is in the correct container
        if blob_container != self.blob_container:
            logger.info(f"Ignoring blob {blob_name} - not in target container {self.blob_container}")
            return None
            
        # Safely log blob info without using len() on the stream
        logger.info(f"Processing blob: {blob_name} from stream")
        try:
            # Verify the blob exists before processing
            if not await self._blob_exists(blob_container, blob_name):
                logger.warning(f"Blob {blob_name} not found in container {blob_container}. It may have been processed already.")
                return None
                
            # Generate SAS URL directly using our method
            secure_blob_url = self.generate_sas_url(blob_container, blob_name)
            logger.info(f"Generated secure blob URL with SAS token")
            
            # Call cognitive service to analyze the image asynchronously and wait for the result
            logger.info(f"Sending blob {blob_name} to cognitive service for analysis")
            analysis_start = time.time()
            analysis_result = await self.cognitive_service.analyze_image(secure_blob_url)
            analysis_duration = time.time() - analysis_start
            logger.info(f"Analysis completed for {blob_name} in {analysis_duration:.2f} seconds")
            
            if analysis_result:
                logger.info(f"Analysis result: {analysis_result}")
                
                # Pass the raw URL for reference
                simple_blob_url = f"https://{self.storage_account_name}.blob.core.windows.net/{blob_container}/{urllib.parse.quote(blob_name)}"
                # Fix: Pass blob_name as a string, not a set
                await self.handle_notification(analysis_result, f"{blob_container}/{blob_name}", simple_blob_url, blob_name)

                # Check if blob exists again before moving (it might have been processed by another instance)
                """
                if await self._blob_exists(blob_container, blob_name):
                    logger.info(f"Moving {blob_name} to processed container")
                    move_start = time.time()
                    await self.move_blob_to_processed_async(blob_name)
                    move_duration = time.time() - move_start
                    logger.info(f"Move operation completed for {blob_name} in {move_duration:.2f} seconds")
                else:
                    logger.info(f"Blob {blob_name} no longer exists, skipping move operation")
                """    
            else:
                logger.warning(f"No valid analysis result for {blob_name}, skipping move operation")
            
            total_duration = time.time() - start_time
            logger.info(f"Total processing time for {blob_name}: {total_duration:.2f} seconds")
            return analysis_result
        except Exception as e:
            logger.exception(f"Failed to process blob {blob_name}: {str(e)}")
            raise
    
    async def _blob_exists(self, container_name, blob_name):
        """
        Check if a blob exists in the specified container.
        
        Args:
            container_name: The container name
            blob_name: The blob name
            
        Returns:
            bool: True if the blob exists, False otherwise
        """
        try:
            # Create a synchronous blob client (more reliable for existence check)
            blob_service_client = BlobServiceClient.from_connection_string(self.connection_string)
            container_client = blob_service_client.get_container_client(container_name)
            blob_client = container_client.get_blob_client(blob_name)
            
            # Use get_blob_properties to check if the blob exists
            properties = blob_client.get_blob_properties()
            return True
        except Exception as e:
            if "BlobNotFound" in str(e):
                logger.info(f"Blob {blob_name} not found in container {container_name}")
                return False
            else:
                logger.warning(f"Error checking if blob {blob_name} exists: {str(e)}")
                return False
            
    async def move_blob_to_processed_async(self, blob_name):
        """
        Moves a blob from the source container to the processed container asynchronously.
        
        Args:
            blob_name: The name of the blob to move
        """
        logger.info(f"Starting move operation for blob {blob_name} from {self.blob_container} to {self.processed_container}")
        try:
            # First check if the blob exists before attempting to move it
            if not await self._blob_exists(self.blob_container, blob_name):
                logger.warning(f"Source blob {blob_name} not found in {self.blob_container}, skipping move operation")
                return False
                
            # Create the AsyncBlobServiceClient
            logger.info(f"Creating AsyncBlobServiceClient using connection string")
            async with AsyncBlobServiceClient.from_connection_string(self.connection_string) as blob_service_client:
                # Get source and destination containers
                logger.info(f"Getting container clients for source ({self.blob_container}) and destination ({self.processed_container})")
                source_container_client = blob_service_client.get_container_client(self.blob_container)
                dest_container_client = blob_service_client.get_container_client(self.processed_container)
                
                # Get source blob
                logger.info(f"Getting source blob client for {blob_name}")
                source_blob = source_container_client.get_blob_client(blob_name)
                
                # Create destination blob
                logger.info(f"Getting destination blob client for {blob_name}")
                dest_blob = dest_container_client.get_blob_client(blob_name)
                
                # Generate a SAS URL for the source blob
                source_sas_url = self.generate_sas_url(self.blob_container, blob_name)
                
                # Start copy from source to destination using SAS URL
                logger.info(f"Initiating copy using SAS URL to destination container")
                copy_start = time.time()
                copy_result = await dest_blob.start_copy_from_url(source_sas_url)
                logger.info(f"Copy initiated with ID: {copy_result['copy_id']}, status: {copy_result['copy_status']}")
                
                # Delete the source blob after copying
                logger.info(f"Deleting source blob {blob_name} from {self.blob_container}")
                await source_blob.delete_blob()
                logger.info(f"Source blob {blob_name} deleted successfully")
                
                copy_duration = time.time() - copy_start
                logger.info(f"Successfully moved blob {blob_name} to processed container {self.processed_container} in {copy_duration:.2f} seconds")
                return True
                
        except Exception as e:
            logger.exception(f"Failed to move blob {blob_name} to processed container: {str(e)}")
            return False

    async def handle_notification(self, analysis_result, blob_path, blob_url, blob_name):
        """
        Process the image analysis results and send notification based on detected content.
        
        Args:
            analysis_result: The result from the cognitive service analysis
            blob_path: The path to the blob in storage
            blob_url: The URL of the blob
            
        Returns:
            bool: True if content was detected and notification sent, False otherwise
        """
        logger.info("Processing analysis results for content detection")
        try:
            import datetime
            from azure_services.blob_storage_service import BlobStorageService
            from azure_services.communication_service import CommunicationService
            from config.azure_config import get_azure_config
            
            # Check if analysis_result contains valid information
            if not analysis_result or not isinstance(analysis_result, dict):
                logger.warning("No valid analysis result to process")
                return False
            
            # Get content detection result - use cognitive_service instance instead of self
            # The detect_image_content method is in the CognitiveServices class
            content_type = analysis_result.get("content_type", "other")
            confidence = analysis_result.get("confidence", 0.0)
            content_description = analysis_result.get("description", "No description available")
            
            # If no significant content detected, return False
            if content_type == "other" or confidence < 0.5:
                logger.info("No significant content detected in the image")
                return False
            
            logger.info(f"{content_type.capitalize()} detected with confidence {confidence}, sending notification")
            
            try:
                # Get blob URL with SAS token
                blob_service = BlobStorageService()
                image_url_with_sas = blob_service.generate_sas_url(blob_path)
                
                # Get admin email from config
                # Fix: Await the coroutine properly
                user = await self.get_user_by_filename(blob_name)

                if user:
                    admin_email = user["email"]
                else:
                    return {"error": "User not found"}
                
                # Prepare email content based on content type
                current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                
                # Customize email subject and content based on detected content
                subject = f"{content_type.capitalize()} Alert Detected!"
                
                # Determine severity level and additional instructions based on content type
                severity = "High" if content_type in ["fire", "flood"] else "Medium" if content_type == "thunder" else "Low"
                
                instructions = {
                    "fire": "Please take immediate action. Evacuate the area if necessary and contact emergency services.",
                    "flood": "Please be cautious of rising water levels. Move to higher ground if needed.",
                    "thunder": "Take shelter indoors and stay away from electrical equipment and windows.",
                    "human": "An unauthorized person may be present in the monitored area.",
                    "animal": "An animal has been detected in the monitored area.",
                    "other": "Please review the image for more information."
                }.get(content_type, "Please review the image for more information.")
                
                plain_text_body = (
                    f"A {content_type} has been detected in an image processed by the system.\n\n"
                    f"Details:\n- Event Date: {current_time}\n"
                    f"- Detection Result: {content_description}\n"
                    f"- Severity: {severity}\n"
                    f"- Instructions: {instructions}\n"
                    f"- Image URL: {image_url_with_sas}"
                )
                
                html_body = f"""
                <html>
                    <body>
                        <h2>{content_type.capitalize()} Alert Detected!</h2>
                        <p>A {content_type} has been detected in an image processed by the system.</p>
                        <p><strong>Details:</strong></p>
                        <ul>
                            <li><strong>Event Date:</strong> {current_time}</li>
                            <li><strong>Detection Result:</strong> {content_description}</li>
                            <li><strong>Severity:</strong> <span style="color: {'red' if severity == 'High' else 'orange' if severity == 'Medium' else 'green'};">{severity}</span></li>
                            <li><strong>Instructions:</strong> {instructions}</li>
                            <li><strong>Image URL:</strong> <a href="{image_url_with_sas}">View Image</a></li>
                        </ul>
                        <p>Please review the attached image and take appropriate action.</p>
                    </body>
                </html>
                """
                
                # Send the email
                communication_service = CommunicationService()
                communication_service.send_email(
                    recipient_email=admin_email,
                    subject=subject,
                    body=plain_text_body,
                    html_body=html_body
                )
                logger.info(f"{content_type.capitalize()} alert email sent to {admin_email}")
                return True
            except Exception as e:
                logger.exception(f"Failed to send {content_type} alert email: {str(e)}")
                return False
                
        except Exception as e:
            logger.exception(f"Error processing image analysis results: {str(e)}")
            return False
        
    async def get_user_by_filename(self, blob_filename):
        """
        Parse a blob filename to extract device_id and find the associated user.
        
        Blob filename format: {event_date}_{device_id}.{file_extension}
        Where event_date has colons, dashes, and periods replaced
        
        Args:
            blob_filename: The name of the blob file
            
        Returns:
            dict: User information if found, None otherwise
        """
        logger.info(f"Attempting to find user for blob: {blob_filename}")
        
        try:
            # Extract the device_id using regex pattern
            # Pattern matches anything after the last underscore and before the last dot
            match = re.search(r'_([^_]+)\.[^.]+$', blob_filename)
            
            if not match:
                logger.warning(f"Could not parse device_id from blob filename: {blob_filename}")
                return None
                
            device_id = match.group(1)
            logger.info(f"Extracted device_id: {device_id} from blob: {blob_filename}")
            
            # Create CosmosDB service instance
            cosmos_service = CosmosDBService()
            
            # Query for users that have this device_id in their Devices array
            # This uses MongoDB's syntax for querying nested arrays
            query = {"Devices.deviceId": device_id}
            user = cosmos_service.find_document(query)
            
            if user:
                logger.info(f"Found user: {user.get('username')} (ID: {user.get('userId')}) for device: {device_id}")
                return user
            else:
                logger.warning(f"No user found with device_id: {device_id}")
                return None
                
        except Exception as e:
            logger.exception(f"Error finding user for blob {blob_filename}: {str(e)}")
            return None