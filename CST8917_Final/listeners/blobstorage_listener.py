import re
import logging
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

                blob_path = f"{blob_container}/{blob_name}"
                
                response = await self.get_user_by_filename(blob_name)
                if response and "user" in response:
                    # Pass device_id to handle_notification - blob movement is now ONLY handled there
                    await self.handle_notification(analysis_result, blob_path, response["user"], response["device_id"], response["event_id"])
                else:
                    logger.warning(f"No valid user found for {blob_name}, skipping notification and move operation")




            
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


    async def handle_notification(self, analysis_result, blob_path, user, device_id, event_id):
        """
        Process the image analysis results and send notification based on detected content.
        
        Args:
            analysis_result: The result from the cognitive service analysis
            blob_path: The path to the blob in storage
            user: The user information
            device_id: The device ID for organizing in processed container
            
        Returns:
            bool: True if content was detected and notification sent, False otherwise
        """
        logger.info(f"Processing analysis results for content detection {event_id}")
        try:
            import datetime
            from azure_services.blob_storage_service import BlobStorageService
            from azure_services.communication_service import CommunicationService
            from config.azure_config import get_azure_config
            
            # Check if analysis_result contains valid information
            if not analysis_result or not isinstance(analysis_result, dict):
                logger.warning("No valid analysis result to process")
                return False
            
            # Extract container and blob name from blob_path
            parts = blob_path.split('/', 1)
            if len(parts) != 2:
                logger.error(f"Invalid blob_path format: {blob_path}")
                return False
                
            blob_container, blob_name = parts
            
            # Get content detection result
            content_type = analysis_result.get("content_type", "other")
            confidence = analysis_result.get("confidence", 0.0)
            content_description = analysis_result.get("description", "No description available")
            
            # If no significant content detected, return False
            if content_type == "other" or confidence < 0.5:
                logger.info("No significant content detected in the image")
                return False
            
            logger.info(f"{content_type.capitalize()} detected with confidence {confidence}, sending notification")
            
            # First move the blob to processed container and get the new path
            moved_blob_path = None
            if await self._blob_exists(blob_container, blob_name):
                logger.info(f"Moving {blob_name} to processed container")
                move_start = time.time()
                moved_blob_path = await self.move_blob_to_processed_async(blob_name, device_id)
                move_duration = time.time() - move_start
                if moved_blob_path:
                    logger.info(f"Move operation completed for {blob_name} in {move_duration:.2f} seconds")
                    logger.info(f"New blob path: {moved_blob_path}")
                else:
                    logger.warning(f"Failed to move {blob_name}, will use original location for notification")
            else:
                logger.info(f"Blob {blob_name} no longer exists, will attempt to use processed container path")
                
            try:
                # Get blob URL with SAS token - use the new location if moved successfully
                blob_service = BlobStorageService()
                
                if moved_blob_path:
                    # Split the moved_blob_path to extract container and blob path
                    path_parts = moved_blob_path.split('/', 1)
                    if len(path_parts) == 2:
                        container_name, blob_path_only = path_parts
                        # Fix: Pass the full path as a single parameter
                        image_url_with_sas = blob_service.generate_sas_url(moved_blob_path)
                        logger.info(f"Using new blob path for notification: {moved_blob_path}")
                        
                        # Add image URL to telemetry data
                        if event_id:
                            telemetry_updated = await self.add_telemetry_data(blob_name, device_id ,event_id)
                            if telemetry_updated:
                                logger.info(f"Telemetry data updated with image URL for event_id: {event_id}")
                            else:
                                logger.warning(f"Failed to update telemetry data with image URL for event_id: {event_id}")
                    else:
                        # Fallback if path format is unexpected
                        image_url_with_sas = blob_service.generate_sas_url(moved_blob_path)
                        logger.info(f"Using moved blob path with single parameter: {moved_blob_path}")
                else:
                    # Fallback to original path if move failed
                    original_path = f"{blob_container}/{blob_name}"
                    image_url_with_sas = blob_service.generate_sas_url(original_path)
                    logger.info(f"Using original blob path for notification: {blob_path}")

                    
                # Get admin email from user
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
                
                # Send the email notification
                communication_service = CommunicationService()
                response = communication_service.send_email(
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


    async def add_telemetry_data(self, blob_name, device_id, event_id):
        """
        Updates the telemetry data with image URL information based on event_id.
        
        Args:
            blob_name: The name of the blob file
            device_id: The device ID associated with the image
            event_id: The event ID to link the image to
    
        Returns:
            dict: Updated user document or None if failed
        """
        logger.info(f"Searching for telemetry data with event_id: {event_id} across all users")
        
        try:
            from azure_services.cosmosdb_service import CosmosDBService
            cosmos_service = CosmosDBService()
            
            # Normalize the event_id for comparison
            search_event_id = str(event_id).strip()
            
            # Use a query that searches for the event_id in the nested telemetryData array
            query = {
                "Devices.telemetryData.eventId": search_event_id
            }
            
            processed_blob_path = f"{self.processed_container}/{device_id}/{blob_name}"

            # Find the document containing the event_id
            user = cosmos_service.find_document(query)
            
            if not user:
                logger.warning(f"No telemetry data found with event_id: {search_event_id} across all users")
                return None
            
            # Now modify the document in memory
            telemetry_updated = False
            
            # Find and update the specific telemetry entry
            for device in user.get("Devices", []):
                for telemetry in device.get("telemetryData", []):
                    telemetry_event_id = str(telemetry.get("eventId", "")).strip()
                    
                    if telemetry_event_id == search_event_id:
                        logger.info(f"Found telemetry data with event_id: {search_event_id} in user: {user.get('username')}, device: {device.get('deviceId')}")
                        
                        # Update the telemetry with the image URL directly in the object
                        telemetry["imageUrl"] = processed_blob_path
                        telemetry_updated = True
                        
                        # Once we've made the update, replace the entire document
                        filter_query = {"_id": user.get("_id")}
                        
                        # Update the document in Cosmos DB with the modified user object
                        result = cosmos_service.update_document(filter_query, {"$set": user})
                        
                        if result:
                            logger.info(f"Updated telemetry data with imageUrl: {processed_blob_path}")
                            return {
                                "user": user,
                                "device_id": device.get("deviceId"),
                                "telemetry": telemetry
                            }
                        else:
                            logger.error(f"Failed to update document in Cosmos DB")
                            return None
            
            # This should not happen if the query worked correctly, but as a fallback
            if not telemetry_updated:
                logger.warning(f"Event ID {search_event_id} found in user document but not in telemetry data (inconsistent state)")
            return None
            
        except Exception as e:
            logger.exception(f"Error searching for telemetry data with event_id: {search_event_id}: {str(e)}")
            return None


    async def get_user_by_filename(self, blob_filename):
        """
        Parse a blob filename to extract device_id and find the associated user.
        
        Blob filename format: {event_date}_{event_id}_{device_id}.{file_extension}
        Where event_date has colons, dashes, and periods removed
        
        Args:
            blob_filename: The name of the blob file
            
        Returns:
            dict: Object containing user information and device_id if found, None otherwise
        """
        logger.info(f"Attempting to find user for blob: {blob_filename}")
        try:
            # Extract the device_id using regex pattern
            # Pattern matches the third segment (after second underscore, before the extension)
            match = re.search(r'([^_]+)_([^_]+)_([^_\.]+)\.([^\.]+)$', blob_filename)
            if not match:
                logger.warning(f"Could not parse device_id from blob filename: {blob_filename}")
                return None
            
            event_date = match.group(1)
            event_id = match.group(2)  # Extract just the event ID portion
            device_id = match.group(3)
            logger.info(f"Extracted device_id: {device_id} from blob: {blob_filename}, event_id: {event_id}, event_date: {event_date}")
            
            # Create CosmosDB service instance
            cosmos_service = CosmosDBService()
            
            # Query for users that have this device_id in their Devices array
            query = {"Devices.deviceId": device_id}
            user = cosmos_service.find_document(query)
            
            if user:
                logger.info(f"Found user: {user.get('username')} (ID: {user.get('userId')}) for device: {device_id} {user} ")
                return {"user": user, "device_id": device_id, "event_id": event_id}
            else:
                logger.warning(f"No user found with device_id: {device_id}")
                return None
        except Exception as e:
            logger.exception(f"Error finding user for blob {blob_filename}: {str(e)}")
            return None

    async def move_blob_to_processed_async(self, blob_name, device_id):
        """
        Moves a blob from the source container to the processed container within a device-specific folder asynchronously.
        
        Args:
            blob_name: The name of the blob to move
            device_id: The device ID to use for subfolder organization
            
        Returns:
            str or None: The new blob path if successful, None if failed
        """
        logger.info(f"Starting move operation for blob {blob_name} from {self.blob_container} to {self.processed_container}/{device_id}")
        try:
            # First check if the blob exists before attempting to move it
            if not await self._blob_exists(self.blob_container, blob_name):
                logger.warning(f"Source blob {blob_name} not found in {self.blob_container}, skipping move operation")
                return None
                
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
                
                # Define destination path with device_id subfolder
                dest_blob_path = f"{device_id}/{blob_name}"
                
                # Create destination blob with device_id subfolder path
                logger.info(f"Getting destination blob client for {dest_blob_path}")
                dest_blob = dest_container_client.get_blob_client(dest_blob_path)
                
                # Generate a SAS URL for the source blob
                source_sas_url = self.generate_sas_url(self.blob_container, blob_name)
                
                # Start copy from source to destination using SAS URL
                logger.info(f"Initiating copy using SAS URL to destination container with path {dest_blob_path}")
                copy_start = time.time()
                copy_result = await dest_blob.start_copy_from_url(source_sas_url)
                logger.info(f"Copy initiated with ID: {copy_result['copy_id']}, status: {copy_result['copy_status']}")
                
                # Delete the source blob after copying
                logger.info(f"Deleting source blob {blob_name} from {self.blob_container}")
                await source_blob.delete_blob()
                logger.info(f"Source blob {blob_name} deleted successfully")
                
                copy_duration = time.time() - copy_start
                logger.info(f"Successfully moved blob {blob_name} to processed container {self.processed_container}/{device_id} in {copy_duration:.2f} seconds")
                
                # Return the new blob path
                return f"{self.processed_container}/{dest_blob_path}"
        except Exception as e:
            logger.exception(f"Failed to move blob {blob_name} to processed container/{device_id}: {str(e)}")
            return None

