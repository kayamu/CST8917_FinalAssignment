import os
import logging
from azure_services.cognitive_serivce import analyze_image

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
        self.storage_account_name = os.environ.get('BLOB_STORAGE_NAME')
        
    def process_blob(self, blob_data, blob_name):
        """
        Process a blob that has been triggered by a blob storage event.
        
        Args:
            blob_data: The blob data stream
            blob_name: The name of the blob
            
        Returns:
            dict: Analysis result from the cognitive service
        """
        logger.info(f"Processing blob: {blob_name}")
        try:
            # Get the blob URL
            blob_url = f"https://{self.storage_account_name}.blob.core.windows.net/telemetry-images/{blob_name}"
            
            # Call cognitive service to analyze the image
            analysis_result = analyze_image(blob_url)
            logger.info(f"Analysis result for {blob_name}: {analysis_result}")
            
            return analysis_result
        except Exception as e:
            logger.exception(f"Failed to process blob {blob_name}: {str(e)}")
            raise