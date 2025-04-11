import logging
import asyncio
from azure.cognitiveservices.vision.computervision import ComputerVisionClient
from msrest.authentication import CognitiveServicesCredentials
from config.azure_config import get_azure_config

# Configure logger
logger = logging.getLogger(__name__)

class CognitiveServices:
    """Class for Azure Cognitive Services operations"""
    
    def __init__(self):
        """Initialize the CognitiveServices class with Azure configuration"""
        # Get Azure Cognitive Service configuration
        config = get_azure_config()
        self.endpoint = config["COGNITIVE_SERVICE_ENDPOINT"]
        self.subscription_key = config["COGNITIVE_SERVICE_KEY"]
        
        # Create a Computer Vision Client
        self.client = ComputerVisionClient(
            self.endpoint, 
            CognitiveServicesCredentials(self.subscription_key)
        )
        logger.info("CognitiveServices client initialized")

    async def detect_image_content(self, analysis_result):
        """
        Detects the content type in an image based on analysis results.
        
        Args:
            analysis_result: The result from the cognitive service analysis
            
        Returns:
            dict: A dictionary containing the detected content type and confidence score
        """
        logger.info("Detecting image content from analysis results")
        
        # Default result
        detection_result = {
            "content_type": "other",
            "confidence": 0,
            "description": "No specific content detected"
        }
        
        if not analysis_result:
            logger.warning("No valid analysis result to process for content detection")
            return detection_result
        
        # Define detection keywords for each content type
        content_types = {
            "fire": ["fire", "flame", "smoke", "burning", "blaze"],
            "animal": ["animal", "dog", "cat", "bird", "wildlife", "pet", "horse", "cow", "sheep", "lion", "tiger"],
            "human": ["person", "people", "human", "man", "woman", "child", "face", "portrait"],
            "flood": ["flood", "flooding", "water", "submerged", "inundation"],
            "thunder": ["lightning", "thunder", "storm", "thunderstorm", "electrical storm"]
        }
        
        # Check tags for content matches
        highest_confidence = 0
        detected_type = "other"
        description = "No specific content detected"
        
        # Process tags
        if hasattr(analysis_result, 'tags'):
            for tag in analysis_result.tags:
                tag_name = tag.name.lower()
                tag_confidence = tag.confidence
                
                # Check each content type
                for content_type, keywords in content_types.items():
                    if any(keyword in tag_name for keyword in keywords) and tag_confidence > highest_confidence:
                        highest_confidence = tag_confidence
                        detected_type = content_type
                        description = f"{content_type.capitalize()} detected with {highest_confidence:.2f} confidence in tag '{tag_name}'"
        
        # Check descriptions for content mentions
        if highest_confidence < 0.6 and hasattr(analysis_result, 'description') and analysis_result.description:
            for caption in analysis_result.description.captions:
                caption_text = caption.text.lower()
                caption_confidence = caption.confidence
                
                for content_type, keywords in content_types.items():
                    if any(keyword in caption_text for keyword in keywords) and caption_confidence > highest_confidence:
                        highest_confidence = caption_confidence
                        detected_type = content_type
                        description = f"{content_type.capitalize()} mentioned in description: '{caption_text}' with {highest_confidence:.2f} confidence"
        
        # Only consider it detected if confidence is above threshold
        if highest_confidence > 0.5:
            detection_result = {
                "content_type": detected_type,
                "confidence": highest_confidence,
                "description": description
            }
            logger.info(f"Content detection result: {detection_result}")
        else:
            logger.info("No specific content detected with sufficient confidence")
        
        return detection_result

    async def analyze_image(self, image_url: str) -> dict:
        """
        Asynchronously analyze an image to detect various content types.
        
        Args:
            image_url: URL of the image to analyze
            
        Returns:
            dict: Analysis result with content type, confidence and description
        """
        try:
            # Run the synchronous API call in a thread pool
            analysis = await asyncio.to_thread(
                self.client.analyze_image,
                image_url,
                visual_features=["Tags", "Description"]
            )

            # Log the analysis result
            logger.info(f"Analysis completed for image: {image_url}")
            
            # Use the enhanced detection logic
            detection_result = await self.detect_image_content(analysis)
            
            # Log the final detection result                
            return detection_result
            
        except Exception as e:
            logger.error(f"Error analyzing image: {str(e)}")
            return {
                "content_type": "error",
                "confidence": 0,
                "description": f"Error analyzing image: {str(e)}",
                "legacy_message": "Error analyzing image"
            }