import logging
from azure.cognitiveservices.vision.computervision import ComputerVisionClient
from msrest.authentication import CognitiveServicesCredentials
from config.azure_config import get_azure_config

def analyze_image_for_fire(image_url: str) -> str:
    # Get Azure Cognitive Service configuration
    config = get_azure_config()
    endpoint = config["COGNITIVE_SERVICE_ENDPOINT"]
    subscription_key = config["COGNITIVE_SERVICE_KEY"]

    # Create a Computer Vision Client
    client = ComputerVisionClient(endpoint, CognitiveServicesCredentials(subscription_key))

    # Analyze the image
    analysis = client.analyze_image(
        image_url,
        visual_features=["Tags", "Description"]  # İkili analiz
    )

    # Log the analysis result
    logging.info(f"Analysis result: {analysis.as_dict()}")  # Log the full analysis result as a dictionary

    if hasattr(analysis, 'tags'):
        for tag in analysis.tags:
            if "fire" in tag.name.lower() and tag.confidence > 0.5:  # Daha düşük eşik
                return "Fire detected (Tags)"    

    # Check if the analysis contains a description
    if analysis.description and analysis.description.captions:
        for caption in analysis.description.captions:
            logging.info(f"Caption: {caption.text}, Confidence: {caption.confidence}")
            if "fire" in caption.text.lower() and caption.confidence > 0.8:
                return "Fire detected!"
    
    # If no captions or no fire detected
    return "No fire detected."