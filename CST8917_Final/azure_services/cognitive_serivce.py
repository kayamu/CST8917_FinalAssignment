import logging
from azure.cognitiveservices.vision.computervision import ComputerVisionClient
from msrest.authentication import CognitiveServicesCredentials
from config.azure_config import get_azure_config

def analyze_image(image_url: str) -> str:
    # Get Azure Cognitive Service configuration
    config = get_azure_config()
    endpoint = config["COGNITIVE_SERVICE_ENDPOINT"]
    subscription_key = config["COGNITIVE_SERVICE_KEY"]

    # Create a Computer Vision Client
    client = ComputerVisionClient(endpoint, CognitiveServicesCredentials(subscription_key))

    # Analyze the image
    analysis = client.analyze_image(
        image_url,
        visual_features=["Tags", "Description"]
    )

    # Log the analysis result
    logging.info(f"Analysis result: {analysis.as_dict()}")

    # Initialize detection flags
    fire_detected = False
    human_detected = False

    # Check tags for fire and humans
    if hasattr(analysis, 'tags'):
        for tag in analysis.tags:
            tag_name = tag.name.lower()
            # Check for fire
            if "fire" in tag_name and tag.confidence > 0.5:
                fire_detected = True
            # Check for humans
            if any(human_term in tag_name for human_term in ["person", "human", "people", "man", "woman", "child"]) and tag.confidence > 0.5:
                human_detected = True

    # Check descriptions for fire and humans
    if analysis.description and analysis.description.captions:
        for caption in analysis.description.captions:
            caption_text = caption.text.lower()
            logging.info(f"Caption: {caption.text}, Confidence: {caption.confidence}")
            # Check for fire in caption
            if "fire" in caption_text and caption.confidence > 0.8:
                fire_detected = True
            # Check for humans in caption
            if any(human_term in caption_text for human_term in ["person", "human", "people", "man", "woman", "child"]) and caption.confidence > 0.8:
                human_detected = True

    # Return detection results
    if fire_detected and human_detected:
        return "Fire and human detected!"
    elif fire_detected:
        return "Fire detected!"
    elif human_detected:
        return "Human detected!"
    else:
        return "No fire or human detected."