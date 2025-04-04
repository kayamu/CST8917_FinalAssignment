import logging
import json
from azure_services.cognitive_serivce import analyze_image_for_fire
from azure_services.eventtopic_service import forward_event

def main(event: str):
    logging.info("Blob Storage event received.")
    
    # Parse the Event Grid event
    event_data = json.loads(event)
    blob_url = event_data["data"]["url"]  # Get the blob URL from the event
    logging.info(f"Blob URL: {blob_url}")
    
    # Analyze the image for fire
    fire_detection_result = analyze_image_for_fire(blob_url)
    # Log the fire detection result with color coding for terminal output
    if fire_detection_result.get("Fire detected (Tags)", False):
        logging.error(f"\033[91mFire detected: {fire_detection_result}\033[0m")  # Red for fire detected
    else:
        logging.info(f"\033[92mNo fire detected: {fire_detection_result}\033[0m")  # Green for no fire detected
    
    # Forward the result to Event Grid
    forward_event({
        "blob_url": blob_url,
        "fire_detection_result": fire_detection_result
    })