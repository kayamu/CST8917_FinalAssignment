import logging
from azure.eventgrid import EventGridPublisherClient, EventGridEvent
from azure.core.credentials import AzureKeyCredential
from config.azure_config import get_azure_config

config = get_azure_config()

eventgrid_client = EventGridPublisherClient(
    config["EVENTGRID_TOPIC_ENDPOINT"],
    AzureKeyCredential(config["EVENTGRID_TOPIC_KEY"])
)

def forward_event(event_data: dict):
    """
    Forwards the given event data to Azure Event Grid.
    """
    try:
        logging.info(f"[forward_event] Preparing to forward event for device_id: {event_data.get('device_id')}")
        event = EventGridEvent(
            subject=f"Device/{event_data.get('device_id')}",
            data=event_data,
            event_type="IoT.DeviceTelemetry",
            data_version="1.0"
        )
        eventgrid_client.send([event])
        logging.info(f"[forward_event] Successfully forwarded event for device: {event_data.get('device_id')}")
    except Exception as e:
        logging.exception(f"[forward_event] Failed to forward event: {e}")
        raise e
