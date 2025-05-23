import os
import logging
import azure.functions as func
from functions import condition_functions
from functions import user_functions, device_functions, telemetry_functions, alertlogs
from scheduled.trigger_functions import scheduled_cleanup
from listeners.servicebus_listener import ServiceBusListener
from functions import admin_functions
from listeners.blobstorage_listener import BlobListener

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)

@app.function_name(name="Ping")
@app.route(route="ping", methods=["GET"])
def Ping(req: func.HttpRequest) -> func.HttpResponse:
    return func.HttpResponse("Function App is running", status_code=200)


@app.function_name(name="SwaggerYaml")
@app.route(route="swagger", methods=["GET"])
def SwaggerYaml(req: func.HttpRequest) -> func.HttpResponse:
    try:
        yaml_path = os.path.join(os.getcwd(), 'swagger', 'swagger.yaml')
        with open(yaml_path, 'r') as file:
            return func.HttpResponse(file.read(), mimetype='application/x-yaml', status_code=200)
    except Exception as ex:
        return func.HttpResponse(f"Error loading YAML: {str(ex)}", status_code=500)

@app.function_name(name="SwaggerUI")
@app.route(route="swagger-ui", methods=["GET"])
def SwaggerUI(req: func.HttpRequest) -> func.HttpResponse:
    try:
        html_path = os.path.join(os.getcwd(), 'static', 'index.html')
        with open(html_path, 'r') as file:
            return func.HttpResponse(file.read(), mimetype='text/html', status_code=200)
    except Exception as ex:
        return func.HttpResponse(f"Error loading Swagger UI: {str(ex)}", status_code=500)

@app.function_name(name="UserFunctions")
@app.route(route="user", methods=["POST", "GET", "PUT", "PATCH", "DELETE"])
def UserManagement(req: func.HttpRequest) -> func.HttpResponse:
    # Dispatch the request to the main function in user_functions.py
    return user_functions.main(req)

@app.function_name(name="LoginUser")
@app.route(route="user/login", methods=["POST"])
def LoginUser(req: func.HttpRequest) -> func.HttpResponse:
    # Dispatch the request to the login_user function in user_functions.py
    return user_functions.login_user(req)


@app.function_name(name="DeviceFunctions")
@app.route(route="devices", methods=["GET"])
def DeviceManagement(req: func.HttpRequest) -> func.HttpResponse:
    # Dispatch the request to the main function in device_functions.py
    return device_functions.main(req)

@app.function_name(name="DeviceFunction")
@app.route(route="device", methods=["POST", "PUT", "PATCH", "DELETE"])
def DeviceManagement(req: func.HttpRequest) -> func.HttpResponse:
    # Dispatch the request to the main function in device_functions.py
    return device_functions.main(req)

@app.function_name(name="TelemetryFunctions")
@app.route(route="telemetry", methods=["POST", "GET", "DELETE"])
def TelemetryManagement(req: func.HttpRequest) -> func.HttpResponse:
    # Dispatch the request to the main function in telemetry_functions.py
    return telemetry_functions.main(req)


@app.function_name(name="ConditionsFunctions")
@app.route(route="conditions", methods=["POST", "GET", "PUT", "DELETE"])
def ConditionsManagement(req: func.HttpRequest) -> func.HttpResponse:
    return condition_functions.main(req)

@app.function_name(name="AlertLogsFunctions")
@app.route(route="alertlogs", methods=["GET", "DELETE"])
def AlertLogsManagement(req: func.HttpRequest) -> func.HttpResponse:
    """
    Dispatch the request to the main function in alertlogs.py.
    """
    return alertlogs.main(req)

@app.function_name(name="ScheduledCleanup")
@app.schedule(schedule="0 0 0 * * *", arg_name="mytimer", run_on_startup=False, use_monitor=True)
def ScheduledCleanup(mytimer: func.TimerRequest):
    """
    This function is triggered daily at midnight (cron schedule: "0 0 0 * * *").
    It performs cleanup of old images from blob storage and updates MongoDB.
    """
    logging.info("Scheduled cleanup function triggered.")
    scheduled_cleanup(mytimer)

@app.function_name(name="ServiceBusListenerFunction")
@app.service_bus_queue_trigger(
    arg_name="msg",
    queue_name="cst8922servicebusqueue",  # Queue name from azure_config.py
    connection="SERVICE_BUS_CONNECTION_STRING"  # Connection string from azure_config.py
)
def ServiceBusListenerFunction(msg: str):
    """
    Azure Function triggered by a Service Bus Queue message.
    Processes incoming telemetry data messages.
    """
    logging.info("Service Bus Listener Function triggered.")
    try:
        # Decode the message body
        message_body = msg  # msg is already a string
        logging.info(f"Message received")

        # Pass the message to the ServiceBusListener for processing
        listener = ServiceBusListener()
        listener.main(message_body)
    except Exception as e:
        logging.exception(f"Failed to process Service Bus message: {str(e)}")


@app.function_name(name="GetUsers")
@app.route(route="manage/users", methods=["GET"])
def GetUsers(req: func.HttpRequest) -> func.HttpResponse:
    """
    Admin endpoint to retrieve user information.
    """
    return admin_functions.get_users(req)

@app.function_name(name="ChangeUserType")
@app.route(route="manage/change-user-type", methods=["PUT"])
def ChangeUserType(req: func.HttpRequest) -> func.HttpResponse:
    """
    Admin endpoint to change a user's type (e.g., to admin).
    """
    return admin_functions.change_user_type(req)

@app.function_name(name="CreateAdminUser")
@app.route(route="manage/create-admin", methods=["POST"])
def CreateAdminUser(req: func.HttpRequest) -> func.HttpResponse:
    """
    Endpoint to create an admin user account.
    """
    return admin_functions.create_admin_user(req)

@app.function_name(name="ListProcessedImages")
@app.route(route="manage/processed-images", methods=["GET"])
def ListProcessedImages(req: func.HttpRequest) -> func.HttpResponse:
    """
    Admin endpoint to list processed images from blob storage.
    """
    return admin_functions.list_processed_images(req)

@app.function_name(name="TransferDevice")
@app.route(route="manage/transfer-device", methods=["POST"])
def TransferDevice(req: func.HttpRequest) -> func.HttpResponse:
    """
    Admin endpoint to transfer a device from one user to another.
    """
    return admin_functions.transfer_device(req)

@app.function_name(name="BlobTriggerListener")
@app.blob_trigger(
    arg_name="myblob",
    path="telemetry-images/{name}",
    connection="AzureWebJobsStorage"
)
async def BlobTriggerListener(myblob: func.InputStream):
    """
    Azure Function triggered by a new blob upload in the telemetry-images container.
    Processes uploaded images for content analysis and alerting.
    """
    blob_name = myblob.name.split('/')[-1]  # Extract the filename
    logger.info(f"Blob Trigger Function triggered for blob: {blob_name}")
    try:
        listener = BlobListener()
        await listener.process_blob(myblob, blob_name)
    except Exception as e:
        logger.exception(f"Failed to process blob {blob_name}: {str(e)}")