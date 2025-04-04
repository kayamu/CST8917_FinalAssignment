import os
import logging
import azure.functions as func
from functions import user_functions, device_functions, telemetry_functions, conditions
from scheduled.trigger_functions import scheduled_cleanup

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

@app.function_name(name="CreateAdminUser")
@app.route(route="user/admin", methods=["POST"])
def CreateAdminUser(req: func.HttpRequest) -> func.HttpResponse:
    # Dispatch the request to the create_admin_user function in user_functions.py
    return user_functions.create_admin_user(req)

@app.function_name(name="GetUsers")
@app.route(route="users", methods=["GET"])
def GetUsers(req: func.HttpRequest) -> func.HttpResponse:
    # Dispatch the request to the get_users function in user_functions.py
    return user_functions.get_users(req)

@app.function_name(name="ConditionsFunctions")
@app.route(route="conditions", methods=["POST", "GET", "PUT", "DELETE"])
def ConditionsManagement(req: func.HttpRequest) -> func.HttpResponse:
    return conditions.main(req)

@app.function_name(name="ScheduledCleanup")
@app.schedule(schedule="0 0 0 * * *", arg_name="mytimer", run_on_startup=False, use_monitor=True)
def ScheduledCleanup(mytimer: func.TimerRequest):
    """
    This function is triggered every hour (cron schedule: "0 0 * * * *").
    It performs cleanup of old images from blob storage and updates MongoDB.
    """
    logging.info("Scheduled cleanup function triggered.")
    scheduled_cleanup(mytimer)