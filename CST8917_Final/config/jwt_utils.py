import jwt
import datetime
import logging
import json
from azure.functions import HttpRequest, HttpResponse
from .azure_config import get_azure_config

config = get_azure_config()
JWT_SECRET = config["JWT_SECRET"]
JWT_ALGORITHM = config["JWT_ALGORITHM"]

def create_token(user_id: str) -> str:
    payload = {
        "user_id": user_id,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return token

def decode_token(token: str):
    """
    Decode a JWT token and return its payload.
    """
    logging.info("Starting token decoding.")
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        logging.debug(f"Token decoded successfully: {payload}")
        return payload
    except jwt.ExpiredSignatureError:
        logging.error("Token decoding failed: Token has expired.")
        return None
    except jwt.InvalidTokenError as e:
        logging.error(f"Token decoding failed: Invalid token. Error: {str(e)}")
        return None

def authenticate_user(req: HttpRequest, return_http_response: bool = True):
    """
    Validate the Authorization header, decode the token, and extract the user_id.
    Returns the user_id if successful. If validation fails:
      - Returns None if return_http_response is False.
      - Returns an HttpResponse if return_http_response is True.
    """
    logging.info("Validating token and extracting user_id.")
    auth_header = req.headers.get("Authorization")
    if not auth_header:
        logging.error("Authorization header is missing.")
        if return_http_response:
            return HttpResponse(
                json.dumps({"message": "Unauthorized"}), 
                status_code=401, 
                mimetype="application/json"
            )
        return None
    
    token = auth_header.split("Bearer ")[-1]
    payload = decode_token(token)
    if not payload:
        logging.error("Token decoding failed or token is invalid.")
        if return_http_response:
            return HttpResponse("Invalid token", status_code=401)
        return None
    
    user_id = payload.get("user_id")
    if not user_id:
        logging.error("Token payload does not contain user_id.")
        if return_http_response:
            return HttpResponse("Invalid token payload: user_id missing", status_code=401)
        return None
    
    return user_id

