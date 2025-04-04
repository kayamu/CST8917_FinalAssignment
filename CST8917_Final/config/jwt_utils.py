import jwt
import datetime
import logging
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

def authenticate_user(req: HttpRequest):
    """
    Authenticate the user using the Authorization header.
    """
    logging.info("Starting user authentication.")
    try:
        # Get the Authorization header
        token = req.headers.get("Authorization")
        if not token:
            logging.error("Authorization header is missing.")
            return None
        logging.debug(f"Authorization header received: {token}")

        # Extract the token from the "Bearer" scheme
        if token.startswith("Bearer "):
            token = token.split(" ")[1]
        else:
            logging.error("Authorization header is invalid. Missing 'Bearer' prefix.")
            return None
        logging.debug(f"Extracted token: {token}")

        # Decode the token and extract user_id
        logging.info("Decoding the token.")
        decoded_token = decode_token(token)
        if not decoded_token:
            logging.error("Token decoding failed or token is invalid.")
            return None
        logging.debug(f"Decoded token: {decoded_token}")

        user_id = decoded_token.get("user_id")
        if not user_id:
            logging.error("Invalid token: user_id is missing.")
            return None
        logging.info(f"Authentication successful for user_id={user_id}.")

        return user_id
    except Exception as e:
        logging.error(f"Authentication failed due to an exception: {str(e)}")
        return None

