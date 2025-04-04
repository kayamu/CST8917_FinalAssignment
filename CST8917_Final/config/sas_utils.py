from azure.storage.blob import BlobServiceClient, generate_blob_sas, BlobSasPermissions
from datetime import datetime, timedelta
from .azure_config import get_azure_config

import os
import urllib.parse
import hmac
import hashlib
import base64
import time

def generate_sas_url(container_name, blob_name):
    config = get_azure_config()
    blob_service_client = BlobServiceClient.from_connection_string(os.environ["AzureWebJobsStorage"])

    sas_token = generate_blob_sas(
        account_name=blob_service_client.account_name,
        container_name=container_name,
        blob_name=blob_name,
        account_key=blob_service_client.credential.account_key, 
        permission=BlobSasPermissions(read=True),
        expiry=datetime.utcnow() + timedelta(hours=1) 
    )

    url = f"https://{blob_service_client.account_name}.blob.core.windows.net/{container_name}/{blob_name}?{sas_token}"
    return url

def generate_sas_token(uri, key_name, key_value, expiry_in_seconds=3600):
    expiry = str(int(time.time() + expiry_in_seconds))
    encoded_uri = urllib.parse.quote_plus(uri)

    string_to_sign = encoded_uri + '\n' + expiry
    signed_hmac_sha256 = hmac.new(
        key=key_value.encode('utf-8'),
        msg=string_to_sign.encode('utf-8'),
        digestmod=hashlib.sha256
    ).digest()

    signature = urllib.parse.quote_plus(base64.b64encode(signed_hmac_sha256))
    token = f'SharedAccessSignature sr={encoded_uri}&sig={signature}&se={expiry}&skn={key_name}'
    return token