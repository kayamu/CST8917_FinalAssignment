import logging
from config.azure_config import get_azure_config
from pymongo import MongoClient


class CosmosDBService:
    def __init__(self):
        try:
            config = get_azure_config()
            client = MongoClient(config["COSMOS_DB_CONNECTION_STRING"])
            self.db = client[config["COSMOS_DB_NAME"]]
            self.default_collection_name = config["COLLECTION_NAME"]  # Default collection name
            logging.info("[CosmosDBService] MongoDB database initialized successfully.")
        except Exception as ex:
            logging.exception("[CosmosDBService] MongoDB database initialization failed.")
            raise ex

    def insert_document(self, document: dict, collection_name: str = None):
        collection_name = collection_name or self.default_collection_name
        collection = self.db[collection_name]
        return collection.insert_one(document)

    def find_document(self, query: dict, collection_name: str = None):
        collection_name = collection_name or self.default_collection_name
        collection = self.db[collection_name]
        return collection.find_one(query)

    def update_document(self, query: dict, update: dict, collection_name: str = None):
        collection_name = collection_name or self.default_collection_name
        collection = self.db[collection_name]
        return collection.update_one(query, update)

    def delete_document(self, query: dict, collection_name: str = None):
        collection_name = collection_name or self.default_collection_name
        collection = self.db[collection_name]
        return collection.delete_one(query)

    def find_documents(self, query: dict, collection_name: str = None):
        collection_name = collection_name or self.default_collection_name
        collection = self.db[collection_name]
        return list(collection.find(query))