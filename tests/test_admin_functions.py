import unittest
import json
import azure.functions as func
from functions import admin_functions

# Dummy HttpRequest for testing
class DummyRequest(func.HttpRequest):
    def __init__(self, method, url, headers=None, params=None, body=b""):
        super().__init__(method, url, headers or {}, params or {}, body)

class TestAdminFunctions(unittest.TestCase):
    def test_missing_method(self):
        req = DummyRequest("GET", "/api/admin", params={})
        resp = admin_functions.main(req)
        self.assertEqual(resp.status_code, 400)
        body = json.loads(resp.get_body().decode())
        self.assertEqual(body["message"], "Method not specified")

    def test_invalid_method(self):
        req = DummyRequest("GET", "/api/admin", params={"method": "INVALID"})
        resp = admin_functions.main(req)
        self.assertEqual(resp.status_code, 400)
        body = json.loads(resp.get_body().decode())
        self.assertEqual(body["message"], "Invalid method")

if __name__ == '__main__':
    unittest.main()
