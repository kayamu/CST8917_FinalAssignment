import unittest
import json
import azure.functions as func
from functions import device_functions

class DummyRequest(func.HttpRequest):
    def __init__(self, method, url, headers=None, params=None, body=b""):
        super().__init__(method, url, headers or {}, params or {}, body)

class TestDeviceFunctions(unittest.TestCase):
    def test_method_not_allowed(self):
        req = DummyRequest("HEAD", "/api/device")
        resp = device_functions.main(req)
        self.assertEqual(resp.status_code, 405)
        body = json.loads(resp.get_body().decode())
        self.assertIn("message", body)

if __name__ == '__main__':
    unittest.main()
