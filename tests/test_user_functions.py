import unittest
import json
import azure.functions as func
from functions import user_functions

class DummyRequest(func.HttpRequest):
    def __init__(self, method, url, headers=None, params=None, body=b""):
        super().__init__(method, url, headers or {}, params or {}, body)

class TestUserFunctions(unittest.TestCase):
    def test_method_not_allowed(self):
        req = DummyRequest("OPTIONS", "/api/user", params={})
        resp = user_functions.main(req)
        self.assertEqual(resp.status_code, 405)
        self.assertEqual(resp.get_body().decode(), "Method not allowed")

if __name__ == '__main__':
    unittest.main()
