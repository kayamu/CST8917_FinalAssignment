import unittest
import json
import azure.functions as func
from functions import conditions

class DummyRequest(func.HttpRequest):
    def __init__(self, method, url, headers=None, params=None, body=b""):
        super().__init__(method, url, headers or {}, params or {}, body)

class TestConditions(unittest.TestCase):
    def test_unsupported_method(self):
        req = DummyRequest("PATCH", "/api/conditions", body=b'{}')
        resp = conditions.main(req)
        self.assertEqual(resp.status_code, 405)
        body = json.loads(resp.get_body().decode())
        self.assertIn("error", body)

if __name__ == '__main__':
    unittest.main()
