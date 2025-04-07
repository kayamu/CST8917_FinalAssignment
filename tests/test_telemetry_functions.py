import unittest
import json
import azure.functions as func
from functions import telemetry_functions

class DummyRequest(func.HttpRequest):
    def __init__(self, method, url, headers=None, params=None, body=b"", form=None, files=None):
        super().__init__(method, url, headers or {}, params or {}, body)
        self._form = form or {}
        self._files = files or {}

    @property
    def form(self):
        return self._form

    @property
    def files(self):
        return self._files

class TestTelemetryFunctions(unittest.TestCase):
    def test_method_not_allowed(self):
        req = DummyRequest("PUT", "/api/telemetry")
        resp = telemetry_functions.main(req)
        self.assertEqual(resp.status_code, 405)
        self.assertEqual(resp.get_body().decode(), "Method not allowed")

if __name__ == '__main__':
    unittest.main()
