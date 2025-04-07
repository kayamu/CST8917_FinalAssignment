import unittest
import json
from functions import image_functions

class TestImageFunctions(unittest.TestCase):
    def test_main_event(self):
        # Dummy Event Grid event
        event = json.dumps({
            "data": {"url": "https://dummy.blob.core.windows.net/container/dummy.jpg"}
        })
        try:
            image_functions.main(event)
        except Exception as e:
            self.fail(f"main() raised Exception unexpectedly: {e}")

if __name__ == '__main__':
    unittest.main()
