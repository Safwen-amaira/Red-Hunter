import unittest
from src.detection.engine import DetectionEngine

class TestDetectionEngine(unittest.TestCase):
    def setUp(self):
        self.engine = DetectionEngine(config_path="config/waf-config.yaml")

    def test_sqli_detection(self):
        malicious = {
            "url": "/search?q=1' OR 1=1--",
            "body": "",
            "headers": {}
        }
        result = self.engine.analyze(malicious)
        self.assertEqual(result["action"], "block")

    def test_xss_detection(self):
        malicious = {
            "url": "/",
            "body": "<script>alert(1)</script>",
            "headers": {}
        }
        result = self.engine.analyze(malicious)
        self.assertEqual(result["action"], "block")

if __name__ == "__main__":
    unittest.main()