import importlib.util
from pathlib import Path
import unittest
from unittest.mock import Mock, patch
from requests.exceptions import SSLError

spec = importlib.util.spec_from_file_location("auto_checkin", Path(__file__).resolve().parents[1] / "tools" / "auto-checkin.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

class CheckinSecurityTests(unittest.TestCase):
    def test_login_verifies_tls_and_limits_time_for_both_routes(self):
        for proxy in [False, True]:
            with self.subTest(proxy=proxy), patch.object(module.requests, "post", return_value=Mock(status_code=200, headers={"Set-Cookie": "fixture"})) as post:
                self.assertEqual(module.login("https://fixture.invalid/login", {"email": "fixture"}, {}, 1, proxy), {"set-cookie": "fixture"})
                self.assertTrue(post.call_args.kwargs.get("verify", True))
                self.assertEqual(post.call_args.kwargs["timeout"], (10, 30))
    def test_checkin_uses_already_decoded_json_and_secure_requests(self):
        for proxy in [False, True]:
            response = Mock(status_code=200, headers={"Content-Encoding": "br"})
            response.json.return_value = {"msg": "fixture"}
            with self.subTest(proxy=proxy), patch.object(module.requests, "post", return_value=response) as post:
                module.checkin("https://fixture.invalid/checkin", {}, 1, proxy)
                response.json.assert_called_once()
                self.assertTrue(post.call_args.kwargs.get("verify", True))
                self.assertEqual(post.call_args.kwargs["timeout"], (10, 30))
    def test_invalid_certificate_does_not_produce_login_credentials(self):
        with patch.object(module.requests, "post", side_effect=SSLError("fixture certificate failure")) as post:
            self.assertEqual(module.login("https://fixture.invalid/login", {}, {}, 1, True), {})
            post.assert_called_once()
    def test_logout_limits_request_time(self):
        with patch.object(module.requests, "get", return_value=Mock(status_code=200)) as get:
            self.assertEqual(module.logout("https://fixture.invalid/logout", {}), 0)
            self.assertEqual(get.call_args.kwargs["timeout"], (10, 30))

if __name__ == "__main__":
    unittest.main()
