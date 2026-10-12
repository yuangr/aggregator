import ast
from datetime import datetime, timedelta, timezone
import http.server
from pathlib import Path
import ssl
from tempfile import TemporaryDirectory
import threading
import unittest
import urllib.error
import urllib.request

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

ROOT = Path(__file__).resolve().parents[1]
FILES = [".github/actions/checkin/universal.py", "subscribe/clash.py", "subscribe/utils.py", "tools/clean.py", "tools/filter.py", "tools/renewal.py", "tools/scaner.py", "tools/xui.py"]

def actual_context(path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    setup = []
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == "CTX" or isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name) and target.value.id == "CTX" for target in node.targets):
            setup.append(node)
    namespace = {"ssl": ssl}
    exec(compile(ast.Module(body=setup, type_ignores=[]), str(path), "exec"), namespace)
    return namespace["CTX"]

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"fixture-ok")
    def log_message(self, *args):
        pass

class TLSContextSecurityTests(unittest.TestCase):
    def test_actual_contexts_accept_trusted_and_reject_untrusted_or_wrong_host(self):
        with TemporaryDirectory() as directory:
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
            now = datetime.now(timezone.utc)
            cert = x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=1)).add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False).sign(key, hashes.SHA256())
            certfile = Path(directory) / "cert.pem"
            keyfile = Path(directory) / "key.pem"
            certfile.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
            keyfile.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
            server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(certfile, keyfile)
            server.socket = context.wrap_socket(server.socket, server_side=True)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                for filename in FILES:
                    for trusted, host in ((False, "localhost"), (True, "localhost"), (True, "127.0.0.1")):
                        with self.subTest(file=filename, trusted=trusted, host=host):
                            client = actual_context(ROOT / filename)
                            if trusted:
                                client.load_verify_locations(cafile=str(certfile))
                            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=client))
                            if trusted and host == "localhost":
                                with opener.open(f"https://{host}:{server.server_port}/", timeout=5) as response:
                                    self.assertEqual(response.read(), b"fixture-ok")
                            else:
                                with self.assertRaises(urllib.error.URLError) as error:
                                    opener.open(f"https://{host}:{server.server_port}/", timeout=5)
                                self.assertIsInstance(error.exception.reason, ssl.SSLCertVerificationError)
            finally:
                server.shutdown()
                thread.join(timeout=5)
                server.server_close()

if __name__ == "__main__":
    unittest.main()
