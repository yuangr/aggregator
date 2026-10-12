import ast
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]

def load_function(path, name, namespace):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == name)
    exec(compile(ast.Module(body=[node], type_ignores=[]), str(path), "exec"), namespace)
    return namespace[name]

# Run the actual pure parsing function and actual blank predicate without importing
# the unrelated collector modules or starting network/subprocess resources.
isblank = load_function(ROOT / "subscribe/utils.py", "isblank", {})
path = ROOT / "subscribe/crawl/helpers.py"
if not path.exists():
    path = ROOT / "subscribe/crawl.py"
is_expired = load_function(path, "is_expired", {"utils": SimpleNamespace(isblank=isblank), "time": time})

class SubscriptionHeaderSecurityTests(unittest.TestCase):
    def test_header_cannot_execute_for_any_numeric_field(self):
        for field in ("upload", "download", "total", "expire"):
            with self.subTest(field=field), TemporaryDirectory() as directory:
                marker = Path(directory) / "executed.txt"
                attack = "__import__('pathlib').Path(" + repr(str(marker)) + ").write_text('executed')"
                values = {"upload": "0", "download": "0", "total": "8589934592", "expire": ""}
                values[field] = attack
                header = "; ".join(f"{key}={value}" for key, value in values.items())
                self.assertEqual(is_expired(header), (True, False))
                self.assertFalse(marker.exists(), "Untrusted header executed code")
    def test_numeric_header_preserves_quota_and_expiration(self):
        self.assertEqual(is_expired("upload=1024; download=2048; total=8589934592; expire=", remain=1), (True, False))
        self.assertEqual(is_expired("upload=1024; download=2048; total=4096; expire=1", remain=1), (False, True))
    def test_unknown_metadata_is_ignored(self):
        self.assertEqual(is_expired("label=not-a-number; total=8589934592", remain=1), (True, False))
    def test_malformed_header_retains_existing_fallback(self):
        for value in ("nope", "1024*1024", "1.5"):
            with self.subTest(value=value):
                self.assertEqual(is_expired("total=" + value), (True, False))

if __name__ == "__main__":
    unittest.main()
