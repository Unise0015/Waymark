import unittest
import ast


class TestPhase12Syntax(unittest.TestCase):
    """Verify all Phase 12 files parse correctly."""

    def test_rate_limiter_syntax(self):
        with open("app/middleware/rate_limiter.py", encoding="utf-8") as f:
            ast.parse(f.read())

    def test_security_headers_syntax(self):
        with open("app/middleware/security_headers.py", encoding="utf-8") as f:
            ast.parse(f.read())

    def test_middleware_init_syntax(self):
        with open("app/middleware/__init__.py", encoding="utf-8") as f:
            ast.parse(f.read())

    def test_validators_syntax(self):
        with open("app/utils/validators.py", encoding="utf-8") as f:
            ast.parse(f.read())

    def test_utils_init_syntax(self):
        with open("app/utils/__init__.py", encoding="utf-8") as f:
            ast.parse(f.read())

    def test_main_syntax(self):
        with open("app/main.py", encoding="utf-8") as f:
            ast.parse(f.read())


if __name__ == "__main__":
    unittest.main()
