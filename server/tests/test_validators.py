"""
Input Validation Tests — Ensure domain names, URLs, and patterns are properly sanitized.
"""
import unittest


class TestDomainValidation(unittest.TestCase):
    def setUp(self):
        from app.utils.validators import validate_domain
        self.validate = validate_domain

    def test_valid_domain(self):
        ok, result = self.validate("example.com")
        self.assertTrue(ok)
        self.assertEqual(result, "example.com")

    def test_valid_subdomain(self):
        ok, result = self.validate("admin.staging.example.com")
        self.assertTrue(ok)

    def test_valid_wildcard(self):
        ok, result = self.validate("*.example.com")
        self.assertTrue(ok)

    def test_strips_whitespace(self):
        ok, result = self.validate("  example.com  ")
        self.assertTrue(ok)
        self.assertEqual(result, "example.com")

    def test_lowercases(self):
        ok, result = self.validate("EXAMPLE.COM")
        self.assertTrue(ok)
        self.assertEqual(result, "example.com")

    def test_rejects_empty(self):
        ok, _ = self.validate("")
        self.assertFalse(ok)

    def test_rejects_command_injection(self):
        ok, _ = self.validate("example.com; rm -rf /")
        self.assertFalse(ok)

    def test_rejects_pipe_injection(self):
        ok, _ = self.validate("example.com | cat /etc/passwd")
        self.assertFalse(ok)

    def test_rejects_backtick_injection(self):
        ok, _ = self.validate("`whoami`.example.com")
        self.assertFalse(ok)

    def test_rejects_too_long(self):
        ok, _ = self.validate("a" * 300 + ".com")
        self.assertFalse(ok)

    def test_strips_protocol(self):
        ok, result = self.validate("https://example.com")
        self.assertTrue(ok)
        self.assertEqual(result, "example.com")


class TestURLValidation(unittest.TestCase):
    def setUp(self):
        from app.utils.validators import validate_url
        self.validate = validate_url

    def test_valid_https(self):
        ok, _ = self.validate("https://example.com/path")
        self.assertTrue(ok)

    def test_valid_http(self):
        ok, _ = self.validate("http://example.com")
        self.assertTrue(ok)

    def test_rejects_empty(self):
        ok, _ = self.validate("")
        self.assertFalse(ok)

    def test_rejects_dangerous_chars(self):
        ok, _ = self.validate("https://example.com/path; rm -rf /")
        self.assertFalse(ok)

    def test_rejects_too_long(self):
        ok, _ = self.validate("https://example.com/" + "a" * 2100)
        self.assertFalse(ok)


class TestSanitizeForCommand(unittest.TestCase):
    def setUp(self):
        from app.utils.validators import sanitize_for_command
        self.sanitize = sanitize_for_command

    def test_removes_semicolons(self):
        self.assertEqual(self.sanitize("example.com;ls"), "example.comls")

    def test_removes_pipes(self):
        self.assertEqual(self.sanitize("test|cat"), "testcat")

    def test_removes_backticks(self):
        self.assertEqual(self.sanitize("`whoami`"), "whoami")

    def test_preserves_clean_input(self):
        self.assertEqual(self.sanitize("admin.example.com"), "admin.example.com")


if __name__ == "__main__":
    unittest.main()
