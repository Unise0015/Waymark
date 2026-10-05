"""
Plugin Parser Tests — Verify all tool output parsers handle real, empty, and malformed data.

These are the MOST IMPORTANT tests because parser bugs cause silent data loss.
A broken parser means the scan runs but Waymark never sees the results.
"""
import unittest
import json


class TestSubfinderParser(unittest.TestCase):
    """Test subfinder JSON line parser."""

    def setUp(self):
        from app.plugins.subfinder import SubfinderPlugin
        self.plugin = SubfinderPlugin()

    def test_parse_valid_single_line(self):
        raw = '{"host":"admin.example.com","source":"crtsh","input":"example.com"}\n'
        results = self.plugin.parse_output(raw)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["fqdn"], "admin.example.com")
        self.assertEqual(results[0]["source"], "crtsh")
        self.assertEqual(results[0]["_type"], "subdomain")

    def test_parse_multiple_lines(self):
        raw = (
            '{"host":"admin.example.com","source":"crtsh","input":"example.com"}\n'
            '{"host":"api.example.com","source":"dnsdumpster","input":"example.com"}\n'
            '{"host":"staging.example.com","source":"shodan","input":"example.com"}\n'
        )
        results = self.plugin.parse_output(raw)
        self.assertEqual(len(results), 3)
        fqdns = [r["fqdn"] for r in results]
        self.assertIn("admin.example.com", fqdns)
        self.assertIn("api.example.com", fqdns)
        self.assertIn("staging.example.com", fqdns)

    def test_parse_empty_output(self):
        self.assertEqual(self.plugin.parse_output(""), [])
        self.assertEqual(self.plugin.parse_output("\n\n"), [])

    def test_parse_malformed_lines_skipped(self):
        raw = 'not json at all\n{"host":"valid.example.com","source":"crtsh"}\nmore garbage\n'
        results = self.plugin.parse_output(raw)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["fqdn"], "valid.example.com")

    def test_parse_lowercases_fqdn(self):
        raw = '{"host":"ADMIN.Example.COM","source":"crtsh"}\n'
        results = self.plugin.parse_output(raw)
        self.assertEqual(results[0]["fqdn"], "admin.example.com")

    def test_parse_missing_host_field(self):
        raw = '{"source":"crtsh","input":"example.com"}\n'
        results = self.plugin.parse_output(raw)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["fqdn"], "")  # Empty string from .get default


class TestHttpxParser(unittest.TestCase):
    """Test httpx JSON line parser."""

    def setUp(self):
        from app.plugins.httpx_plugin import HttpxPlugin
        self.plugin = HttpxPlugin()

    def test_parse_valid_output(self):
        data = {
            "input": "admin.example.com",
            "url": "https://admin.example.com",
            "status_code": 200,
            "title": "Admin Panel",
            "webserver": "nginx/1.24",
            "content_length": 12345,
            "tech": ["PHP/8.2", "WordPress"],
            "csp": "",
            "x-frame-options": "DENY",
        }
        raw = json.dumps(data) + "\n"
        results = self.plugin.parse_output(raw)
        self.assertEqual(len(results), 1)
        r = results[0]
        self.assertEqual(r["_type"], "subdomain_update")
        self.assertEqual(r["fqdn"], "admin.example.com")
        self.assertEqual(r["status_code"], 200)
        self.assertEqual(r["title"], "Admin Panel")
        self.assertIn("WordPress", r["technologies"])
        self.assertTrue(r["is_alive"])

    def test_parse_empty_output(self):
        self.assertEqual(self.plugin.parse_output(""), [])

    def test_parse_malformed_skipped(self):
        raw = 'broken json\n{"input":"ok.com","status_code":200}\n'
        results = self.plugin.parse_output(raw)
        self.assertEqual(len(results), 1)

    def test_parse_lowercases_fqdn(self):
        raw = json.dumps({"input": "API.Example.COM", "status_code": 200}) + "\n"
        results = self.plugin.parse_output(raw)
        self.assertEqual(results[0]["fqdn"], "api.example.com")

    def test_parse_missing_tech(self):
        raw = json.dumps({"input": "test.com", "status_code": 200}) + "\n"
        results = self.plugin.parse_output(raw)
        self.assertEqual(results[0]["technologies"], [])


class TestFfufParser(unittest.TestCase):
    """Test ffuf JSON parser (block format, not line-by-line)."""

    def setUp(self):
        from app.plugins.ffuf import FfufPlugin
        self.plugin = FfufPlugin()

    def test_parse_valid_output(self):
        data = {
            "results": [
                {
                    "url": "https://example.com/admin",
                    "status": 200,
                    "length": 4096,
                    "content-type": "text/html",
                    "input": {"FUZZ": "admin"},
                    "redirectlocation": "",
                },
                {
                    "url": "https://example.com/backup.zip",
                    "status": 200,
                    "length": 1048576,
                    "content-type": "application/zip",
                    "input": {"FUZZ": "backup.zip"},
                    "redirectlocation": "",
                },
            ]
        }
        raw = json.dumps(data)
        results = self.plugin.parse_output(raw)
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0]["_type"], "url")
        self.assertEqual(results[0]["full_url"], "https://example.com/admin")
        self.assertEqual(results[0]["status_code"], 200)
        self.assertEqual(results[0]["discovery_method"], "directory_fuzzing")
        self.assertEqual(results[0]["word"], "admin")
        self.assertEqual(results[1]["full_url"], "https://example.com/backup.zip")

    def test_parse_empty_results(self):
        raw = json.dumps({"results": []})
        results = self.plugin.parse_output(raw)
        self.assertEqual(len(results), 0)

    def test_parse_empty_string(self):
        self.assertEqual(self.plugin.parse_output(""), [])

    def test_parse_invalid_json(self):
        self.assertEqual(self.plugin.parse_output("not json"), [])

    def test_parse_missing_results_key(self):
        raw = json.dumps({"commandline": "ffuf ..."})
        results = self.plugin.parse_output(raw)
        self.assertEqual(len(results), 0)


class TestPluginBuildCommand(unittest.TestCase):
    """Test that plugins produce valid command arrays."""

    def test_subfinder_basic_command(self):
        from app.plugins.subfinder import SubfinderPlugin
        cmd = SubfinderPlugin().build_command("example.com", {})
        self.assertIn("subfinder", cmd)
        self.assertIn("-d", cmd)
        self.assertIn("example.com", cmd)
        self.assertIn("-json", cmd)

    def test_httpx_rate_limit_default(self):
        from app.plugins.httpx_plugin import HttpxPlugin
        cmd = HttpxPlugin().build_command("example.com", {})
        self.assertIn("httpx", cmd)
        self.assertIn("-rate-limit", cmd)
        self.assertIn("50", cmd)

    def test_ffuf_appends_fuzz(self):
        from app.plugins.ffuf import FfufPlugin
        cmd = FfufPlugin().build_command("https://example.com", {})
        # Should have FUZZ appended to URL
        url_arg_idx = cmd.index("-u") + 1
        self.assertIn("FUZZ", cmd[url_arg_idx])


if __name__ == "__main__":
    unittest.main()
