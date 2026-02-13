import unittest

from app.scanners.web_scanner.rules.header_rules import evaluate_headers
from app.scanners.web_scanner.rules.cache_rules import evaluate_cache
from app.scanners.web_scanner.rules.redirect_rules import evaluate_redirect
from app.scanners.web_scanner.rules.tls_rules import evaluate_tls


class RuleTests(unittest.TestCase):
    def test_missing_headers(self):
        findings = evaluate_headers({})
        self.assertIn("headersContentSecurityPolicy", findings)
        self.assertIn("headersStrictTransportSecurity", findings)

    def test_cache_rules(self):
        vuln = evaluate_cache({"cache-control": "", "pragma": "", "expires": ""})
        self.assertEqual(vuln, "cacheHttpsResponse")

    def test_redirect_rules(self):
        self.assertEqual(evaluate_redirect(None), "lackingRedirectHttpHttps")
        self.assertIsNone(evaluate_redirect("https://example.com"))

    def test_tls_rules(self):
        findings = evaluate_tls({"tls_version": "TLSv1.0", "is_wildcard": True})
        self.assertIn("httpsCertificateVersion", findings)
        self.assertIn("wildcardTLSCertificate", findings)


if __name__ == "__main__":
    unittest.main()
