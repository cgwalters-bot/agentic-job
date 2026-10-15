"""Tests for policy.py, against the real policy.toml:
python3 -m unittest discover -s agent/egress"""

import os
import tempfile
import unittest

from policy import MAX_ALLOWED_DOMAINS, Policy, WriteRule, glob_regex, normalize_host

HERE = os.path.dirname(os.path.abspath(__file__))


class PolicyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
            f.write("# a feed\nevil.example\nbad.test # trailing comment\n\n")
        cls.policy = Policy.load(os.path.join(HERE, "policy.toml"), f.name)
        os.unlink(f.name)

    def test_requests(self):
        # (method, host, path, extra keyword arguments, allowed)
        cases = [
            ("GET", "index.crates.io", "/se/rd/serde", {}, True),
            ("HEAD", "static.crates.io", "/crates/x/x-1.0.0.crate", {}, True),
            ("OPTIONS", "example.com", "/", {}, True),
            ("GET", "anything.example.org", "/?q=1", {}, True),
            ("GET", "GitHub.com.", "/", {}, True),
            # writes only where policy.toml lists them
            ("POST", "github.com", "/bootc-dev/bootc/git-upload-pack", {}, True),
            ("POST", "github.com", "/bootc-dev/bootc.git/git-upload-pack", {}, True),
            ("POST", "github.com", "/bootc-dev/bootc.git/git-upload-pack?x=1", {}, True),
            ("POST", "github.com", "/bootc-dev/bootc.git/git-receive-pack", {}, False),
            ("POST", "evil.github.com", "/a/b/git-upload-pack", {}, False),
            ("POST", "example.com", "/a/b/git-upload-pack", {}, False),
            ("PUT", "github.com", "/a/b/git-upload-pack", {}, False),
            ("POST", "registry.npmjs.org", "/-/npm/v1/security/advisories/bulk", {}, True),
            ("POST", "registry.npmjs.org", "/-/npm/v1/security/advisories/bulk/x", {}, False),
            ("PUT", "registry.npmjs.org", "/some-package", {}, False),
            # gh's reads; the read-only token is what refuses a mutation
            ("GET", "api.github.com", "/repos/a/b/pulls/1/comments?per_page=100", {}, True),
            ("GET", "api.github.com", "/repos/a/b/pulls/1/reviews", {}, True),
            ("POST", "api.github.com", "/graphql", {}, True),
            ("POST", "api.github.com", "/graphql/x", {}, False),
            ("POST", "github.com", "/graphql", {}, False),
            ("POST", "api.github.com", "/repos/a/b/issues/1/comments", {}, False),
            ("POST", "api.github.com", "/repos/a/b/pulls/1/comments", {}, False),
            ("PATCH", "api.github.com", "/repos/a/b/issues/1", {}, False),
            ("PUT", "api.github.com", "/graphql", {}, False),
            ("DELETE", "example.com", "/", {}, False),
            ("PATCH", "example.com", "/", {}, False),
            # reads that carry data are writes
            ("GET", "example.com", "/", {"has_body": True}, False),
            ("GET", "github.com", "/", {"websocket": True}, False),
            # the threat feed covers subdomains, for reads too
            ("GET", "evil.example", "/", {}, False),
            ("GET", "a.b.Evil.Example", "/", {}, False),
            ("GET", "bad.test", "/", {}, False),
            ("GET", "notevil.example", "/", {}, True),
            # domain fronting
            ("GET", "github.com", "/", {"host_header": "github.com:443"}, True),
            ("GET", "github.com", "/", {"host_header": "evil.example.org"}, False),
            ("GET", "github.com", "/", {"sni": "github.com"}, True),
            ("GET", "github.com", "/", {"sni": "other.example.org"}, False),
            ("GET", "::1", "/", {"host_header": "[::1]:8080"}, True),
        ]
        for method, host, path, extra, allowed in cases:
            with self.subTest(method=method, host=host, path=path, **extra):
                d = self.policy.request(method=method, host=host, path=path, **extra)
                self.assertEqual(d.allowed, allowed, d.reason)

    def test_connect(self):
        self.assertTrue(self.policy.connect("github.com").allowed)
        self.assertFalse(self.policy.connect("x.evil.example").allowed)

    def load_text(self, text):
        with tempfile.NamedTemporaryFile("w", suffix=".toml") as f:
            f.write(text)
            f.flush()
            return Policy.load(f.name)

    def test_allowlist(self):
        policy = self.load_text('[egress]\nmode = "allowlist"\nallow = ["Example.COM."]\n')
        policy.denylist = frozenset({"evil.example.com"})
        policy.writes = self.policy.writes
        for host, allowed in [
            ("example.com", True), ("A.Example.COM.:443", True),
            ("notexample.com", False), ("example.com.attacker.test", False),
            ("other.test", False), ("evil.example.com", False),
            ("sub.evil.example.com", False), ("192.0.2.1", False),
            ("[2001:db8::1]:443", False), ("::1", False),
        ]:
            with self.subTest(host=host):
                self.assertEqual(policy.connect(host).allowed, allowed)
                for method in ("GET", "HEAD", "OPTIONS"):
                    self.assertEqual(policy.request(method=method, host=host, path="/").allowed, allowed)
        for extra in ({"host_header": "other.test"}, {"sni": "other.test"}, {"has_body": True}):
            self.assertFalse(policy.request(method="GET", host="example.com", path="/", **extra).allowed)
        self.assertFalse(policy.request(method="POST", host="api.github.com", path="/graphql").allowed)
        policy.allowlist = frozenset({"api.github.com"})
        self.assertTrue(policy.request(method="POST", host="api.github.com", path="/graphql").allowed)
        self.assertFalse(policy.request(method="DELETE", host="api.github.com", path="/graphql").allowed)

    def test_allowlist_config(self):
        for text in ('', '[egress]\nmode = "reads-anywhere"'):
            self.assertTrue(self.load_text(text).connect("other.test").allowed)
        self.assertFalse(self.load_text('[egress]\nmode = "allowlist"').connect("example.com").allowed)
        for value in ['"example.com"', '["*.example.com"]', '["https://example.com"]',
                      '["example.com:443"]', '["192.0.2.1"]', '["::1"]', '[1]',
                      '["localhost"]', '["-bad.example"]', '["a..example"]',
                      repr(["a.example"] * (MAX_ALLOWED_DOMAINS + 1))]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.load_text('[egress]\nmode = "allowlist"\nallow = ' + value)
        for text in ('[egress]\nmode = "typo"', '[egress]\nallow = []',
                     '[egress]\nmode = "allowlist"\nextra = true', 'egress = []'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                self.load_text(text)

    def test_reasons(self):
        self.assertEqual(self.policy.request(method="GET", host="a.org", path="/").reason, "read")
        d = self.policy.request(method="POST", host="github.com", path="/a/b/git-upload-pack")
        self.assertEqual(d.reason, "git fetch (smart HTTP)")
        d = self.policy.request(method="POST", host="a.org", path="/")
        self.assertIn("not in the write allowlist", d.reason)

    def test_glob(self):
        cases = [
            ("/*/x", "/a/x", True), ("/*/x", "/a/b/x", False), ("/**/x", "/a/b/x", True),
            ("/a.b", "/a.b", True), ("/a.b", "/aXb", False), ("/x", "/x/", False),
        ]
        for glob, path, want in cases:
            with self.subTest(glob=glob, path=path):
                self.assertEqual(bool(glob_regex(glob).match(path)), want)

    def test_normalize_host(self):
        cases = [("Example.COM.", "example.com"), ("example.com:443", "example.com"), ("[::1]:80", "::1"),
                 ("::1", "::1"), (" a.org ", "a.org")]
        for host, want in cases:
            with self.subTest(host=host):
                self.assertEqual(normalize_host(host), want)

    def test_bad_rules(self):
        good = {"name": "x", "hosts": ["a.org"], "methods": ["POST"], "paths": ["/x"]}
        WriteRule.parse(good)
        for bad in [
            {**good, "name": ""},
            {**good, "hosts": []},
            {**good, "methods": ["GET"]},
            {**good, "paths": ["x"]},
            {**good, "paths": "/x"},
            {**good, "extra": 1},
        ]:
            with self.subTest(rule=bad), self.assertRaises(ValueError):
                WriteRule.parse(bad)


if __name__ == "__main__":
    unittest.main()
