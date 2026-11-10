"""addon.py in a running mitmdump, on loopback only: an allowlist policy, and
HTTP origins on loopback ports under names in .test, which never resolve
(RFC 6761). A second addon, loaded after addon.py, connects those names to
their loopback ports, so the policy sees the names a client asked for.
Skipped where mitmproxy is not installed; CI runs it with the pinned one:
python -m unittest discover -s egress -p test_live.py"""

import http.server
import importlib.util
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
START_TIMEOUT = 30
REQUEST_TIMEOUT = 10

# Runs in mitmdump: EGRESS_TEST_ORIGINS maps a name, and its subdomains, to
# a loopback port; any other name goes to port 1 on loopback, closed, never
# to DNS.
RESOLVER = """
import json, os
ORIGINS = json.loads(os.environ["EGRESS_TEST_ORIGINS"])
class Resolve:
    def server_connect(self, data):
        host, _ = data.server.address
        port = next((p for name, p in ORIGINS.items() if host == name or host.endswith("." + name)), 1)
        data.server.address = ("127.0.0.1", port)
addons = [Resolve()]
"""


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Origin(http.server.BaseHTTPRequestHandler):
    """Answers 200, or with a redirect when the path is /redirect?to=URL."""
    def do_GET(self):
        self.server.paths.append(self.path)
        if self.path.startswith("/redirect?to="):
            self.send_response(302)
            self.send_header("Location", self.path.split("=", 1)[1])
        else:
            self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *args):
        pass


@unittest.skipIf(importlib.util.find_spec("mitmproxy") is None, "mitmproxy is not installed")
class LiveProxyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.origins = {}
        for name in ("allowed.test", "refused.test"):
            server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Origin)
            server.paths = []
            threading.Thread(target=server.serve_forever, daemon=True).start()
            cls.origins[name] = server
        policy = os.path.join(cls.tmp.name, "policy.toml")
        with open(policy, "w") as f:
            f.write('[egress]\nmode = "allowlist"\nallow = ["allowed.test"]\n')
        resolver = os.path.join(cls.tmp.name, "resolve.py")
        with open(resolver, "w") as f:
            f.write(RESOLVER)
        cls.port = free_port()
        env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1", "EGRESS_TEST_ORIGINS": json.dumps(
            {name: server.server_address[1] for name, server in cls.origins.items()})}
        # The options sandbox/egress.rs starts it with, but the paths.
        cls.proxy = subprocess.Popen(
            [sys.executable, "-c", "from mitmproxy.tools.main import mitmdump; mitmdump()",
             "--mode", "regular", "--listen-host", "127.0.0.1", "--listen-port", str(cls.port),
             "--set", f"confdir={cls.tmp.name}", "--set", "connection_strategy=lazy",
             "--set", "rawtcp=false", "--set", "flow_detail=0", "--set", "termlog_verbosity=warn",
             "-s", os.path.join(HERE, "addon.py"), "-s", resolver, "--set", f"egress_policy={policy}"],
            env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        deadline = time.monotonic() + START_TIMEOUT
        while True:
            try:
                socket.create_connection(("127.0.0.1", cls.port), timeout=1).close()
                break
            except OSError:
                if cls.proxy.poll() is not None or time.monotonic() > deadline:
                    cls.tearDownClass()
                    raise RuntimeError("mitmdump did not start")
                time.sleep(0.2)
        cls.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": f"http://127.0.0.1:{cls.port}"}))

    @classmethod
    def tearDownClass(cls):
        cls.proxy.terminate()
        _, err = cls.proxy.communicate(timeout=START_TIMEOUT)
        if err.strip():
            print(err, file=sys.stderr)
        for server in cls.origins.values():
            server.shutdown()
            server.server_close()
        cls.tmp.cleanup()

    def setUp(self):
        for server in self.origins.values():
            server.paths.clear()

    def get(self, url: str):
        """The status and refusal header of a GET through the proxy, which
        follows redirects through it too."""
        try:
            with self.opener.open(url, timeout=REQUEST_TIMEOUT) as r:
                return r.status, r.headers.get("X-Egress-Denied")
        except urllib.error.HTTPError as e:
            with e:
                return e.code, e.headers.get("X-Egress-Denied")

    def test_requests(self):
        # (URL, status, refused, paths each origin was asked for)
        cases = [
            ("http://allowed.test/a", 200, False, {"allowed.test": ["/a"], "refused.test": []}),
            ("http://sub.allowed.test/b", 200, False, {"allowed.test": ["/b"], "refused.test": []}),
            ("http://refused.test/c", 403, True, {"allowed.test": [], "refused.test": []}),
            ("http://allowed.test/redirect?to=http://refused.test/d", 403, True,
             {"allowed.test": ["/redirect?to=http://refused.test/d"], "refused.test": []}),
            ("http://allowed.test/redirect?to=http://allowed.test/e", 200, False,
             {"allowed.test": ["/redirect?to=http://allowed.test/e", "/e"], "refused.test": []}),
        ]
        for url, status, refused, paths in cases:
            with self.subTest(url=url):
                self.setUp()
                got, denied = self.get(url)
                self.assertEqual(got, status)
                self.assertEqual(denied == "host is not in the domain allowlist", refused, denied)
                self.assertEqual({name: s.paths for name, s in self.origins.items()}, paths)


if __name__ == "__main__":
    unittest.main()
