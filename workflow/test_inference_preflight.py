import importlib.util
from pathlib import Path
import re
import shutil
import socket
import subprocess
import tempfile
import unittest
from unittest.mock import MagicMock

spec = importlib.util.spec_from_file_location(
    "preflight", Path(__file__).with_name("inference-preflight.py")
)
preflight = importlib.util.module_from_spec(spec)
spec.loader.exec_module(preflight)


class PreflightTests(unittest.TestCase):
    def test_workflow_order_and_trusted_binary(self):
        root = Path(__file__).resolve().parents[1]
        workflow = (root / ".github/workflows/agentic-job.yml").read_text()
        policy = (root / ".github/workflows/policy.yml").read_text()
        prepare = (root / "prepare/action.yml").read_text()
        secure = (root / "secure-host/action.yml").read_text()
        run = (root / "run/action.yml").read_text()
        self.assertIn('"$JOB_DIR/bin/agentic-job" config', policy)
        self.assertIn(".agentic-job/config.toml", policy.split("agentic-job-policy\n", 1)[1].split("\n  activate:", 1)[0])
        self.assertNotIn("CONFIG_BINARY", policy)
        self.assertIn('sudo install -m 0755 "$JOB_DIR/agentic-job" /usr/local/bin/agentic-job', prepare)
        self.assertLess(prepare.index("artifact-ids:"), prepare.index("- name: Install the binary"))
        # The agent job writes no configuration of its own: secure-host
        # takes the policy job's, which prepare downloaded.
        for file, source in [("agentic-job.yml", workflow),
                             ("example-compose.yml", (root / ".github/workflows/example-compose.yml").read_text())]:
            with self.subTest(file=file):
                agent = source.split("\n  agent:\n", 1)[1].split("\n  check:\n", 1)[0]
                self.assertNotIn(" config ", agent)
                self.assertIn("config: .agentic-job/config.toml", agent)
                # Follow the composite calls in place: installation must
                # precede the preflight, and the preflight setup, and
                # execution must follow host hardening.
                expanded = agent.replace("uses: ./.agentic-job-source/prepare", prepare)
                expanded = expanded.replace("uses: ./.agentic-job-source/secure-host", secure)
                expanded = expanded.replace("uses: ./.agentic-job-source/run", run)
                position = 0
                for name in ["Install the binary", "Write what the run is called", "Write the configuration",
                             "Check inference proxy reachability", "Secure the host",
                             "Prove the host is secured", "Run the agent"]:
                    position = expanded.index(f"- name: {name}\n", position)
        self.assertIn("@agentclientprotocol/claude-agent-acp@0.88.0", policy)

    def test_policy_configuration_uses_its_own_binary(self):
        workflow = (Path(__file__).resolve().parents[1] / ".github/workflows/policy.yml").read_text()
        step = workflow.split("- name: Write the configuration\n", 1)[1]
        body = step.split("        run: |\n", 1)[1]
        script = re.match(r"(?:          [^\n]*\n)+", body).group()
        script = "\n".join(line.removeprefix("          ") for line in script.splitlines())

        # echo stands in for the binary to record its arguments.
        with tempfile.TemporaryDirectory(dir=Path.home()) as directory:
            root = Path(directory)
            (root / "bin").mkdir()
            shutil.copyfile("/bin/echo", root / "bin/agentic-job")
            (root / "bin/agentic-job").chmod(0o755)
            env = dict.fromkeys([
                "CONFIG", "MODEL", "CONFIG_REPO", "CONFIG_REF", "CONFIG_PATH",
                "SKILLS", "URL", "REGISTER", "AUDIENCE", "TOKEN_FILE", "PROVIDER", "TIMEOUT",
                "MAX_REQUESTS", "MAX_TASKS", "BUDGET", "PACKAGES", "NPM", "SETUP",
                "SESSION", "IDLE_MINUTES",
            ], "")
            env.update(JOB_DIR=str(root), PATH="/usr/bin:/bin", AGENT="fake", REPO="example/repo")
            result = subprocess.run(
                ["bash", "-euo", "pipefail", "-c", script], env=env,
                capture_output=True, text=True, timeout=10,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue((root / "config.toml").read_text().startswith("config --repo example/repo --string agent.name=fake "))

    def test_proposals_skip_agent_configuration(self):
        workflow = (Path(__file__).resolve().parents[1] / ".github/workflows/policy.yml").read_text()
        step = workflow.split("- name: Write the configuration\n", 1)[1].split("- name:", 1)[0]
        self.assertIn("if: ${{ inputs.proposals-artifact == '' && steps.event.outputs.admitted != 'false' }}", step)

    def test_fake_agent_skips_proxy_step(self):
        action = (Path(__file__).resolve().parents[1] / "secure-host/action.yml").read_text()
        step = action.split("- name: Check inference proxy reachability\n", 1)[1].split("- name:", 1)[0]
        body = step.split("      run: |\n", 1)[1]
        script = "\n".join(line.removeprefix("        ") for line in body.splitlines() if line.startswith("        "))
        self.assertIn('python3 "$ACTION/../workflow/inference-preflight.py" "$RUNNER_TEMP/secure-host/config.toml"', script)

        # Python, which `tomllib` needs at 3.11, runs only for a
        # configuration naming a proxy; a stand-in records that it ran.
        with tempfile.TemporaryDirectory(dir=Path.home()) as directory:
            root = Path(directory)
            (root / "bin").mkdir()
            (root / "bin/python3").write_text(f"#!/bin/sh\ntouch {root}/ran\n")
            (root / "bin/python3").chmod(0o755)
            (root / "secure-host").mkdir()
            for config, runs in [("[sandbox]\nuser = \"agent\"\n", False),
                                 ("[agent]\nname = \"inference\"\n", False),
                                 ("[agent]\nname = \"claude\"\n\n[inference]\nurl = \"http://proxy.invalid\"\n", True)]:
                with self.subTest(config=config):
                    (root / "ran").unlink(missing_ok=True)
                    (root / "secure-host/config.toml").write_text(config)
                    result = subprocess.run(
                        ["bash", "-eo", "pipefail", "-c", script],
                        env={"PATH": f"{root}/bin:/usr/bin:/bin", "RUNNER_TEMP": str(root), "ACTION": str(root)},
                        capture_output=True, text=True, timeout=10,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual((root / "ran").exists(), runs)

        # Even a fake agent configured with an unreachable proxy must not connect.
        for agent, runs in [("fake", False), ("claude", True), ("opencode", True), ("codex", True)]:
            with self.subTest(agent=agent):
                connect = MagicMock()
                preflight.check({"agent": {"name": agent}, "inference": {"url": "http://proxy.invalid:8080"}}, connect)
                self.assertEqual(connect.call_count, int(runs))

    def test_addresses(self):
        for url, address in [
            ("http://100.64.0.1:8080/path", ("100.64.0.1", 8080)),
            ("https://proxy.example", ("proxy.example", 443)),
            ("http://[::1]", ("::1", 80)),
        ]:
            with self.subTest(url=url):
                connect = MagicMock()
                preflight.check({"inference": {"url": url}}, connect)
                connect.assert_called_once_with(address, timeout=10)
                connect.return_value.__exit__.assert_called_once()

    def test_no_proxy(self):
        connect = MagicMock()
        preflight.check({}, connect)
        connect.assert_not_called()

    def test_e2e_callers_do_not_need_a_proxy(self):
        ci = (Path(__file__).resolve().parents[1] / ".github/workflows/ci.yml").read_text()
        for name in [
            "e2e-full", "e2e-limit", "e2e-event", "e2e-analysis",
            "e2e-analysis-refused", "e2e-review",
        ]:
            with self.subTest(job=name):
                # Job bodies are indented at least four spaces.
                job = ci.split(f"\n  {name}:\n", 1)[1]
                job = re.split(r"\n  [^ ]", job, maxsplit=1)[0]
                self.assertIn("agent: fake", job)
                self.assertNotIn("inference-url:", job)

    def test_refusals(self):
        for url in ["file:///etc/passwd", "http://", "http://proxy:invalid"]:
            with self.subTest(url=url), self.assertRaises(ValueError):
                preflight.check({"inference": {"url": url}})
        for error in [ConnectionRefusedError(), socket.timeout(), socket.gaierror()]:
            with self.subTest(error=error), self.assertRaisesRegex(
                RuntimeError, "control failed: the runner cannot reach.*join its network in a step before secure-host"
            ):
                preflight.check(
                    {"inference": {"url": "http://127.0.0.1:8080"}},
                    MagicMock(side_effect=error),
                )

    def test_real_connection(self):
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            port = listener.getsockname()[1]
            preflight.check({"inference": {"url": f"http://127.0.0.1:{port}"}})


if __name__ == "__main__":
    unittest.main()
