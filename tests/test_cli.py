"""End-to-end tests that run the CLI in a subprocess.

The subprocess inherits ``PYTHONPATH=src`` so the package is imported exactly
the way the README's source-checkout workflow does.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from tests.helpers import start_agent, unused_ports

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = REPO_ROOT / "src"


def run_cli(*args: str, timeout: float = 120.0) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(SRC_DIR)
    return subprocess.run(
        [sys.executable, "-m", "netwatch", *args],
        cwd=str(REPO_ROOT),
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


class CliTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.db = str(Path(self.temp_dir.name) / "netwatch.db")

    def poll_simulate(self, *extra: str) -> subprocess.CompletedProcess:
        return run_cli(
            "poll",
            "--simulate",
            "--count",
            "2",
            "--interval",
            "0.2",
            "--db",
            self.db,
            *extra,
        )


class CliHelpTests(CliTestCase):
    def test_help_lists_all_commands(self) -> None:
        result = run_cli("--help")
        self.assertEqual(result.returncode, 0)
        self.assertIn("usage: netwatch", result.stdout)
        for command in ("init", "poll", "dashboard", "report", "alerts", "serve", "agent"):
            self.assertIn(command, result.stdout)
        self.assertIn("exit codes", result.stdout)

    def test_version(self) -> None:
        result = run_cli("--version")
        self.assertEqual(result.returncode, 0)
        self.assertIn("netwatch 1.0.0", result.stdout)

    def test_no_command_is_bad_usage(self) -> None:
        result = run_cli()
        self.assertEqual(result.returncode, 2)

    def test_unknown_command_is_bad_usage(self) -> None:
        result = run_cli("explode")
        self.assertEqual(result.returncode, 2)


class CliInitTests(CliTestCase):
    def test_init_creates_database(self) -> None:
        result = run_cli("init", "--db", self.db)
        self.assertEqual(result.returncode, 0)
        self.assertIn("initialized", result.stdout)
        self.assertIn("schema v1", result.stdout)
        self.assertTrue(Path(self.db).exists())

    def test_init_is_idempotent(self) -> None:
        self.assertEqual(run_cli("init", "--db", self.db).returncode, 0)
        second = run_cli("init", "--db", self.db)
        self.assertEqual(second.returncode, 0)
        self.assertIn("alerts", second.stdout)


class CliPollTests(CliTestCase):
    def test_poll_simulate_text_output(self) -> None:
        result = self.poll_simulate()
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertEqual(result.stderr, "")
        self.assertIn("simulator listening on udp://127.0.0.1:", result.stdout)
        self.assertIn("simulated device: simsw01.example", result.stdout)
        self.assertIn("Ethernet0/1", result.stdout)
        self.assertIn("reachable", result.stdout)
        self.assertIn("oper status is down", result.stdout)
        self.assertIn("2 poll(s) completed; 6 sample(s) stored", result.stdout)
        self.assertIn("1 active alert(s)", result.stdout)

    def test_poll_simulate_json_output(self) -> None:
        result = self.poll_simulate("--json")
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(len(payload), 2)
        self.assertTrue(payload[0]["reachable"])
        self.assertEqual(len(payload[0]["interfaces"]), 3)
        self.assertTrue(all(item["in_bps"] is None for item in payload[0]["interfaces"]))
        self.assertTrue(any(item["in_bps"] is not None for item in payload[1]["interfaces"]))
        self.assertEqual(payload[1]["interfaces"][0]["counter_bits"], 64)
        self.assertEqual(payload[1]["sys_name"], "simsw01.example")

    def test_poll_real_agent_from_subprocess(self) -> None:
        agent, _device, host, port = start_agent()
        self.addCleanup(agent.stop)
        result = run_cli(
            "poll",
            "--device",
            f"{host}:{port}",
            "--count",
            "2",
            "--interval",
            "0.2",
            "--db",
            self.db,
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn(f"({host}:{port}) - reachable", result.stdout)
        self.assertIn("Ethernet0/2", result.stdout)
        report = run_cli("report", "--db", self.db)
        self.assertEqual(report.returncode, 0)
        self.assertIn(f"{host}:{port}", report.stdout)

    def test_unreachable_device_returns_exit_code_1(self) -> None:
        port = unused_ports()[0]
        result = run_cli(
            "poll",
            "--device",
            f"127.0.0.1:{port}",
            "--timeout",
            "0.2",
            "--retries",
            "0",
            "--db",
            self.db,
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("UNREACHABLE", result.stdout)
        self.assertIn("failed", result.stderr)

    def test_invalid_count_is_bad_usage(self) -> None:
        result = self.poll_simulate("--count", "0")
        self.assertEqual(result.returncode, 2)
        self.assertIn("--count must be at least 1", result.stderr)

    def test_poll_without_target_is_bad_usage(self) -> None:
        result = run_cli("poll", "--db", self.db)
        self.assertEqual(result.returncode, 2)


class CliOutputTests(CliTestCase):
    def setUp(self) -> None:
        super().setUp()
        result = self.poll_simulate()
        self.assertEqual(result.returncode, 0, msg=result.stderr)

    def test_report_text(self) -> None:
        result = run_cli("report", "--db", self.db)
        self.assertEqual(result.returncode, 0)
        self.assertIn("netwatch report -", result.stdout)
        self.assertIn("Ethernet0/1", result.stdout)
        self.assertIn("oper_status_down", result.stdout)
        self.assertIn("thresholds:", result.stdout)

    def test_report_json(self) -> None:
        result = run_cli("report", "--db", self.db, "--json")
        self.assertEqual(result.returncode, 0)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["totals"]["devices"], 1)
        self.assertEqual(payload["totals"]["interfaces"], 3)
        self.assertEqual(payload["totals"]["samples"], 6)
        self.assertEqual(payload["totals"]["active_alerts"], 1)
        self.assertEqual(payload["devices"][0]["interfaces"][0]["name"], "Ethernet0/1")

    def test_alerts_text_and_json(self) -> None:
        text = run_cli("alerts", "--db", self.db)
        self.assertEqual(text.returncode, 0)
        self.assertIn("oper_status_down", text.stdout)
        self.assertIn("1 active alert(s)", text.stdout)
        payload = json.loads(run_cli("alerts", "--db", self.db, "--json").stdout)
        self.assertEqual(payload["active"], 1)
        self.assertEqual(payload["alerts"][0]["kind"], "oper_status_down")
        self.assertEqual(payload["alerts"][0]["state"], "active")
        everything = json.loads(run_cli("alerts", "--db", self.db, "--json", "--all").stdout)
        self.assertEqual(everything["total"], 1)

    def test_dashboard_written_to_file(self) -> None:
        output = Path(self.temp_dir.name) / "site" / "dashboard.html"
        result = run_cli("dashboard", "--db", self.db, "--output", str(output))
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn("dashboard written to", result.stdout)
        document = output.read_text(encoding="utf-8")
        self.assertIn("<!DOCTYPE html>", document)
        self.assertIn("<svg", document)
        self.assertIn("Ethernet0/2", document)
        self.assertNotIn("http://", document)
        self.assertNotIn("https://", document)

    def test_dashboard_to_stdout(self) -> None:
        result = run_cli("dashboard", "--db", self.db, "--output", "-")
        self.assertEqual(result.returncode, 0)
        self.assertTrue(result.stdout.startswith("<!DOCTYPE html>"))
        self.assertIn("netwatch dashboard", result.stdout)

    def test_serve_rejects_invalid_port(self) -> None:
        result = run_cli("serve", "--db", self.db, "--port", "0")
        self.assertEqual(result.returncode, 2)
        self.assertIn("--port must be within 1..65535", result.stderr)


if __name__ == "__main__":
    unittest.main()
