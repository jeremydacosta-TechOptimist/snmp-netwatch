"""Shared fixtures for the netwatch test suite."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from typing import Optional, Tuple

from netwatch.agent import SimulatedDevice, SnmpAgent
from netwatch.clock import Clock, FixedClock
from netwatch.storage import Store

REPO_ROOT = Path(__file__).resolve().parents[1]


def start_agent(
    clock: Optional[Clock] = None,
    support_hc_counters: bool = True,
    community: str = "public",
) -> Tuple[SnmpAgent, SimulatedDevice, str, int]:
    """Start a simulator on an ephemeral localhost port and return its parts."""

    device = SimulatedDevice(clock=clock or FixedClock(), support_hc_counters=support_hc_counters)
    agent = SnmpAgent(device, host="127.0.0.1", port=0, community=community)
    host, port = agent.start()
    return agent, device, host, port


class StoreTestCase(unittest.TestCase):
    """Base test case with a temporary SQLite store and a fixed clock."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.clock = FixedClock()
        self.store = Store(Path(self.temp_dir.name) / "netwatch.db", clock=self.clock)
        self.store.initialize()
        self.addCleanup(self.store.close)

    @property
    def db_path(self) -> Path:
        return Path(self.temp_dir.name) / "netwatch.db"


class AgentTestCase(StoreTestCase):
    """Base test case with a simulator agent running on an ephemeral port."""

    def setUp(self) -> None:
        super().setUp()
        self.agent_clock = FixedClock()
        self.device = SimulatedDevice(clock=self.agent_clock)
        self.agent = SnmpAgent(self.device, host="127.0.0.1", port=0)
        self.host, self.port = self.agent.start()
        self.addCleanup(self.agent.stop)


def unused_ports(count: int = 1) -> Tuple[int, ...]:
    """Return UDP ports that were just bound and released (likely free)."""

    import socket

    ports = []
    sockets = []
    try:
        for _ in range(count):
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(("127.0.0.1", 0))
            sockets.append(sock)
            ports.append(sock.getsockname()[1])
    finally:
        for sock in sockets:
            sock.close()
    return tuple(ports)
