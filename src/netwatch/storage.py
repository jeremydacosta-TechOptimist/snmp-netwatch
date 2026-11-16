"""SQLite persistence for devices, interfaces, samples and alerts.

The store keeps a single connection guarded by a re-entrant lock so the HTTP
dashboard can read the database from server threads while a poll writes to it.
Timestamps are ISO-8601 UTC strings produced by an injectable
:class:`~netwatch.clock.Clock`, which keeps persisted history deterministic in
tests.

Schema (version 1):

``devices``
    One row per polled endpoint (address is unique) with reachability state.
``interfaces``
    One row per interface per device, unique on ``(device_id, if_index)``.
``samples``
    Counter snapshots and computed rates for an interface over time.
``alerts``
    Threshold events; an event is active while ``resolved_at`` is NULL.
"""

from __future__ import annotations

import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Optional, Union

from .clock import Clock, SystemClock

__all__ = [
    "DEFAULT_DB_FILE",
    "SCHEMA_VERSION",
    "StoreError",
    "parse_timestamp",
    "Device",
    "Interface",
    "Sample",
    "Alert",
    "Store",
]

DEFAULT_DB_FILE = "netwatch.db"
SCHEMA_VERSION = 1

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    address TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    community TEXT NOT NULL DEFAULT 'public',
    reachable INTEGER NOT NULL DEFAULT 1,
    last_error TEXT,
    last_polled_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS interfaces (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    if_index INTEGER NOT NULL,
    name TEXT NOT NULL,
    alias TEXT NOT NULL DEFAULT '',
    speed_bps INTEGER,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (device_id, if_index)
);

CREATE TABLE IF NOT EXISTS samples (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    interface_id INTEGER NOT NULL REFERENCES interfaces(id) ON DELETE CASCADE,
    sampled_at TEXT NOT NULL,
    in_octets INTEGER NOT NULL,
    out_octets INTEGER NOT NULL,
    counter_bits INTEGER NOT NULL DEFAULT 64,
    in_bps REAL,
    out_bps REAL,
    utilization_pct REAL,
    oper_status INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_samples_interface_time
    ON samples (interface_id, sampled_at);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    interface_id INTEGER REFERENCES interfaces(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    severity TEXT NOT NULL,
    message TEXT NOT NULL,
    value REAL,
    threshold REAL,
    created_at TEXT NOT NULL,
    resolved_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_alerts_active
    ON alerts (device_id, interface_id, kind, resolved_at);
"""


class StoreError(Exception):
    """Raised when the SQLite store cannot satisfy a request."""


def parse_timestamp(text: str) -> datetime:
    """Parse an ISO-8601 timestamp, assuming UTC when no offset is present."""

    try:
        parsed = datetime.fromisoformat(text)
    except (TypeError, ValueError) as exc:
        raise StoreError(f"invalid timestamp {text!r}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


@dataclass(frozen=True)
class Device:
    """A monitored endpoint."""

    id: int
    address: str
    name: str
    community: str
    reachable: bool
    last_error: Optional[str]
    last_polled_at: Optional[str]
    created_at: str
    updated_at: str


@dataclass(frozen=True)
class Interface:
    """An interface discovered on a device."""

    id: int
    device_id: int
    if_index: int
    name: str
    alias: str
    speed_bps: Optional[int]


@dataclass(frozen=True)
class Sample:
    """One counter snapshot plus the rates derived from the previous snapshot."""

    id: int
    interface_id: int
    sampled_at: str
    in_octets: int
    out_octets: int
    counter_bits: int
    in_bps: Optional[float]
    out_bps: Optional[float]
    utilization_pct: Optional[float]
    oper_status: int

    @property
    def timestamp(self) -> datetime:
        """Parsed UTC timestamp of the sample."""

        return parse_timestamp(self.sampled_at)


@dataclass(frozen=True)
class Alert:
    """A persisted alert event."""

    id: int
    device_id: int
    interface_id: Optional[int]
    kind: str
    severity: str
    message: str
    value: Optional[float]
    threshold: Optional[float]
    created_at: str
    resolved_at: Optional[str]

    @property
    def active(self) -> bool:
        """True while the alert has not been resolved."""

        return self.resolved_at is None


class Store:
    """Small, thread-tolerant wrapper around a SQLite database file."""

    def __init__(self, path: Union[str, Path] = DEFAULT_DB_FILE, clock: Optional[Clock] = None) -> None:
        self.path = str(path)
        self.clock = clock or SystemClock()
        self._is_memory = self.path == ":memory:"
        if not self._is_memory:
            parent = Path(self.path).expanduser().parent
            if str(parent) not in ("", "."):
                parent.mkdir(parents=True, exist_ok=True)
        self._connection: Optional[sqlite3.Connection] = None
        self._lock = threading.RLock()

    def __enter__(self) -> "Store":
        self.initialize()
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    def connect(self) -> sqlite3.Connection:
        """Open (once) and return the SQLite connection."""

        with self._lock:
            if self._connection is None:
                connection = sqlite3.connect(self.path, check_same_thread=False)
                connection.row_factory = sqlite3.Row
                connection.execute("PRAGMA foreign_keys = ON")
                if not self._is_memory:
                    connection.execute("PRAGMA journal_mode = WAL")
                self._connection = connection
            return self._connection

    def close(self) -> None:
        """Close the underlying connection; safe to call more than once."""

        with self._lock:
            if self._connection is not None:
                self._connection.close()
                self._connection = None

    def initialize(self) -> None:
        """Create the schema if needed and stamp the schema version."""

        connection = self.connect()
        with self._lock, connection:
            connection.executescript(SCHEMA_SQL)
            connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")

    def schema_version(self) -> int:
        """Return the SQLite ``user_version`` pragma."""

        connection = self.connect()
        with self._lock:
            row = connection.execute("PRAGMA user_version").fetchone()
        return int(row[0]) if row is not None else 0

    def table_names(self) -> List[str]:
        """Return user table names, sorted (used by health checks and tests)."""

        connection = self.connect()
        with self._lock:
            rows = connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
            ).fetchall()
        return [str(row["name"]) for row in rows]

    # ------------------------------------------------------------------
    # Devices
    # ------------------------------------------------------------------
    def upsert_device(self, address: str, name: Optional[str] = None, community: str = "public") -> Device:
        """Insert a device or refresh its name/community."""

        address = str(address).strip()
        if not address:
            raise ValueError("device address cannot be empty")
        now = self.clock.timestamp()
        connection = self.connect()
        with self._lock, connection:
            row = connection.execute("SELECT id FROM devices WHERE address = ?", (address,)).fetchone()
            if row is None:
                connection.execute(
                    "INSERT INTO devices (address, name, community, reachable, created_at, updated_at) "
                    "VALUES (?, ?, ?, 1, ?, ?)",
                    (address, name or address, community, now, now),
                )
            else:
                if name:
                    connection.execute(
                        "UPDATE devices SET name = ?, community = ?, updated_at = ? WHERE id = ?",
                        (name, community, now, int(row["id"])),
                    )
                else:
                    connection.execute(
                        "UPDATE devices SET community = ?, updated_at = ? WHERE id = ?",
                        (community, now, int(row["id"])),
                    )
        device = self.get_device(address)
        assert device is not None  # just inserted or updated
        return device

    def get_device(self, address: str) -> Optional[Device]:
        """Return the device with ``address``, or None."""

        connection = self.connect()
        with self._lock:
            row = connection.execute("SELECT * FROM devices WHERE address = ?", (address,)).fetchone()
        return _device_from_row(row) if row is not None else None

    def get_device_by_id(self, device_id: int) -> Optional[Device]:
        """Return the device with ``device_id``, or None."""

        connection = self.connect()
        with self._lock:
            row = connection.execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()
        return _device_from_row(row) if row is not None else None

    def list_devices(self) -> List[Device]:
        """Return every known device ordered by address."""

        connection = self.connect()
        with self._lock:
            rows = connection.execute("SELECT * FROM devices ORDER BY address ASC").fetchall()
        return [_device_from_row(row) for row in rows]

    def update_device_status(
        self,
        device_id: int,
        reachable: bool,
        error: Optional[str] = None,
        polled_at: Optional[str] = None,
    ) -> None:
        """Record the outcome of the latest poll for a device."""

        connection = self.connect()
        with self._lock, connection:
            connection.execute(
                "UPDATE devices SET reachable = ?, last_error = ?, last_polled_at = ?, updated_at = ? WHERE id = ?",
                (1 if reachable else 0, error, polled_at, self.clock.timestamp(), device_id),
            )

    # ------------------------------------------------------------------
    # Interfaces
    # ------------------------------------------------------------------
    def upsert_interface(
        self,
        device_id: int,
        if_index: int,
        name: str,
        alias: str = "",
        speed_bps: Optional[int] = None,
    ) -> Interface:
        """Insert or update one interface row and return it."""

        if if_index < 0:
            raise ValueError("if_index cannot be negative")
        now = self.clock.timestamp()
        connection = self.connect()
        with self._lock, connection:
            connection.execute(
                "INSERT INTO interfaces (device_id, if_index, name, alias, speed_bps, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT (device_id, if_index) DO UPDATE SET "
                "name = excluded.name, alias = excluded.alias, speed_bps = excluded.speed_bps, "
                "updated_at = excluded.updated_at",
                (device_id, if_index, name, alias, speed_bps, now, now),
            )
        interface = self.get_interface(device_id, if_index)
        assert interface is not None  # just inserted or updated
        return interface

    def get_interface(self, device_id: int, if_index: int) -> Optional[Interface]:
        """Return one interface by device and ifIndex, or None."""

        connection = self.connect()
        with self._lock:
            row = connection.execute(
                "SELECT * FROM interfaces WHERE device_id = ? AND if_index = ?",
                (device_id, if_index),
            ).fetchone()
        return _interface_from_row(row) if row is not None else None

    def get_interface_by_id(self, interface_id: int) -> Optional[Interface]:
        """Return one interface by synthetic id, or None."""

        connection = self.connect()
        with self._lock:
            row = connection.execute("SELECT * FROM interfaces WHERE id = ?", (interface_id,)).fetchone()
        return _interface_from_row(row) if row is not None else None

    def list_interfaces(self, device_id: Optional[int] = None) -> List[Interface]:
        """Return interfaces ordered by device then ifIndex."""

        connection = self.connect()
        with self._lock:
            if device_id is None:
                rows = connection.execute(
                    "SELECT * FROM interfaces ORDER BY device_id ASC, if_index ASC"
                ).fetchall()
            else:
                rows = connection.execute(
                    "SELECT * FROM interfaces WHERE device_id = ? ORDER BY if_index ASC",
                    (device_id,),
                ).fetchall()
        return [_interface_from_row(row) for row in rows]

    # ------------------------------------------------------------------
    # Samples
    # ------------------------------------------------------------------
    def record_sample(
        self,
        interface_id: int,
        sampled_at: str,
        in_octets: int,
        out_octets: int,
        counter_bits: int,
        in_bps: Optional[float],
        out_bps: Optional[float],
        utilization_pct: Optional[float],
        oper_status: int,
    ) -> Sample:
        """Persist one counter snapshot and its derived rates."""

        if counter_bits not in (32, 64):
            raise ValueError("counter_bits must be 32 or 64")
        if in_octets < 0 or out_octets < 0:
            raise ValueError("octet counters cannot be negative")
        parse_timestamp(sampled_at)  # validate early for a clear error
        connection = self.connect()
        with self._lock, connection:
            cursor = connection.execute(
                "INSERT INTO samples (interface_id, sampled_at, in_octets, out_octets, counter_bits, "
                "in_bps, out_bps, utilization_pct, oper_status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    interface_id,
                    sampled_at,
                    int(in_octets),
                    int(out_octets),
                    int(counter_bits),
                    in_bps,
                    out_bps,
                    utilization_pct,
                    int(oper_status),
                ),
            )
            sample_id = int(cursor.lastrowid)
        sample = self.get_sample(sample_id)
        assert sample is not None  # just inserted
        return sample

    def get_sample(self, sample_id: int) -> Optional[Sample]:
        """Return one sample by id, or None."""

        connection = self.connect()
        with self._lock:
            row = connection.execute("SELECT * FROM samples WHERE id = ?", (sample_id,)).fetchone()
        return _sample_from_row(row) if row is not None else None

    def latest_sample(self, interface_id: int) -> Optional[Sample]:
        """Return the most recent sample for an interface, or None."""

        connection = self.connect()
        with self._lock:
            row = connection.execute(
                "SELECT * FROM samples WHERE interface_id = ? ORDER BY sampled_at DESC, id DESC LIMIT 1",
                (interface_id,),
            ).fetchone()
        return _sample_from_row(row) if row is not None else None

    def interface_samples(self, interface_id: int, limit: int = 30) -> List[Sample]:
        """Return up to ``limit`` recent samples, oldest first (for sparklines)."""

        if limit <= 0:
            raise ValueError("limit must be positive")
        connection = self.connect()
        with self._lock:
            rows = connection.execute(
                "SELECT * FROM (SELECT * FROM samples WHERE interface_id = ? "
                "ORDER BY sampled_at DESC, id DESC LIMIT ?) ORDER BY sampled_at ASC, id ASC",
                (interface_id, limit),
            ).fetchall()
        return [_sample_from_row(row) for row in rows]

    def count_samples(self) -> int:
        """Return the total number of stored samples."""

        connection = self.connect()
        with self._lock:
            row = connection.execute("SELECT COUNT(*) AS total FROM samples").fetchone()
        return int(row["total"])

    def count_interface_samples(self, interface_id: int) -> int:
        """Return the number of samples stored for one interface."""

        connection = self.connect()
        with self._lock:
            row = connection.execute(
                "SELECT COUNT(*) AS total FROM samples WHERE interface_id = ?", (interface_id,)
            ).fetchone()
        return int(row["total"])

    def prune_samples(self, retain_hours: float, now: Optional[datetime] = None) -> int:
        """Delete samples older than ``retain_hours``; return rows removed.

        A retention of 0 is rejected: call :meth:`reset_samples_for_device`
        explicitly when a simulated device restarts its counters.
        """

        if retain_hours <= 0:
            raise ValueError("retain_hours must be positive")
        reference = now if now is not None else self.clock.utcnow()
        if reference.tzinfo is None:
            reference = reference.replace(tzinfo=timezone.utc)
        cutoff = (reference - timedelta(hours=retain_hours)).isoformat(timespec="milliseconds")
        connection = self.connect()
        with self._lock, connection:
            cursor = connection.execute("DELETE FROM samples WHERE sampled_at < ?", (cutoff,))
            return int(cursor.rowcount)

    def reset_samples_for_device(self, device_id: int) -> int:
        """Delete counter history for a device (used when the simulator restarts)."""

        connection = self.connect()
        with self._lock, connection:
            cursor = connection.execute(
                "DELETE FROM samples WHERE interface_id IN "
                "(SELECT id FROM interfaces WHERE device_id = ?)",
                (device_id,),
            )
            return int(cursor.rowcount)

    # ------------------------------------------------------------------
    # Alerts
    # ------------------------------------------------------------------
    def find_active_alert(
        self, device_id: int, kind: str, interface_id: Optional[int] = None
    ) -> Optional[Alert]:
        """Return the open alert of ``kind`` for a target, or None."""

        connection = self.connect()
        with self._lock:
            row = connection.execute(
                "SELECT * FROM alerts WHERE device_id = ? AND interface_id IS ? AND kind = ? "
                "AND resolved_at IS NULL ORDER BY id DESC LIMIT 1",
                (device_id, interface_id, kind),
            ).fetchone()
        return _alert_from_row(row) if row is not None else None

    def record_alert(
        self,
        device_id: int,
        kind: str,
        severity: str,
        message: str,
        interface_id: Optional[int] = None,
        value: Optional[float] = None,
        threshold: Optional[float] = None,
    ) -> Alert:
        """Open an alert, or return the already-open alert with the same target."""

        existing = self.find_active_alert(device_id, kind, interface_id)
        if existing is not None:
            return existing
        connection = self.connect()
        with self._lock, connection:
            cursor = connection.execute(
                "INSERT INTO alerts (device_id, interface_id, kind, severity, message, value, threshold, "
                "created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    device_id,
                    interface_id,
                    kind,
                    severity,
                    message,
                    value,
                    threshold,
                    self.clock.timestamp(),
                ),
            )
            alert_id = int(cursor.lastrowid)
        alert = self.get_alert(alert_id)
        assert alert is not None  # just inserted
        return alert

    def get_alert(self, alert_id: int) -> Optional[Alert]:
        """Return one alert by id, or None."""

        connection = self.connect()
        with self._lock:
            row = connection.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
        return _alert_from_row(row) if row is not None else None

    def resolve_alert(self, alert_id: int) -> bool:
        """Resolve one open alert; returns False when it was already resolved."""

        connection = self.connect()
        with self._lock, connection:
            cursor = connection.execute(
                "UPDATE alerts SET resolved_at = ? WHERE id = ? AND resolved_at IS NULL",
                (self.clock.timestamp(), alert_id),
            )
            return cursor.rowcount > 0

    def resolve_alerts(
        self, device_id: int, kind: str, interface_id: Optional[int] = None
    ) -> int:
        """Resolve all open alerts matching a target and kind; return count."""

        connection = self.connect()
        with self._lock, connection:
            cursor = connection.execute(
                "UPDATE alerts SET resolved_at = ? WHERE device_id = ? AND interface_id IS ? "
                "AND kind = ? AND resolved_at IS NULL",
                (self.clock.timestamp(), device_id, interface_id, kind),
            )
            return int(cursor.rowcount)

    def list_alerts(self, active_only: bool = True, limit: int = 100) -> List[Alert]:
        """Return alerts newest first, active only by default."""

        if limit <= 0:
            raise ValueError("limit must be positive")
        connection = self.connect()
        with self._lock:
            if active_only:
                rows = connection.execute(
                    "SELECT * FROM alerts WHERE resolved_at IS NULL ORDER BY id DESC LIMIT ?",
                    (limit,),
                ).fetchall()
            else:
                rows = connection.execute(
                    "SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,)
                ).fetchall()
        return [_alert_from_row(row) for row in rows]

    def count_alerts(self, active_only: bool = True) -> int:
        """Return the number of alerts (open ones by default)."""

        connection = self.connect()
        with self._lock:
            if active_only:
                row = connection.execute(
                    "SELECT COUNT(*) AS total FROM alerts WHERE resolved_at IS NULL"
                ).fetchone()
            else:
                row = connection.execute("SELECT COUNT(*) AS total FROM alerts").fetchone()
        return int(row["total"])


def _device_from_row(row: sqlite3.Row) -> Device:
    return Device(
        id=int(row["id"]),
        address=str(row["address"]),
        name=str(row["name"]),
        community=str(row["community"]),
        reachable=bool(row["reachable"]),
        last_error=row["last_error"],
        last_polled_at=row["last_polled_at"],
        created_at=str(row["created_at"]),
        updated_at=str(row["updated_at"]),
    )


def _interface_from_row(row: sqlite3.Row) -> Interface:
    return Interface(
        id=int(row["id"]),
        device_id=int(row["device_id"]),
        if_index=int(row["if_index"]),
        name=str(row["name"]),
        alias=str(row["alias"]),
        speed_bps=None if row["speed_bps"] is None else int(row["speed_bps"]),
    )


def _sample_from_row(row: sqlite3.Row) -> Sample:
    return Sample(
        id=int(row["id"]),
        interface_id=int(row["interface_id"]),
        sampled_at=str(row["sampled_at"]),
        in_octets=int(row["in_octets"]),
        out_octets=int(row["out_octets"]),
        counter_bits=int(row["counter_bits"]),
        in_bps=None if row["in_bps"] is None else float(row["in_bps"]),
        out_bps=None if row["out_bps"] is None else float(row["out_bps"]),
        utilization_pct=None if row["utilization_pct"] is None else float(row["utilization_pct"]),
        oper_status=int(row["oper_status"]),
    )


def _alert_from_row(row: sqlite3.Row) -> Alert:
    return Alert(
        id=int(row["id"]),
        device_id=int(row["device_id"]),
        interface_id=None if row["interface_id"] is None else int(row["interface_id"]),
        kind=str(row["kind"]),
        severity=str(row["severity"]),
        message=str(row["message"]),
        value=None if row["value"] is None else float(row["value"]),
        threshold=None if row["threshold"] is None else float(row["threshold"]),
        created_at=str(row["created_at"]),
        resolved_at=row["resolved_at"],
    )
