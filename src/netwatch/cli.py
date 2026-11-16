"""Command line interface for ``netwatch``.

Sub-commands:

``init``       create the SQLite database and schema
``poll``       poll the built-in simulator or real SNMPv2c devices
``dashboard``  render the self-contained HTML dashboard to a file
``report``     print a monitoring report from stored history
``alerts``     list active (or all) alerts
``serve``      serve the dashboard and JSON API over HTTP
``agent``      run the simulator as a standalone UDP agent

Exit codes follow the project convention: 0 success, 2 bad usage, 1 runtime
failure (for example an unreachable device or an unreadable database).
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Callable, List, Optional, Sequence

from . import __version__
from .agent import SimulatedDevice, SnmpAgent
from .alerting import Thresholds
from .clock import SystemClock
from .dashboard import render_dashboard
from .poller import Poller, PollResult, parse_endpoint
from .reporting import (
    build_alerts_payload,
    build_summary,
    poll_result_to_dict,
    render_alerts,
    render_poll_result,
    render_report,
)
from .server import DashboardServer
from .snmp import SnmpError
from .storage import DEFAULT_DB_FILE, Store, StoreError

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2

DEFAULT_RETAIN_HOURS = 168.0
DEFAULT_SERVE_PORT = 8080
DEFAULT_AGENT_PORT = 1161


class CliUsageError(ValueError):
    """Raised for invalid argument combinations detected after argparse."""


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser with all sub-commands."""

    parser = argparse.ArgumentParser(
        prog="netwatch",
        description=(
            "Zero-dependency SNMPv2c network monitor: poll interface tables, "
            "compute rates and utilization, keep SQLite history, raise threshold "
            "alerts and render a self-contained HTML dashboard."
        ),
        epilog=(
            "exit codes: 0 success, 1 runtime failure, 2 bad usage. "
            "Run 'netwatch poll --simulate' for a demo that needs no hardware."
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", metavar="COMMAND", required=True)

    init_parser = subparsers.add_parser(
        "init", help="create the SQLite database and schema", description="Create the database schema."
    )
    _add_db_option(init_parser)
    init_parser.set_defaults(handler=cmd_init)

    poll_parser = subparsers.add_parser(
        "poll",
        help="poll SNMPv2c devices and store samples",
        description="Poll the built-in simulator or real SNMPv2c devices and store interface history.",
    )
    target = poll_parser.add_mutually_exclusive_group(required=True)
    target.add_argument(
        "--simulate",
        action="store_true",
        help="poll the built-in localhost agent simulator (no hardware required)",
    )
    target.add_argument(
        "--device",
        action="append",
        metavar="HOST[:PORT]",
        help="SNMPv2c agent to poll; repeat the option for several devices",
    )
    _add_db_option(poll_parser)
    poll_parser.add_argument("--community", default="public", help="SNMPv2c community (default: public)")
    poll_parser.add_argument(
        "--count",
        type=int,
        default=None,
        metavar="N",
        help="number of polls per device (default: 2 for --simulate, 1 otherwise)",
    )
    poll_parser.add_argument(
        "--interval",
        type=float,
        default=1.0,
        metavar="SECONDS",
        help="delay between polls (default: 1.0)",
    )
    poll_parser.add_argument("--timeout", type=float, default=1.0, metavar="SECONDS", help="SNMP timeout (default: 1.0)")
    poll_parser.add_argument("--retries", type=int, default=1, metavar="N", help="SNMP retries per request (default: 1)")
    poll_parser.add_argument(
        "--util-threshold",
        type=float,
        default=80.0,
        metavar="PERCENT",
        help="interface utilization alert threshold (default: 80)",
    )
    poll_parser.add_argument("--no-oper-alerts", action="store_true", help="disable operational-status alerts")
    poll_parser.add_argument(
        "--no-unreachable-alerts", action="store_true", help="disable device-unreachable alerts"
    )
    poll_parser.add_argument(
        "--retain-hours",
        type=float,
        default=DEFAULT_RETAIN_HOURS,
        metavar="HOURS",
        help=f"delete samples older than this after polling, 0 disables (default: {DEFAULT_RETAIN_HOURS:g})",
    )
    poll_parser.add_argument("--json", action="store_true", help="emit machine-readable JSON on stdout")
    poll_parser.set_defaults(handler=cmd_poll)

    dashboard_parser = subparsers.add_parser(
        "dashboard",
        help="render the HTML dashboard to a file",
        description="Render the self-contained HTML dashboard (inline CSS and SVG, no external assets).",
    )
    _add_db_option(dashboard_parser)
    dashboard_parser.add_argument(
        "--output",
        "-o",
        default="dashboard.html",
        metavar="PATH",
        help="output file, '-' for stdout (default: dashboard.html)",
    )
    dashboard_parser.add_argument("--refresh-seconds", type=int, default=30, metavar="N", help="meta refresh period (default: 30)")
    dashboard_parser.add_argument("--util-threshold", type=float, default=80.0, metavar="PERCENT", help="threshold shown in the dashboard")
    dashboard_parser.set_defaults(handler=cmd_dashboard)

    report_parser = subparsers.add_parser(
        "report",
        help="print a monitoring report",
        description="Print a device/interface/alert report built from stored history.",
    )
    _add_db_option(report_parser)
    report_parser.add_argument("--util-threshold", type=float, default=80.0, metavar="PERCENT", help="threshold shown in the report")
    report_parser.add_argument("--json", action="store_true", help="emit the summary as JSON")
    report_parser.set_defaults(handler=cmd_report)

    alerts_parser = subparsers.add_parser(
        "alerts",
        help="list alerts",
        description="List active alerts, or all alerts including resolved ones.",
    )
    _add_db_option(alerts_parser)
    alerts_parser.add_argument("--all", action="store_true", help="include resolved alerts")
    alerts_parser.add_argument("--limit", type=int, default=100, metavar="N", help="maximum rows (default: 100)")
    alerts_parser.add_argument("--json", action="store_true", help="emit JSON")
    alerts_parser.set_defaults(handler=cmd_alerts)

    serve_parser = subparsers.add_parser(
        "serve",
        help="serve the dashboard and JSON API over HTTP",
        description="Serve the dashboard on / and JSON on /api/summary and /api/health.",
    )
    _add_db_option(serve_parser)
    serve_parser.add_argument("--host", default="127.0.0.1", help="bind address (default: 127.0.0.1)")
    serve_parser.add_argument("--port", type=int, default=DEFAULT_SERVE_PORT, metavar="PORT", help=f"bind port (default: {DEFAULT_SERVE_PORT})")
    serve_parser.add_argument("--refresh-seconds", type=int, default=30, metavar="N", help="dashboard refresh period (default: 30)")
    serve_parser.add_argument("--util-threshold", type=float, default=80.0, metavar="PERCENT", help="utilization threshold")
    serve_parser.set_defaults(handler=cmd_serve)

    agent_parser = subparsers.add_parser(
        "agent",
        help="run the SNMPv2c agent simulator standalone",
        description="Run the localhost SNMPv2c agent simulator until interrupted (Ctrl+C).",
    )
    agent_parser.add_argument("--host", default="127.0.0.1", help="bind address (default: 127.0.0.1)")
    agent_parser.add_argument("--port", type=int, default=DEFAULT_AGENT_PORT, metavar="PORT", help=f"UDP port (default: {DEFAULT_AGENT_PORT})")
    agent_parser.add_argument("--community", default="public", help="accepted community (default: public)")
    agent_parser.add_argument("--name", default="simsw01.example", help="sysName exposed by the agent")
    agent_parser.set_defaults(handler=cmd_agent)

    return parser


def _add_db_option(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--db",
        default=DEFAULT_DB_FILE,
        metavar="PATH",
        help=f"SQLite database path (default: {DEFAULT_DB_FILE})",
    )


def _open_store(path: str) -> Store:
    store = Store(path)
    store.initialize()
    return store


def _thresholds(args: argparse.Namespace) -> Thresholds:
    return Thresholds(
        utilization_pct=getattr(args, "util_threshold", 80.0),
        oper_status_down=not getattr(args, "no_oper_alerts", False),
        device_unreachable=not getattr(args, "no_unreachable_alerts", False),
    )


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise CliUsageError(message)


def cmd_init(args: argparse.Namespace) -> int:
    """Create the database schema and report what exists."""

    with _open_store(args.db) as store:
        tables = store.table_names()
        version = store.schema_version()
    print(f"initialized {args.db} (schema v{version}, tables: {', '.join(tables)})")
    return EXIT_OK


def cmd_poll(args: argparse.Namespace) -> int:
    """Poll targets once or repeatedly, storing history and evaluating alerts."""

    count = args.count if args.count is not None else (2 if args.simulate else 1)
    _require(count >= 1, "--count must be at least 1")
    _require(args.interval >= 0, "--interval cannot be negative")
    _require(args.timeout > 0, "--timeout must be positive")
    _require(args.retries >= 0, "--retries cannot be negative")
    _require(args.retain_hours >= 0, "--retain-hours cannot be negative")
    thresholds = _thresholds(args)
    store = _open_store(args.db)
    results: List[PollResult] = []
    pruned = 0
    sample_count = 0
    active_alerts = 0
    try:
        if args.simulate:
            results = _run_simulation(store, thresholds, args, count)
        else:
            poller = Poller(
                store,
                thresholds,
                timeout=args.timeout,
                retries=args.retries,
            )
            for target in args.device:
                try:
                    host, port = parse_endpoint(target)
                except ValueError as exc:
                    raise CliUsageError(str(exc)) from exc
                for attempt in range(count):
                    result = poller.poll(
                        target,
                        host=host,
                        port=port,
                        community=args.community,
                    )
                    results.append(result)
                    if not args.json:
                        print(render_poll_result(result))
                        if attempt + 1 < count:
                            print()
                    if attempt + 1 < count:
                        time.sleep(args.interval)
        if args.retain_hours > 0:
            pruned = store.prune_samples(args.retain_hours)
        sample_count = store.count_samples()
        active_alerts = store.count_alerts(active_only=True)
    finally:
        store.close()
    if args.json:
        print(json.dumps([poll_result_to_dict(result) for result in results], indent=2))
    else:
        if pruned:
            print(f"history retention: removed {pruned} sample(s) older than {args.retain_hours:g} h")
        print(
            f"{len(results)} poll(s) completed; {sample_count} sample(s) stored; "
            f"{active_alerts} active alert(s)"
        )
    unreachable = [result for result in results if not result.reachable]
    if unreachable:
        if not args.json:
            print(
                f"netwatch: {len(unreachable)} of {len(results)} poll(s) failed",
                file=sys.stderr,
            )
        return EXIT_ERROR
    return EXIT_OK


def _run_simulation(
    store: Store, thresholds: Thresholds, args: argparse.Namespace, count: int
) -> List[PollResult]:
    """Run the built-in agent and poll it ``count`` times."""

    clock = SystemClock()
    device = SimulatedDevice(clock=clock)
    agent = SnmpAgent(device, host="127.0.0.1", port=0)
    agent.start()
    results: List[PollResult] = []
    try:
        host, port = agent.address
        if not args.json:
            print(f"simulator listening on udp://{host}:{port} (community: {args.community})")
            print("simulated device: simsw01.example with 3 interfaces (1 Gigabit uplink, server, spare)")
        simulator = store.upsert_device("simulator", name="simulator", community=args.community)
        # A new simulator process starts its counters from scratch, so old
        # samples of the simulator device are not comparable and are removed.
        store.reset_samples_for_device(simulator.id)
        poller = Poller(store, thresholds, clock=clock, timeout=args.timeout, retries=args.retries)
        for index in range(count):
            result = poller.poll(
                "simulator",
                host=host,
                port=port,
                community=args.community,
                name="simulator",
            )
            results.append(result)
            if not args.json:
                print(render_poll_result(result))
                if index + 1 < count:
                    print()
            if index + 1 < count:
                time.sleep(args.interval)
    finally:
        agent.stop()
    return results


def cmd_dashboard(args: argparse.Namespace) -> int:
    """Render the self-contained HTML dashboard."""

    _require(args.output != "", "--output cannot be empty")
    store = _open_store(args.db)
    try:
        document = render_dashboard(
            store,
            thresholds=_thresholds(args),
            generated_at=SystemClock().utcnow(),
            refresh_seconds=args.refresh_seconds,
        )
    finally:
        store.close()
    if args.output == "-":
        sys.stdout.write(document)
        return EXIT_OK
    output = Path(args.output)
    if str(output.parent) not in ("", "."):
        output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(document, encoding="utf-8", newline="\n")
    print(f"dashboard written to {args.output} ({len(document)} bytes)")
    return EXIT_OK


def cmd_report(args: argparse.Namespace) -> int:
    """Print a monitoring report or its JSON summary."""

    store = _open_store(args.db)
    try:
        thresholds = _thresholds(args)
        generated = SystemClock().utcnow()
        if args.json:
            print(json.dumps(build_summary(store, thresholds, generated), indent=2))
        else:
            print(render_report(store, thresholds, generated))
    finally:
        store.close()
    return EXIT_OK


def cmd_alerts(args: argparse.Namespace) -> int:
    """List active or resolved alerts."""

    _require(args.limit > 0, "--limit must be positive")
    store = _open_store(args.db)
    try:
        if args.json:
            print(
                json.dumps(
                    build_alerts_payload(store, include_resolved=args.all, limit=args.limit),
                    indent=2,
                )
            )
        else:
            print(render_alerts(store, include_resolved=args.all, limit=args.limit))
    finally:
        store.close()
    return EXIT_OK


def cmd_serve(args: argparse.Namespace) -> int:
    """Serve the dashboard and JSON API until interrupted."""

    _require(0 < args.port <= 65535, "--port must be within 1..65535")
    store = _open_store(args.db)
    try:
        server = DashboardServer(
            store,
            host=args.host,
            port=args.port,
            thresholds=_thresholds(args),
            refresh_seconds=args.refresh_seconds,
        )
        server.serve_forever()
    finally:
        store.close()
    return EXIT_OK


def cmd_agent(args: argparse.Namespace) -> int:
    """Run the simulator as a standalone agent until interrupted."""

    _require(0 < args.port <= 65535, "--port must be within 1..65535")
    device = SimulatedDevice(name=args.name)
    agent = SnmpAgent(device, host=args.host, port=args.port, community=args.community)
    agent.start()
    try:
        host, port = agent.address
        print(f"simulated SNMPv2c agent listening on udp://{host}:{port}", flush=True)
        print(
            f"sysName: {device.name} | community: {args.community} | press Ctrl+C to stop",
            flush=True,
        )
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        pass
    finally:
        agent.stop()
    print(f"agent stopped after {agent.requests_handled} request(s)")
    return EXIT_OK


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Run the CLI and return the process exit code."""

    parser = build_parser()
    args = parser.parse_args(argv)
    handler: Callable[[argparse.Namespace], int] = args.handler
    try:
        return int(handler(args))
    except CliUsageError as exc:
        parser.print_usage(sys.stderr)
        print(f"netwatch: error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except (SnmpError, StoreError, OSError, ValueError) as exc:
        print(f"netwatch: error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except KeyboardInterrupt:
        print("netwatch: interrupted", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
