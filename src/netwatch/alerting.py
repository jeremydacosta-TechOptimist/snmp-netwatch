"""Threshold rules that turn poll results into alert decisions.

The functions here are pure: they receive plain values and return
:class:`AlertDecision` records. Persistence is the poller's job, which keeps the
rules easy to test and easy to extend. Three conditions are supported:

* interface utilization at or above a percentage threshold,
* interface operational status not ``up`` (RFC 2863 value 1),
* an unreachable device (timeout or protocol failure).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

from .mib import oper_status_text

__all__ = [
    "KIND_UTILIZATION",
    "KIND_OPER_DOWN",
    "KIND_UNREACHABLE",
    "SEVERITY_WARNING",
    "SEVERITY_CRITICAL",
    "Thresholds",
    "AlertDecision",
    "evaluate_interface",
    "evaluate_unreachable",
]

KIND_UTILIZATION = "utilization"
KIND_OPER_DOWN = "oper_status_down"
KIND_UNREACHABLE = "device_unreachable"

SEVERITY_WARNING = "warning"
SEVERITY_CRITICAL = "critical"


@dataclass(frozen=True)
class Thresholds:
    """Alert rules shared by the poller, reports and the dashboard."""

    utilization_pct: float = 80.0
    oper_status_down: bool = True
    device_unreachable: bool = True

    def __post_init__(self) -> None:
        if not isinstance(self.utilization_pct, (int, float)) or isinstance(self.utilization_pct, bool):
            raise ValueError("utilization threshold must be a number")
        if not 0 < float(self.utilization_pct) <= 1000:
            raise ValueError("utilization threshold must be within (0, 1000] percent")


@dataclass(frozen=True)
class AlertDecision:
    """One rule outcome: either open an alert or resolve the open one."""

    kind: str
    active: bool
    severity: str
    message: str
    value: Optional[float] = None
    threshold: Optional[float] = None

    @property
    def resolve(self) -> bool:
        """True when this decision clears a previously opened alert."""

        return not self.active


def evaluate_interface(
    interface_label: str,
    oper_status: int,
    utilization_pct: Optional[float],
    thresholds: Thresholds,
) -> List[AlertDecision]:
    """Evaluate the interface-level rules for one poll result."""

    decisions: List[AlertDecision] = []
    if thresholds.oper_status_down:
        status_text = oper_status_text(oper_status)
        if oper_status != 1:
            decisions.append(
                AlertDecision(
                    kind=KIND_OPER_DOWN,
                    active=True,
                    severity=SEVERITY_CRITICAL if oper_status == 2 else SEVERITY_WARNING,
                    message=f"{interface_label}: oper status is {status_text} (expected up)",
                    value=float(oper_status),
                    threshold=1.0,
                )
            )
        else:
            decisions.append(
                AlertDecision(
                    kind=KIND_OPER_DOWN,
                    active=False,
                    severity=SEVERITY_WARNING,
                    message=f"{interface_label}: oper status is up",
                    value=1.0,
                    threshold=1.0,
                )
            )
    if utilization_pct is not None:
        util = float(utilization_pct)
        threshold = float(thresholds.utilization_pct)
        if util >= threshold:
            decisions.append(
                AlertDecision(
                    kind=KIND_UTILIZATION,
                    active=True,
                    severity=SEVERITY_CRITICAL if util >= 95.0 else SEVERITY_WARNING,
                    message=(
                        f"{interface_label}: utilization {util:.1f}% is at or above "
                        f"the {threshold:.1f}% threshold"
                    ),
                    value=round(util, 3),
                    threshold=threshold,
                )
            )
        else:
            decisions.append(
                AlertDecision(
                    kind=KIND_UTILIZATION,
                    active=False,
                    severity=SEVERITY_WARNING,
                    message=f"{interface_label}: utilization {util:.1f}% is below the {threshold:.1f}% threshold",
                    value=round(util, 3),
                    threshold=threshold,
                )
            )
    return decisions


def evaluate_unreachable(address: str, error: Optional[str], thresholds: Thresholds) -> AlertDecision:
    """Evaluate the device reachability rule for one poll attempt."""

    if not thresholds.device_unreachable or not error:
        return AlertDecision(
            kind=KIND_UNREACHABLE,
            active=False,
            severity=SEVERITY_CRITICAL,
            message=f"{address}: reachable",
        )
    return AlertDecision(
        kind=KIND_UNREACHABLE,
        active=True,
        severity=SEVERITY_CRITICAL,
        message=f"{address}: unreachable ({error})",
        threshold=None,
    )
