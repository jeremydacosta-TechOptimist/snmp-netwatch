"""MIB objects implemented by the built-in simulator and read by the poller.

The OIDs below come from the standard SNMPv2-MIB and IF-MIB definitions. Only
the objects needed by the monitor are listed; keeping the table small makes the
simulator easy to audit and the poller predictable.
"""

from __future__ import annotations

from typing import Dict

__all__ = [
    "SYS_DESCR",
    "SYS_OBJECT_ID",
    "SYS_UPTIME",
    "SYS_CONTACT",
    "SYS_NAME",
    "SYS_LOCATION",
    "SYS_SERVICES",
    "IF_NUMBER",
    "IF_INDEX",
    "IF_DESCR",
    "IF_TYPE",
    "IF_SPEED",
    "IF_ADMIN_STATUS",
    "IF_OPER_STATUS",
    "IF_IN_OCTETS",
    "IF_OUT_OCTETS",
    "IF_IN_ERRORS",
    "IF_OUT_ERRORS",
    "IF_NAME",
    "IF_ALIAS",
    "IF_HIGH_SPEED",
    "IF_HC_IN_OCTETS",
    "IF_HC_OUT_OCTETS",
    "OPER_STATUS_TEXT",
    "oper_status_text",
]

SYS_DESCR = "1.3.6.1.2.1.1.1.0"
SYS_OBJECT_ID = "1.3.6.1.2.1.1.2.0"
SYS_UPTIME = "1.3.6.1.2.1.1.3.0"
SYS_CONTACT = "1.3.6.1.2.1.1.4.0"
SYS_NAME = "1.3.6.1.2.1.1.5.0"
SYS_LOCATION = "1.3.6.1.2.1.1.6.0"
SYS_SERVICES = "1.3.6.1.2.1.1.7.0"

IF_NUMBER = "1.3.6.1.2.1.2.1.0"
IF_INDEX = "1.3.6.1.2.1.2.2.1.1"
IF_DESCR = "1.3.6.1.2.1.2.2.1.2"
IF_TYPE = "1.3.6.1.2.1.2.2.1.3"
IF_SPEED = "1.3.6.1.2.1.2.2.1.5"
IF_ADMIN_STATUS = "1.3.6.1.2.1.2.2.1.7"
IF_OPER_STATUS = "1.3.6.1.2.1.2.2.1.8"
IF_IN_OCTETS = "1.3.6.1.2.1.2.2.1.10"
IF_IN_ERRORS = "1.3.6.1.2.1.2.2.1.14"
IF_OUT_OCTETS = "1.3.6.1.2.1.2.2.1.16"
IF_OUT_ERRORS = "1.3.6.1.2.1.2.2.1.20"
IF_NAME = "1.3.6.1.2.1.31.1.1.1.1"
IF_HC_IN_OCTETS = "1.3.6.1.2.1.31.1.1.1.6"
IF_HC_OUT_OCTETS = "1.3.6.1.2.1.31.1.1.1.10"
IF_HIGH_SPEED = "1.3.6.1.2.1.31.1.1.1.15"
IF_ALIAS = "1.3.6.1.2.1.31.1.1.1.18"

# ifOperStatus values from RFC 2863.
OPER_STATUS_TEXT: Dict[int, str] = {
    1: "up",
    2: "down",
    3: "testing",
    4: "unknown",
    5: "dormant",
    6: "notPresent",
    7: "lowerLayerDown",
}


def oper_status_text(value: int) -> str:
    """Return the RFC 2863 label for an ifOperStatus value."""

    return OPER_STATUS_TEXT.get(int(value), f"unknown({value})")
