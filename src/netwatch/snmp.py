"""SNMPv2c message codec and a small synchronous UDP client.

The module implements the wire format of SNMPv2c (RFC 3416 / RFC 3418): the
outer message is a SEQUENCE of version, community and one PDU. A PDU is a
request-id, two integer fields (error-status / error-index for most PDUs,
non-repeaters / max-repetitions for GETBULK) and a varbind list.

:class:`SnmpClient` sends a single datagram per request and waits for the
response with a per-request id, ignoring stale or malformed datagrams. It is
intentionally synchronous and stateless between calls, like a minimal
monitoring probe.
"""

from __future__ import annotations

import secrets
import socket
import time
from dataclasses import dataclass, field
from typing import Any, Iterable, List, Optional, Sequence

from .ber import (
    EXCEPTION_TAGS,
    TAG_COUNTER32,
    TAG_COUNTER64,
    TAG_GAUGE32,
    TAG_INTEGER,
    TAG_IP_ADDRESS,
    TAG_NULL,
    TAG_OCTET_STRING,
    TAG_OID,
    TAG_SEQUENCE,
    TAG_TIMETICKS,
    BerError,
    BerReader,
    decode_integer,
    decode_ip_address,
    decode_oid,
    encode_integer,
    encode_ip_address,
    encode_octet_string,
    encode_oid,
    encode_sequence,
    encode_tlv,
    join_tlvs,
)
from .oid import is_prefix, oid_key

__all__ = [
    "SNMP_VERSION_2C",
    "PDU_GET",
    "PDU_GETNEXT",
    "PDU_RESPONSE",
    "PDU_SET",
    "PDU_GETBULK",
    "PDU_NAMES",
    "ERROR_STATUS_NAMES",
    "NO_ERROR",
    "SnmpError",
    "SnmpEncodeError",
    "SnmpDecodeError",
    "SnmpProtocolError",
    "SnmpTimeoutError",
    "SnmpResponseError",
    "WalkLimitError",
    "VarBind",
    "SnmpMessage",
    "SnmpClient",
    "decode_varbind_value",
    "encode_varbind_value",
]

SNMP_VERSION_2C = 1

PDU_GET = 0xA0
PDU_GETNEXT = 0xA1
PDU_RESPONSE = 0xA2
PDU_SET = 0xA3
PDU_GETBULK = 0xA5

PDU_NAMES = {
    PDU_GET: "GET",
    PDU_GETNEXT: "GETNEXT",
    PDU_RESPONSE: "RESPONSE",
    PDU_SET: "SET",
    PDU_GETBULK: "GETBULK",
}
PDU_TAGS = frozenset(PDU_NAMES)

NO_ERROR = 0
ERROR_STATUS_NAMES = {
    0: "noError",
    1: "tooBig",
    2: "noSuchName",
    3: "badValue",
    4: "readOnly",
    5: "genErr",
    6: "noAccess",
    7: "wrongType",
    8: "wrongLength",
    9: "wrongEncoding",
    10: "wrongValue",
    11: "noCreation",
    12: "inconsistentValue",
    13: "resourceUnavailable",
    14: "commitFailed",
    15: "undoFailed",
    16: "authorizationError",
    17: "notWritable",
    18: "inconsistentName",
}

_UNSIGNED_TAGS = (TAG_COUNTER32, TAG_GAUGE32, TAG_TIMETICKS, TAG_COUNTER64)
_UNSIGNED_MAXIMUM = {
    TAG_COUNTER32: 2**32 - 1,
    TAG_GAUGE32: 2**32 - 1,
    TAG_TIMETICKS: 2**32 - 1,
    TAG_COUNTER64: 2**64 - 1,
}

# Longest datagram SNMP can carry over UDP is 65507 bytes; read buffering above
# that is harmless but keeps room for oversized agent replies.
_MAX_DATAGRAM = 65535


class SnmpError(Exception):
    """Base class for SNMP encoding, decoding and transport failures."""


class SnmpEncodeError(SnmpError, ValueError):
    """Raised when a Python value cannot be encoded as an SNMP value."""


class SnmpDecodeError(SnmpError, ValueError):
    """Raised when a datagram is not a valid SNMPv2c message."""


class SnmpProtocolError(SnmpError):
    """Raised when an agent behaves contrary to the SNMPv2c protocol."""


class SnmpTimeoutError(SnmpError):
    """Raised when no matching response arrives before the timeout."""


class WalkLimitError(SnmpError):
    """Raised when a GETNEXT walk exceeds its configured row limit."""


class SnmpResponseError(SnmpError):
    """Raised when an agent answers with a non-zero error-status."""

    def __init__(self, error_status: int, error_index: int = 0) -> None:
        self.error_status = int(error_status)
        self.error_index = int(error_index)
        self.status_name = ERROR_STATUS_NAMES.get(self.error_status, f"errorStatus {self.error_status}")
        location = f" at varbind {self.error_index}" if self.error_index else ""
        super().__init__(f"agent returned {self.status_name} ({self.error_status}){location}")


def encode_varbind_value(tag: int, value: Any) -> bytes:
    """Encode a Python value as the TLV carried inside a varbind.

    BER-level problems (invalid OID text, oversized length, wrong IP address)
    are re-raised as :class:`SnmpEncodeError` so callers only handle SNMP errors.
    """

    try:
        return _encode_varbind_value(tag, value)
    except BerError as exc:
        raise SnmpEncodeError(str(exc)) from exc


def _encode_varbind_value(tag: int, value: Any) -> bytes:
    if tag in EXCEPTION_TAGS:
        return encode_tlv(tag, b"")
    if tag == TAG_NULL:
        if value is not None:
            raise SnmpEncodeError("NULL varbind value must be None")
        return encode_tlv(TAG_NULL, b"")
    if tag == TAG_INTEGER:
        if isinstance(value, bool) or not isinstance(value, int):
            raise SnmpEncodeError(f"INTEGER varbind value must be int, got {type(value).__name__}")
        return encode_integer(value)
    if tag in _UNSIGNED_TAGS:
        if isinstance(value, bool) or not isinstance(value, int):
            raise SnmpEncodeError(f"value for tag 0x{tag:02x} must be int, got {type(value).__name__}")
        if value < 0 or value > _UNSIGNED_MAXIMUM[tag]:
            raise SnmpEncodeError(f"value {value} is out of range for tag 0x{tag:02x}")
        return encode_integer(value, tag)
    if tag == TAG_OCTET_STRING:
        return encode_octet_string(value)
    if tag == TAG_OID:
        return encode_oid(value)
    if tag == TAG_IP_ADDRESS:
        return encode_ip_address(value)
    raise SnmpEncodeError(f"unsupported varbind value tag 0x{tag:02x}")


def decode_varbind_value(tag: int, payload: bytes) -> Any:
    """Decode a varbind value TLV payload into a Python value.

    OCTET STRING stays as raw ``bytes`` because SNMP does not discriminate
    between display strings and binary values; callers decode text themselves.
    Malformed BER payloads are re-raised as :class:`SnmpDecodeError`.
    """

    try:
        return _decode_varbind_value(tag, payload)
    except BerError as exc:
        raise SnmpDecodeError(str(exc)) from exc


def _decode_varbind_value(tag: int, payload: bytes) -> Any:
    if tag == TAG_NULL:
        if payload:
            raise SnmpDecodeError("NULL varbind value must be empty")
        return None
    if tag == TAG_INTEGER:
        return decode_integer(payload)
    if tag in _UNSIGNED_TAGS:
        value = decode_integer(payload)
        if value < 0 or value > _UNSIGNED_MAXIMUM[tag]:
            raise SnmpDecodeError(f"value {value} is out of range for tag 0x{tag:02x}")
        return value
    if tag == TAG_OCTET_STRING:
        return bytes(payload)
    if tag == TAG_OID:
        return decode_oid(payload)
    if tag == TAG_IP_ADDRESS:
        return decode_ip_address(payload)
    if tag in EXCEPTION_TAGS:
        if payload:
            raise SnmpDecodeError(f"exception tag 0x{tag:02x} must have an empty payload")
        return None
    raise SnmpDecodeError(f"unsupported varbind value tag 0x{tag:02x}")


@dataclass(frozen=True)
class VarBind:
    """A single SNMP variable binding: object identifier, type tag and value."""

    oid: str
    tag: int = TAG_NULL
    value: Any = None

    @property
    def is_exception(self) -> bool:
        """True when the varbind carries noSuchObject/noSuchInstance/endOfMibView."""

        return self.tag in EXCEPTION_TAGS

    def encode(self) -> bytes:
        """Encode the varbind as a SEQUENCE of OID and value."""

        return encode_sequence(encode_oid(self.oid), encode_varbind_value(self.tag, self.value))

    @classmethod
    def decode_from(cls, reader: BerReader) -> "VarBind":
        """Read one varbind SEQUENCE from ``reader``."""

        try:
            payload = reader.read_expect(TAG_SEQUENCE, "varbind")
            inner = BerReader(payload)
            oid = decode_oid(inner.read_expect(TAG_OID, "varbind OID"))
            tag, value_payload = inner.read_tlv()
            inner.require_end("varbind")
        except BerError as exc:
            raise SnmpDecodeError(f"malformed varbind: {exc}") from exc
        return cls(oid=oid, tag=tag, value=decode_varbind_value(tag, value_payload))


@dataclass
class SnmpMessage:
    """An SNMPv2c message.

    For GETBULK PDUs the two integer PDU fields are non-repeaters and
    max-repetitions; they share the wire positions of error-status and
    error-index, which is why the same dataclass fields are reused and exposed
    through :attr:`non_repeaters` and :attr:`max_repetitions`.
    """

    community: str = "public"
    pdu_type: int = PDU_GET
    request_id: int = 0
    error_status: int = 0
    error_index: int = 0
    varbinds: List[VarBind] = field(default_factory=list)
    version: int = SNMP_VERSION_2C

    @property
    def pdu_name(self) -> str:
        """Human-readable PDU type name."""

        return PDU_NAMES.get(self.pdu_type, f"0x{self.pdu_type:02x}")

    @property
    def non_repeaters(self) -> int:
        """GETBULK non-repeaters field (alias of ``error_status``)."""

        return self.error_status

    @property
    def max_repetitions(self) -> int:
        """GETBULK max-repetitions field (alias of ``error_index``)."""

        return self.error_index

    def encode(self) -> bytes:
        """Encode the message as a complete BER datagram."""

        if self.pdu_type not in PDU_TAGS:
            raise SnmpEncodeError(f"unsupported PDU type 0x{self.pdu_type:02x}")
        if not -2**31 <= self.request_id <= 2**31 - 1:
            raise SnmpEncodeError(f"request-id {self.request_id} does not fit in Integer32")
        varbind_list = encode_tlv(TAG_SEQUENCE, join_tlvs(varbind.encode() for varbind in self.varbinds))
        pdu = encode_tlv(
            self.pdu_type,
            join_tlvs(
                (
                    encode_integer(self.request_id),
                    encode_integer(self.error_status),
                    encode_integer(self.error_index),
                    varbind_list,
                )
            ),
        )
        message = join_tlvs((encode_integer(self.version), encode_octet_string(self.community), pdu))
        return encode_tlv(TAG_SEQUENCE, message)

    @classmethod
    def decode(cls, data: bytes) -> "SnmpMessage":
        """Decode a complete SNMPv2c datagram, rejecting anything malformed."""

        try:
            return cls._decode(data)
        except BerError as exc:
            raise SnmpDecodeError(f"malformed SNMP message: {exc}") from exc

    @classmethod
    def _decode(cls, data: bytes) -> "SnmpMessage":
        reader = BerReader(data)
        message_payload = reader.read_expect(TAG_SEQUENCE, "SNMP message")
        reader.require_end("SNMP message")
        message = BerReader(message_payload)
        version = message.read_integer("version")
        if version != SNMP_VERSION_2C:
            raise SnmpDecodeError(f"unsupported SNMP version {version}; only v2c is supported")
        community = message.read_expect(TAG_OCTET_STRING, "community").decode("utf-8", "replace")
        pdu_tag, pdu_payload = message.read_tlv()
        message.require_end("SNMP message")
        if pdu_tag not in PDU_TAGS:
            raise SnmpDecodeError(f"unsupported PDU type 0x{pdu_tag:02x}")
        pdu = BerReader(pdu_payload)
        request_id = pdu.read_integer("request-id")
        error_status = pdu.read_integer("error-status/non-repeaters")
        error_index = pdu.read_integer("error-index/max-repetitions")
        varbind_payload = pdu.read_expect(TAG_SEQUENCE, "varbind list")
        pdu.require_end("PDU")
        varbinds: List[VarBind] = []
        varbind_reader = BerReader(varbind_payload)
        while not varbind_reader.at_end():
            varbinds.append(VarBind.decode_from(varbind_reader))
        if error_status < 0 or error_index < 0:
            raise SnmpDecodeError("PDU integer fields cannot be negative")
        return cls(
            community=community,
            pdu_type=pdu_tag,
            request_id=request_id,
            error_status=error_status,
            error_index=error_index,
            varbinds=varbinds,
        )

    @classmethod
    def get(cls, community: str, request_id: int, oids: Iterable[str]) -> "SnmpMessage":
        """Build a GET request for the given OIDs."""

        return cls._request(PDU_GET, community, request_id, oids)

    @classmethod
    def get_next(cls, community: str, request_id: int, oids: Iterable[str]) -> "SnmpMessage":
        """Build a GETNEXT request for the given OIDs."""

        return cls._request(PDU_GETNEXT, community, request_id, oids)

    @classmethod
    def get_bulk(
        cls,
        community: str,
        request_id: int,
        oids: Iterable[str],
        non_repeaters: int = 0,
        max_repetitions: int = 10,
    ) -> "SnmpMessage":
        """Build a GETBULK request for the given OIDs."""

        if non_repeaters < 0:
            raise SnmpEncodeError("non-repeaters cannot be negative")
        if max_repetitions < 0:
            raise SnmpEncodeError("max-repetitions cannot be negative")
        return cls(
            community=community,
            pdu_type=PDU_GETBULK,
            request_id=request_id,
            error_status=non_repeaters,
            error_index=max_repetitions,
            varbinds=[VarBind(oid) for oid in oids],
        )

    @classmethod
    def _request(
        cls, pdu_type: int, community: str, request_id: int, oids: Iterable[str]
    ) -> "SnmpMessage":
        return cls(
            community=community,
            pdu_type=pdu_type,
            request_id=request_id,
            varbinds=[VarBind(oid) for oid in oids],
        )


class SnmpClient:
    """Synchronous SNMPv2c client for a single agent endpoint."""

    def __init__(
        self,
        host: str,
        port: int = 161,
        community: str = "public",
        timeout: float = 1.0,
        retries: int = 1,
        request_id: Optional[int] = None,
    ) -> None:
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        if retries < 0:
            raise ValueError("retries cannot be negative")
        self.host = host
        self.port = int(port)
        self.community = community
        self.timeout = float(timeout)
        self.retries = int(retries)
        self._request_id = int(request_id) if request_id is not None else secrets.randbelow(2**31 - 1) + 1
        self._socket: Optional[socket.socket] = None

    def __enter__(self) -> "SnmpClient":
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    def close(self) -> None:
        """Release the UDP socket, if one was opened."""

        if self._socket is not None:
            self._socket.close()
            self._socket = None

    def _get_socket(self) -> socket.socket:
        if self._socket is None:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            self._socket = sock
        return self._socket

    def _take_request_id(self) -> int:
        request_id = self._request_id
        self._request_id = request_id + 1 if request_id < 2**31 - 1 else 1
        return request_id

    def request(self, message: SnmpMessage) -> SnmpMessage:
        """Send ``message`` and return the matching response.

        Datagrams that fail to decode or that carry a different request-id are
        ignored, which mirrors how a real poller must tolerate noise on UDP.
        """

        payload = message.encode()
        sock = self._get_socket()
        last_error: Optional[Exception] = None
        for _attempt in range(self.retries + 1):
            try:
                sock.sendto(payload, (self.host, self.port))
            except OSError as exc:
                raise SnmpTimeoutError(f"cannot send to {self.host}:{self.port}: {exc}") from exc
            deadline = time.monotonic() + self.timeout
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                sock.settimeout(remaining)
                try:
                    data, _address = sock.recvfrom(_MAX_DATAGRAM)
                except socket.timeout:
                    break
                except OSError as exc:
                    raise SnmpTimeoutError(f"error receiving from {self.host}:{self.port}: {exc}") from exc
                try:
                    response = SnmpMessage.decode(data)
                except SnmpError as exc:
                    last_error = exc
                    continue
                if response.request_id != message.request_id:
                    continue
                if response.pdu_type != PDU_RESPONSE:
                    last_error = SnmpDecodeError(
                        f"expected RESPONSE, got {response.pdu_name}"
                    )
                    continue
                return response
        detail = f" (last decode error: {last_error})" if last_error is not None else ""
        raise SnmpTimeoutError(
            f"no SNMP response from {self.host}:{self.port} after {self.retries + 1} attempt(s){detail}"
        )

    def _exchange(self, oids: Sequence[str], pdu_type: int, **pdu_fields: int) -> List[VarBind]:
        request_id = self._take_request_id()
        message = SnmpMessage(
            community=self.community,
            pdu_type=pdu_type,
            request_id=request_id,
            varbinds=[VarBind(oid) for oid in oids],
            **pdu_fields,
        )
        response = self.request(message)
        if response.error_status != NO_ERROR:
            raise SnmpResponseError(response.error_status, response.error_index)
        return response.varbinds

    def get(self, oids: Sequence[str]) -> List[VarBind]:
        """GET the given OIDs and return the response varbinds."""

        return self._exchange(oids, PDU_GET)

    def get_next(self, oids: Sequence[str]) -> List[VarBind]:
        """GETNEXT the given OIDs and return the response varbinds."""

        return self._exchange(oids, PDU_GETNEXT)

    def get_bulk(
        self, oids: Sequence[str], non_repeaters: int = 0, max_repetitions: int = 10
    ) -> List[VarBind]:
        """GETBULK the given OIDs and return the response varbinds."""

        if non_repeaters < 0 or max_repetitions < 0:
            raise ValueError("GETBULK counts cannot be negative")
        return self._exchange(
            oids,
            PDU_GETBULK,
            error_status=non_repeaters,
            error_index=max_repetitions,
        )

    def get_one(self, oid: str) -> Optional[VarBind]:
        """GET a single OID, returning None for SNMPv2c exception values."""

        varbinds = self.get([oid])
        if not varbinds:
            return None
        varbind = varbinds[0]
        return None if varbind.is_exception else varbind

    def walk(self, base_oid: str, max_rows: int = 10000) -> List[VarBind]:
        """Walk the subtree rooted at ``base_oid`` using repeated GETNEXT.

        The walk stops when the agent returns an OID outside the subtree or an
        ``endOfMibView`` exception. A reply that does not advance the cursor is
        treated as a protocol error so a broken agent cannot hang the poller.
        """

        if max_rows <= 0:
            raise ValueError("max_rows must be positive")
        results: List[VarBind] = []
        current = base_oid
        while True:
            if len(results) >= max_rows:
                raise WalkLimitError(f"walk of {base_oid} exceeded {max_rows} rows")
            varbinds = self.get_next([current])
            if not varbinds:
                break
            varbind = varbinds[0]
            if varbind.is_exception:
                break
            if not is_prefix(base_oid, varbind.oid):
                break
            if oid_key(varbind.oid) <= oid_key(current):
                raise SnmpProtocolError(
                    f"GETNEXT did not advance: asked {current}, received {varbind.oid}"
                )
            results.append(varbind)
            current = varbind.oid
        return results
