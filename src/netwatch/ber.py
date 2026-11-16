"""Hand-written BER codec for the subset of ASN.1 used by SNMPv2c.

SNMP messages are BER-encoded (basic encoding rules, X.690). This module covers
exactly the tags that SNMPv2c needs: INTEGER, OCTET STRING, NULL, OBJECT
IDENTIFIER, SEQUENCE, and the SNMP application types IpAddress, Counter32,
Gauge32, TimeTicks and Counter64. It deliberately rejects indefinite lengths and
multi-byte tags, both of which are invalid or absent in SNMP PDUs, and reports
every malformed packet as a :class:`BerError`.

Values travel as ``(tag, payload)`` pairs; :class:`BerReader` walks a buffer and
checks that each structural element is exactly where the protocol expects it.
"""

from __future__ import annotations

import ipaddress
from typing import Iterable, List, Tuple

from .oid import OidError, format_oid, parse_oid

__all__ = [
    "BerError",
    "TAG_INTEGER",
    "TAG_OCTET_STRING",
    "TAG_NULL",
    "TAG_OID",
    "TAG_SEQUENCE",
    "TAG_IP_ADDRESS",
    "TAG_COUNTER32",
    "TAG_GAUGE32",
    "TAG_TIMETICKS",
    "TAG_COUNTER64",
    "TAG_NO_SUCH_OBJECT",
    "TAG_NO_SUCH_INSTANCE",
    "TAG_END_OF_MIB_VIEW",
    "EXCEPTION_TAGS",
    "encode_length",
    "decode_length",
    "encode_tlv",
    "decode_tlv",
    "encode_integer",
    "decode_integer",
    "encode_octet_string",
    "encode_null",
    "encode_oid",
    "decode_oid",
    "encode_ip_address",
    "decode_ip_address",
    "join_tlvs",
    "encode_sequence",
    "BerReader",
]

TAG_INTEGER = 0x02
TAG_OCTET_STRING = 0x04
TAG_NULL = 0x05
TAG_OID = 0x06
TAG_SEQUENCE = 0x30

# Application class (0x40) types defined by the SNMP SMI.
TAG_IP_ADDRESS = 0x40
TAG_COUNTER32 = 0x41
TAG_GAUGE32 = 0x42
TAG_TIMETICKS = 0x43
TAG_COUNTER64 = 0x46

# SNMPv2c exception values carried in place of a value when nothing exists.
TAG_NO_SUCH_OBJECT = 0x80
TAG_NO_SUCH_INSTANCE = 0x81
TAG_END_OF_MIB_VIEW = 0x82

EXCEPTION_TAGS = (TAG_NO_SUCH_OBJECT, TAG_NO_SUCH_INSTANCE, TAG_END_OF_MIB_VIEW)

_UNSIGNED_MAXIMUM = {
    TAG_COUNTER32: 2**32 - 1,
    TAG_GAUGE32: 2**32 - 1,
    TAG_TIMETICKS: 2**32 - 1,
    TAG_COUNTER64: 2**64 - 1,
}

_MAX_LENGTH_OCTETS = 8


class BerError(ValueError):
    """Raised when BER data is truncated, malformed or unsupported."""


def encode_length(length: int) -> bytes:
    """Encode a BER length using the short form below 128 and the long form above."""

    if length < 0:
        raise BerError("length cannot be negative")
    if length < 0x80:
        return bytes((length,))
    payload = length.to_bytes((length.bit_length() + 7) // 8, "big")
    if len(payload) > _MAX_LENGTH_OCTETS:
        raise BerError("length is too large to encode")
    return bytes((0x80 | len(payload),)) + payload


def decode_length(data: bytes, offset: int = 0) -> Tuple[int, int]:
    """Decode a BER length, returning ``(length, next_offset)``."""

    if offset < 0:
        raise BerError("offset cannot be negative")
    if offset >= len(data):
        raise BerError("truncated length field")
    first = data[offset]
    offset += 1
    if first < 0x80:
        return first, offset
    if first == 0x80:
        raise BerError("indefinite lengths are not supported")
    count = first & 0x7F
    if count > _MAX_LENGTH_OCTETS:
        raise BerError(f"length field of {count} octets is not supported")
    if offset + count > len(data):
        raise BerError("truncated long-form length")
    length = int.from_bytes(data[offset : offset + count], "big")
    return length, offset + count


def encode_tlv(tag: int, payload: bytes) -> bytes:
    """Encode a single tag-length-value element."""

    if not 0 <= tag <= 0xFF:
        raise BerError(f"tag 0x{tag:x} cannot be encoded in one octet")
    return bytes((tag,)) + encode_length(len(payload)) + payload


def decode_tlv(data: bytes, offset: int = 0) -> Tuple[int, bytes, int]:
    """Decode one TLV, returning ``(tag, payload, next_offset)``."""

    if offset < 0:
        raise BerError("offset cannot be negative")
    if offset >= len(data):
        raise BerError("truncated tag")
    tag = data[offset]
    if tag & 0x1F == 0x1F:
        raise BerError("multi-octet tags are not used by SNMP")
    length, content_offset = decode_length(data, offset + 1)
    end = content_offset + length
    if end > len(data):
        raise BerError(
            f"truncated value for tag 0x{tag:02x}: need {length} octets, have {len(data) - content_offset}"
        )
    return tag, data[content_offset:end], end


def encode_integer(value: int, tag: int = TAG_INTEGER) -> bytes:
    """Encode a signed value as a minimal two's-complement INTEGER TLV."""

    if not isinstance(value, int):
        raise BerError(f"integer value required, got {type(value).__name__}")
    if tag in _UNSIGNED_MAXIMUM:
        if value < 0:
            raise BerError(f"value {value} is negative but tag 0x{tag:02x} is unsigned")
        maximum = _UNSIGNED_MAXIMUM[tag]
        if value > maximum:
            raise BerError(f"value {value} exceeds maximum {maximum} for tag 0x{tag:02x}")
    payload = _encode_signed_payload(value)
    return encode_tlv(tag, payload)


def _encode_signed_payload(value: int) -> bytes:
    if value == 0:
        return b"\x00"
    if value > 0:
        payload = value.to_bytes((value.bit_length() + 7) // 8, "big")
        if payload[0] & 0x80:
            payload = b"\x00" + payload
        return payload
    count = 1
    while value < -(1 << (8 * count - 1)):
        count += 1
    return value.to_bytes(count, "big", signed=True)


def decode_integer(payload: bytes) -> int:
    """Decode a two's-complement INTEGER payload of any length."""

    if not payload:
        raise BerError("INTEGER payload cannot be empty")
    return int.from_bytes(payload, "big", signed=True)


def encode_octet_string(value: bytes | str, tag: int = TAG_OCTET_STRING) -> bytes:
    """Encode bytes or UTF-8 text as an OCTET STRING TLV."""

    if isinstance(value, str):
        payload = value.encode("utf-8")
    elif isinstance(value, (bytes, bytearray)):
        payload = bytes(value)
    else:
        raise BerError(f"octet string value required, got {type(value).__name__}")
    return encode_tlv(tag, payload)


def decode_octet_string(payload: bytes) -> bytes:
    """Return the raw bytes of an OCTET STRING payload."""

    return bytes(payload)


def encode_null(tag: int = TAG_NULL) -> bytes:
    """Encode a NULL TLV (used for request varbinds and exceptions)."""

    return encode_tlv(tag, b"")


def encode_oid(oid: str, tag: int = TAG_OID) -> bytes:
    """Encode a dotted OID as a BER OBJECT IDENTIFIER TLV."""

    try:
        arcs = parse_oid(oid)
    except OidError as exc:
        raise BerError(str(exc)) from exc
    payload = bytearray(_encode_subidentifier(arcs[0] * 40 + arcs[1]))
    for arc in arcs[2:]:
        payload.extend(_encode_subidentifier(arc))
    return encode_tlv(tag, bytes(payload))


def _encode_subidentifier(value: int) -> bytes:
    if value < 0:
        raise BerError("OID sub-identifiers cannot be negative")
    if value == 0:
        return b"\x00"
    chunks: List[int] = []
    while value:
        chunks.append(value & 0x7F)
        value >>= 7
    chunks.reverse()
    return bytes([chunk | 0x80 for chunk in chunks[:-1]] + [chunks[-1]])


def decode_oid(payload: bytes) -> str:
    """Decode an OID payload into its canonical dotted representation."""

    if not payload:
        raise BerError("OID payload cannot be empty")
    arcs = [0, 0]
    value = 0
    position = 0
    octets = payload
    while position < len(octets):
        byte = octets[position]
        position += 1
        if value > (2**32 - 1) >> 7:
            raise BerError("OID sub-identifier exceeds 32 bits")
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            if value > 2**32 - 1:
                raise BerError("OID sub-identifier exceeds 32 bits")
            arcs.append(value)
            value = 0
        elif position == len(octets):
            raise BerError("truncated OID sub-identifier")
    if len(arcs) < 3:
        raise BerError("OID payload does not contain any complete sub-identifier")
    combined = arcs.pop(2)
    if combined < 40:
        first, second = 0, combined
    elif combined < 80:
        first, second = 1, combined - 40
    else:
        first, second = 2, combined - 80
    arcs[0] = first
    arcs[1] = second
    return format_oid(arcs)


def encode_ip_address(address: str, tag: int = TAG_IP_ADDRESS) -> bytes:
    """Encode a dotted-quad IPv4 address as an SNMP IpAddress TLV."""

    try:
        parsed = ipaddress.IPv4Address(address)
    except (ipaddress.AddressValueError, ValueError) as exc:
        raise BerError(f"invalid IPv4 address {address!r}") from exc
    return encode_tlv(tag, parsed.packed)


def decode_ip_address(payload: bytes) -> str:
    """Decode an SNMP IpAddress payload into dotted-quad notation."""

    if len(payload) != 4:
        raise BerError(f"IpAddress payload must be 4 octets, got {len(payload)}")
    return str(ipaddress.IPv4Address(bytes(payload)))


class BerReader:
    """Sequential TLV reader that checks structure and reports precise offsets."""

    def __init__(self, data: bytes) -> None:
        self._data = bytes(data)
        self._offset = 0

    def at_end(self) -> bool:
        """Return True when the whole buffer has been consumed."""

        return self._offset >= len(self._data)

    def read_tlv(self) -> Tuple[int, bytes]:
        """Read the next TLV as ``(tag, payload)``."""

        if self.at_end():
            raise BerError("unexpected end of data")
        tag, payload, next_offset = decode_tlv(self._data, self._offset)
        self._offset = next_offset
        return tag, payload

    def read_expect(self, tag: int, what: str) -> bytes:
        """Read the next TLV, requiring the given tag."""

        actual, payload = self.read_tlv()
        if actual != tag:
            raise BerError(f"expected {what} (tag 0x{tag:02x}), got tag 0x{actual:02x}")
        return payload

    def read_integer(self, what: str, tag: int = TAG_INTEGER) -> int:
        """Read an INTEGER TLV and return its value."""

        return decode_integer(self.read_expect(tag, what))

    def require_end(self, what: str) -> None:
        """Raise when bytes remain after parsing a complete structure."""

        if not self.at_end():
            raise BerError(f"unexpected trailing data after {what}")


def join_tlvs(tlvs: Iterable[bytes]) -> bytes:
    """Concatenate pre-encoded TLVs (small convenience for message builders)."""

    return b"".join(bytes(tlv) for tlv in tlvs)


def encode_sequence(*tlvs: bytes) -> bytes:
    """Wrap already-encoded TLVs in a SEQUENCE."""

    return encode_tlv(TAG_SEQUENCE, join_tlvs(tlvs))
