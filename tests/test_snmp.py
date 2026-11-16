"""Tests for SNMPv2c messages, varbind typing and client error handling."""

from __future__ import annotations

import unittest

from netwatch.ber import (
    TAG_COUNTER32,
    TAG_COUNTER64,
    TAG_END_OF_MIB_VIEW,
    TAG_GAUGE32,
    TAG_INTEGER,
    TAG_IP_ADDRESS,
    TAG_NO_SUCH_INSTANCE,
    TAG_NO_SUCH_OBJECT,
    TAG_NULL,
    TAG_OCTET_STRING,
    TAG_OID,
    TAG_TIMETICKS,
    BerReader,
    decode_tlv,
    encode_oid,
    encode_sequence,
    encode_tlv,
)
from netwatch.snmp import (
    ERROR_STATUS_NAMES,
    PDU_GET,
    PDU_GETBULK,
    PDU_GETNEXT,
    PDU_RESPONSE,
    SnmpDecodeError,
    SnmpEncodeError,
    SnmpMessage,
    SnmpResponseError,
    VarBind,
    decode_varbind_value,
    encode_varbind_value,
)

_SYS_NAME = "1.3.6.1.2.1.1.5.0"
_IF_DESCR_1 = "1.3.6.1.2.1.2.2.1.2.1"


def _round_trip_varbind(varbind: VarBind) -> VarBind:
    reader = BerReader(varbind.encode())
    decoded = VarBind.decode_from(reader)
    assert reader.at_end()
    return decoded


class VarBindEncodingTests(unittest.TestCase):
    def test_integer_varbind_round_trip(self) -> None:
        varbind = VarBind(_IF_DESCR_1, TAG_INTEGER, -7)
        self.assertEqual(_round_trip_varbind(varbind), varbind)

    def test_octet_string_varbind_round_trip(self) -> None:
        varbind = VarBind(_SYS_NAME, TAG_OCTET_STRING, b"simsw01.example")
        self.assertEqual(_round_trip_varbind(varbind), varbind)

    def test_null_varbind_round_trip(self) -> None:
        varbind = VarBind(_SYS_NAME)
        decoded = _round_trip_varbind(varbind)
        self.assertEqual(decoded.tag, TAG_NULL)
        self.assertIsNone(decoded.value)

    def test_oid_value_varbind_round_trip(self) -> None:
        varbind = VarBind("1.3.6.1.2.1.1.2.0", TAG_OID, "1.3.6.1.4.1.32473.1.1")
        self.assertEqual(_round_trip_varbind(varbind), varbind)

    def test_ip_address_varbind_encoding(self) -> None:
        varbind = VarBind("1.3.6.1.2.1.4.20.1.1.192.0.2.1", TAG_IP_ADDRESS, "192.0.2.1")
        self.assertEqual(
            varbind.encode(),
            encode_sequence(encode_oid(varbind.oid), b"\x40\x04\xc0\x00\x02\x01"),
        )
        self.assertEqual(_round_trip_varbind(varbind), varbind)

    def test_application_integer_varbinds_round_trip(self) -> None:
        cases = (
            (TAG_COUNTER32, 4_000_000_000),
            (TAG_GAUGE32, 1_000_000_000),
            (TAG_TIMETICKS, 123_456),
            (TAG_COUNTER64, 2**63 + 5),
        )
        for tag, value in cases:
            with self.subTest(tag=tag):
                varbind = VarBind("1.3.6.1.2.1.2.2.1.10.1", tag, value)
                self.assertEqual(_round_trip_varbind(varbind), varbind)

    def test_exception_varbinds_round_trip(self) -> None:
        for tag in (TAG_NO_SUCH_OBJECT, TAG_NO_SUCH_INSTANCE, TAG_END_OF_MIB_VIEW):
            with self.subTest(tag=tag):
                varbind = VarBind("1.3.6.1.2.1.99.1.0", tag)
                decoded = _round_trip_varbind(varbind)
                self.assertEqual(decoded.tag, tag)
                self.assertTrue(decoded.is_exception)

    def test_unknown_value_tag_is_rejected(self) -> None:
        payload = encode_sequence(encode_oid(_SYS_NAME), encode_tlv(0x07, b"x"))
        with self.assertRaises(SnmpDecodeError):
            VarBind.decode_from(BerReader(payload))

    def test_exception_with_payload_is_rejected(self) -> None:
        payload = encode_sequence(encode_oid(_SYS_NAME), encode_tlv(TAG_NO_SUCH_OBJECT, b"x"))
        with self.assertRaises(SnmpDecodeError):
            VarBind.decode_from(BerReader(payload))

    def test_null_with_payload_is_rejected(self) -> None:
        payload = encode_sequence(encode_oid(_SYS_NAME), encode_tlv(TAG_NULL, b"x"))
        with self.assertRaises(SnmpDecodeError):
            VarBind.decode_from(BerReader(payload))

    def test_extra_varbind_elements_are_rejected(self) -> None:
        payload = encode_sequence(
            encode_oid(_SYS_NAME), encode_tlv(TAG_NULL, b""), encode_tlv(TAG_NULL, b"")
        )
        with self.assertRaises(SnmpDecodeError):
            VarBind.decode_from(BerReader(payload))


class VarBindValueValidationTests(unittest.TestCase):
    def test_null_value_must_be_none(self) -> None:
        with self.assertRaises(SnmpEncodeError):
            encode_varbind_value(TAG_NULL, 5)

    def test_bool_is_not_an_integer_value(self) -> None:
        with self.assertRaises(SnmpEncodeError):
            encode_varbind_value(TAG_INTEGER, True)

    def test_counter32_rejects_negative_and_overflow(self) -> None:
        with self.assertRaises(SnmpEncodeError):
            encode_varbind_value(TAG_COUNTER32, -1)
        with self.assertRaises(SnmpEncodeError):
            encode_varbind_value(TAG_COUNTER32, 2**32)

    def test_counter64_accepts_full_range(self) -> None:
        encoded = encode_varbind_value(TAG_COUNTER64, 2**64 - 1)
        self.assertEqual(encoded[0], TAG_COUNTER64)
        self.assertEqual(decode_varbind_value(TAG_COUNTER64, decode_tlv(encoded)[1]), 2**64 - 1)

    def test_octet_string_value_type_validation(self) -> None:
        with self.assertRaises(SnmpEncodeError):
            encode_varbind_value(TAG_OCTET_STRING, 42)

    def test_unsupported_tag_rejected(self) -> None:
        with self.assertRaises(SnmpEncodeError):
            encode_varbind_value(0x07, b"x")

    def test_malformed_unsigned_value_rejected(self) -> None:
        with self.assertRaises(SnmpDecodeError):
            decode_varbind_value(TAG_COUNTER32, b"\xff\xff\xff\xff\xff")  # too large for 32 bits


class SnmpMessageTests(unittest.TestCase):
    def test_get_message_round_trip(self) -> None:
        message = SnmpMessage.get("public", 1234, [_SYS_NAME, _IF_DESCR_1])
        decoded = SnmpMessage.decode(message.encode())
        self.assertEqual(decoded.version, 1)
        self.assertEqual(decoded.community, "public")
        self.assertEqual(decoded.pdu_type, PDU_GET)
        self.assertEqual(decoded.pdu_name, "GET")
        self.assertEqual(decoded.request_id, 1234)
        self.assertEqual(decoded.error_status, 0)
        self.assertEqual(decoded.error_index, 0)
        self.assertEqual([varbind.oid for varbind in decoded.varbinds], [_SYS_NAME, _IF_DESCR_1])
        self.assertTrue(all(varbind.tag == TAG_NULL for varbind in decoded.varbinds))

    def test_getnext_message_round_trip(self) -> None:
        message = SnmpMessage.get_next("public", -5, [_IF_DESCR_1])
        decoded = SnmpMessage.decode(message.encode())
        self.assertEqual(decoded.pdu_type, PDU_GETNEXT)
        self.assertEqual(decoded.request_id, -5)

    def test_getbulk_fields_round_trip(self) -> None:
        message = SnmpMessage.get_bulk(
            "public", 77, ["1.3.6.1.2.1.2.2.1.2"], non_repeaters=1, max_repetitions=25
        )
        decoded = SnmpMessage.decode(message.encode())
        self.assertEqual(decoded.pdu_type, PDU_GETBULK)
        self.assertEqual(decoded.non_repeaters, 1)
        self.assertEqual(decoded.max_repetitions, 25)

    def test_response_round_trip_preserves_error_fields(self) -> None:
        message = SnmpMessage(
            community="public",
            pdu_type=PDU_RESPONSE,
            request_id=9,
            error_status=2,
            error_index=1,
            varbinds=[VarBind(_SYS_NAME, TAG_OCTET_STRING, b"edge")],
        )
        decoded = SnmpMessage.decode(message.encode())
        self.assertEqual(decoded.pdu_type, PDU_RESPONSE)
        self.assertEqual(decoded.error_status, 2)
        self.assertEqual(decoded.error_index, 1)
        self.assertEqual(decoded.varbinds[0].value, b"edge")

    def test_empty_varbind_list_round_trip(self) -> None:
        message = SnmpMessage.get("public", 1, [])
        decoded = SnmpMessage.decode(message.encode())
        self.assertEqual(decoded.varbinds, [])

    def test_community_unicode_round_trip(self) -> None:
        message = SnmpMessage.get("p\u00fablico", 3, [_SYS_NAME])
        decoded = SnmpMessage.decode(message.encode())
        self.assertEqual(decoded.community, "p\u00fablico")

    def test_unsupported_version_is_rejected(self) -> None:
        message = SnmpMessage(version=0)
        with self.assertRaises(SnmpDecodeError):
            SnmpMessage.decode(message.encode())

    def test_trailing_bytes_are_rejected(self) -> None:
        encoded = SnmpMessage.get("public", 5, [_SYS_NAME]).encode()
        with self.assertRaises(SnmpDecodeError):
            SnmpMessage.decode(encoded + b"\x00")

    def test_unknown_pdu_tag_is_rejected(self) -> None:
        pdu = encode_tlv(
            0xA4,
            encode_tlv(TAG_INTEGER, b"\x01")
            + encode_tlv(TAG_INTEGER, b"\x00")
            + encode_tlv(TAG_INTEGER, b"\x00")
            + encode_tlv(0x30, b""),
        )
        body = encode_tlv(0x02, b"\x01") + encode_tlv(0x04, b"public") + pdu
        with self.assertRaises(SnmpDecodeError):
            SnmpMessage.decode(encode_tlv(0x30, body))

    def test_truncated_messages_are_rejected(self) -> None:
        encoded = SnmpMessage.get("public", 5, [_SYS_NAME]).encode()
        for length in (0, 1, 3, len(encoded) - 1):
            with self.subTest(length=length):
                with self.assertRaises(SnmpDecodeError):
                    SnmpMessage.decode(encoded[:length])

    def test_request_id_out_of_range_is_rejected(self) -> None:
        with self.assertRaises(SnmpEncodeError):
            SnmpMessage.get("public", 2**31, [_SYS_NAME]).encode()

    def test_negative_getbulk_counts_are_rejected(self) -> None:
        with self.assertRaises(SnmpEncodeError):
            SnmpMessage.get_bulk("public", 1, [_SYS_NAME], non_repeaters=-1)
        with self.assertRaises(SnmpEncodeError):
            SnmpMessage.get_bulk("public", 1, [_SYS_NAME], max_repetitions=-2)

    def test_unsupported_pdu_cannot_be_encoded(self) -> None:
        with self.assertRaises(SnmpEncodeError):
            SnmpMessage(pdu_type=0xA4).encode()

    def test_error_status_names_cover_v2c_errors(self) -> None:
        self.assertEqual(ERROR_STATUS_NAMES[0], "noError")
        self.assertEqual(ERROR_STATUS_NAMES[16], "authorizationError")
        self.assertEqual(ERROR_STATUS_NAMES[18], "inconsistentName")


class ResponseErrorTests(unittest.TestCase):
    def test_message_and_attributes(self) -> None:
        error = SnmpResponseError(2, 1)
        self.assertEqual(error.error_status, 2)
        self.assertEqual(error.error_index, 1)
        self.assertEqual(error.status_name, "noSuchName")
        self.assertIn("noSuchName", str(error))
        self.assertIn("varbind 1", str(error))

    def test_unknown_status_name(self) -> None:
        self.assertIn("errorStatus 99", SnmpResponseError(99).status_name)


if __name__ == "__main__":
    unittest.main()
