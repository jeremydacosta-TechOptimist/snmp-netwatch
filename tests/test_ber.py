"""Tests for the BER length/value codec primitives."""

from __future__ import annotations

import unittest

from netwatch.ber import (
    TAG_INTEGER,
    TAG_OCTET_STRING,
    TAG_SEQUENCE,
    BerError,
    BerReader,
    decode_integer,
    decode_length,
    decode_tlv,
    encode_integer,
    encode_length,
    encode_null,
    encode_octet_string,
    encode_tlv,
)


class LengthEncodingTests(unittest.TestCase):
    def test_short_form_boundaries(self) -> None:
        self.assertEqual(encode_length(0), b"\x00")
        self.assertEqual(encode_length(1), b"\x01")
        self.assertEqual(encode_length(127), b"\x7f")
        self.assertEqual(encode_length(128), b"\x81\x80")

    def test_long_form_encoding(self) -> None:
        self.assertEqual(encode_length(255), b"\x81\xff")
        self.assertEqual(encode_length(256), b"\x82\x01\x00")
        self.assertEqual(encode_length(65535), b"\x82\xff\xff")
        self.assertEqual(encode_length(70000), b"\x83\x01\x11\x70")

    def test_length_round_trip(self) -> None:
        for length in (0, 1, 5, 127, 128, 200, 255, 256, 4096, 65535, 70000):
            with self.subTest(length=length):
                encoded = encode_length(length)
                decoded, offset = decode_length(encoded)
                self.assertEqual(decoded, length)
                self.assertEqual(offset, len(encoded))

    def test_indefinite_length_is_rejected(self) -> None:
        with self.assertRaises(BerError):
            decode_length(b"\x80")

    def test_truncated_lengths_are_rejected(self) -> None:
        with self.assertRaises(BerError):
            decode_length(b"")
        with self.assertRaises(BerError):
            decode_length(b"\x82\x01")
        with self.assertRaises(BerError):
            decode_length(b"\x89\x01")

    def test_negative_length_cannot_be_encoded(self) -> None:
        with self.assertRaises(BerError):
            encode_length(-1)


class IntegerEncodingTests(unittest.TestCase):
    def test_positive_minimal_encoding(self) -> None:
        self.assertEqual(encode_integer(0), b"\x02\x01\x00")
        self.assertEqual(encode_integer(127), b"\x02\x01\x7f")
        self.assertEqual(encode_integer(128), b"\x02\x02\x00\x80")
        self.assertEqual(encode_integer(255), b"\x02\x02\x00\xff")
        self.assertEqual(encode_integer(256), b"\x02\x02\x01\x00")

    def test_negative_encoding(self) -> None:
        self.assertEqual(encode_integer(-1), b"\x02\x01\xff")
        self.assertEqual(encode_integer(-128), b"\x02\x01\x80")
        self.assertEqual(encode_integer(-129), b"\x02\x02\xff\x7f")

    def test_integer_round_trip(self) -> None:
        for value in (0, 1, 42, 127, 128, 255, 256, 65535, 2**31 - 1, -1, -127, -128, -129, -32768):
            with self.subTest(value=value):
                tag, payload, offset = decode_tlv(encode_integer(value))
                self.assertEqual(tag, TAG_INTEGER)
                self.assertEqual(decode_integer(payload), value)
                self.assertEqual(offset, 2 + len(payload))

    def test_empty_integer_payload_is_rejected(self) -> None:
        with self.assertRaises(BerError):
            decode_integer(b"")

    def test_application_tags_reject_negative_values(self) -> None:
        with self.assertRaises(BerError):
            encode_integer(-5, tag=0x41)

    def test_counter64_boundaries(self) -> None:
        payload = encode_integer(2**64 - 1, tag=0x46)
        self.assertEqual(payload[0], 0x46)
        # 2^64 - 1 needs a leading zero octet to stay positive in two's complement.
        self.assertEqual(payload[1], 9)


class TlvTests(unittest.TestCase):
    def test_tlv_round_trip(self) -> None:
        encoded = encode_tlv(TAG_OCTET_STRING, b"hello")
        self.assertEqual(encoded, b"\x04\x05hello")
        tag, payload, offset = decode_tlv(encoded)
        self.assertEqual((tag, payload), (TAG_OCTET_STRING, b"hello"))
        self.assertEqual(offset, len(encoded))

    def test_long_payload_uses_long_length_form(self) -> None:
        payload = b"x" * 300
        encoded = encode_tlv(TAG_OCTET_STRING, payload)
        self.assertEqual(encoded[:4], b"\x04\x82\x01\x2c")
        tag, decoded, offset = decode_tlv(encoded)
        self.assertEqual(tag, TAG_OCTET_STRING)
        self.assertEqual(decoded, payload)
        self.assertEqual(offset, len(encoded))

    def test_truncated_tlv_is_rejected(self) -> None:
        with self.assertRaises(BerError):
            decode_tlv(b"\x04\x05abc")
        with self.assertRaises(BerError):
            decode_tlv(b"")

    def test_multi_octet_tags_are_rejected(self) -> None:
        with self.assertRaises(BerError):
            decode_tlv(b"\x1f\x01\x00")

    def test_reader_checks_expected_tags(self) -> None:
        reader = BerReader(encode_tlv(TAG_INTEGER, b"\x05") + encode_null())
        self.assertEqual(reader.read_integer("counter"), 5)
        self.assertEqual(reader.read_expect(0x05, "NULL"), b"")
        self.assertTrue(reader.at_end())
        with self.assertRaises(BerError):
            reader.read_tlv()

    def test_reader_require_end(self) -> None:
        reader = BerReader(encode_tlv(TAG_SEQUENCE, b"") + b"\x00")
        reader.read_tlv()
        with self.assertRaises(BerError):
            reader.require_end("SEQUENCE")

    def test_octet_string_accepts_text(self) -> None:
        tag, payload, _ = decode_tlv(encode_octet_string("caf\u00e9"))
        self.assertEqual(tag, TAG_OCTET_STRING)
        self.assertEqual(payload.decode("utf-8"), "caf\u00e9")

    def test_octet_string_rejects_other_types(self) -> None:
        with self.assertRaises(BerError):
            encode_octet_string(42)  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
