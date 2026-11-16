"""Tests for object identifier parsing, encoding and ordering."""

from __future__ import annotations

import unittest

from netwatch.ber import BerError, decode_oid, decode_tlv, encode_oid
from netwatch.oid import (
    OidError,
    child_index,
    compare_oids,
    format_oid,
    is_child_of,
    is_prefix,
    normalize_oid,
    oid_key,
    parse_oid,
    sort_oids,
)


class OidParsingTests(unittest.TestCase):
    def test_parse_valid_oid(self) -> None:
        self.assertEqual(parse_oid("1.3.6.1.2.1"), (1, 3, 6, 1, 2, 1))

    def test_normalize_strips_leading_dot(self) -> None:
        self.assertEqual(normalize_oid(".1.3.6.1"), "1.3.6.1")

    def test_invalid_oids_are_rejected(self) -> None:
        for candidate in ("", "1", "1.40", "3.1", "1.3.-1", "1.3.x", "1..3", " 1.3", 13):
            with self.subTest(candidate=candidate):
                with self.assertRaises(OidError):
                    parse_oid(candidate)  # type: ignore[arg-type]

    def test_format_oid(self) -> None:
        self.assertEqual(format_oid([1, 3, 6, 1]), "1.3.6.1")

    def test_oid_key_ordering_tuple(self) -> None:
        self.assertLess(oid_key("1.3.6.1.2"), oid_key("1.3.6.1.10"))
        self.assertEqual(oid_key("1.3.6.1.2"), (1, 3, 6, 1, 2))


class OidOrderingTests(unittest.TestCase):
    def test_compare_oids(self) -> None:
        self.assertEqual(compare_oids("1.3.6.1.2", "1.3.6.1.2"), 0)
        self.assertEqual(compare_oids("1.3.6.1.2", "1.3.6.1.3"), -1)
        self.assertEqual(compare_oids("1.3.6.1.3", "1.3.6.1.2"), 1)

    def test_prefix_and_child_checks(self) -> None:
        self.assertTrue(is_prefix("1.3.6.1.2.1", "1.3.6.1.2.1.1.1.0"))
        self.assertTrue(is_prefix("1.3.6.1.2.1", "1.3.6.1.2.1"))
        self.assertFalse(is_prefix("1.3.6.1.2.1", "1.3.6.1.2.2.1"))
        self.assertTrue(is_child_of("1.3.6.1.2.1", "1.3.6.1.2.1.1"))
        self.assertFalse(is_child_of("1.3.6.1.2.1", "1.3.6.1.2.1"))

    def test_child_index(self) -> None:
        self.assertEqual(child_index("1.3.6.1.2.1.2.2.1.2", "1.3.6.1.2.1.2.2.1.2.7"), 7)
        with self.assertRaises(OidError):
            child_index("1.3.6.1.2.1.2.2.1.2", "1.3.6.1.2.1.2.2.1.3.7")
        with self.assertRaises(OidError):
            child_index("1.3.6.1.2.1.2.2.1.2", "1.3.6.1.2.1.2.2.1.2")

    def test_sort_oids_uses_numeric_arcs(self) -> None:
        values = ["1.3.6.1.2.1.2.2.1.2.10", "1.3.6.1.2.1.2.2.1.2.2", "1.3.6.1.2.1.2.2.1.2.1"]
        self.assertEqual(
            sort_oids(values),
            ["1.3.6.1.2.1.2.2.1.2.1", "1.3.6.1.2.1.2.2.1.2.2", "1.3.6.1.2.1.2.2.1.2.10"],
        )


class OidEncodingTests(unittest.TestCase):
    def test_known_encoding(self) -> None:
        self.assertEqual(
            encode_oid("1.3.6.1.2.1.1.1.0"),
            bytes.fromhex("06082b06010201010100"),
        )

    def test_oid_round_trip(self) -> None:
        for oid in (
            "1.3",
            "0.0",
            "1.3.6.1.2.1.1.1.0",
            "1.3.6.1.2.1.2.2.1.10.16",
            "2.100.3",
            "1.3.6.1.4.1.32473.1.1",
        ):
            with self.subTest(oid=oid):
                tag, payload, offset = decode_tlv(encode_oid(oid))
                self.assertEqual(tag, 0x06)
                self.assertEqual(decode_oid(payload), oid)
                self.assertEqual(offset, len(encode_oid(oid)))

    def test_large_combined_first_identifier(self) -> None:
        encoded = encode_oid("2.999.1")
        _, payload, _ = decode_tlv(encoded)
        self.assertGreater(payload[0], 0x7F)
        self.assertEqual(decode_oid(payload), "2.999.1")

    def test_invalid_oids_raise_ber_error(self) -> None:
        for candidate in ("1", "3.1", "1.3.x"):
            with self.subTest(candidate=candidate):
                with self.assertRaises(BerError):
                    encode_oid(candidate)

    def test_malformed_oid_payloads_are_rejected(self) -> None:
        with self.assertRaises(BerError):
            decode_oid(b"")
        with self.assertRaises(BerError):
            decode_oid(b"\x2b\x86")  # truncated continuation octet


if __name__ == "__main__":
    unittest.main()
