"""Tests for the threshold rule engine."""

from __future__ import annotations

import unittest

from netwatch.alerting import (
    KIND_OPER_DOWN,
    KIND_UNREACHABLE,
    KIND_UTILIZATION,
    SEVERITY_CRITICAL,
    SEVERITY_WARNING,
    AlertDecision,
    Thresholds,
    evaluate_interface,
    evaluate_unreachable,
)


class ThresholdValidationTests(unittest.TestCase):
    def test_defaults(self) -> None:
        thresholds = Thresholds()
        self.assertEqual(thresholds.utilization_pct, 80.0)
        self.assertTrue(thresholds.oper_status_down)
        self.assertTrue(thresholds.device_unreachable)

    def test_invalid_utilization_thresholds(self) -> None:
        for value in (0, -1, 1001, "high"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    Thresholds(utilization_pct=value)  # type: ignore[arg-type]


class UtilizationRuleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.thresholds = Thresholds(utilization_pct=80.0)

    def test_utilization_above_threshold_opens_warning(self) -> None:
        decisions = evaluate_interface("Ethernet0/1 (uplink)", 1, 91.25, self.thresholds)
        utilization = [decision for decision in decisions if decision.kind == KIND_UTILIZATION]
        self.assertEqual(len(utilization), 1)
        decision = utilization[0]
        self.assertTrue(decision.active)
        self.assertEqual(decision.severity, SEVERITY_WARNING)
        self.assertEqual(decision.value, 91.25)
        self.assertEqual(decision.threshold, 80.0)
        self.assertIn("91.2%", decision.message)
        self.assertIn("80.0%", decision.message)

    def test_utilization_at_threshold_opens_alert(self) -> None:
        decisions = evaluate_interface("if1", 1, 80.0, self.thresholds)
        self.assertTrue([decision for decision in decisions if decision.kind == KIND_UTILIZATION][0].active)

    def test_utilization_above_95_is_critical(self) -> None:
        decisions = evaluate_interface("if1", 1, 97.0, self.thresholds)
        utilization = [decision for decision in decisions if decision.kind == KIND_UTILIZATION][0]
        self.assertEqual(utilization.severity, SEVERITY_CRITICAL)

    def test_utilization_below_threshold_resolves(self) -> None:
        decisions = evaluate_interface("if1", 1, 12.5, self.thresholds)
        utilization = [decision for decision in decisions if decision.kind == KIND_UTILIZATION][0]
        self.assertFalse(utilization.active)
        self.assertTrue(utilization.resolve)

    def test_unknown_utilization_produces_no_utilization_decision(self) -> None:
        decisions = evaluate_interface("if1", 1, None, self.thresholds)
        self.assertEqual([decision for decision in decisions if decision.kind == KIND_UTILIZATION], [])


class OperStatusRuleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.thresholds = Thresholds(utilization_pct=80.0)

    def test_oper_down_is_critical(self) -> None:
        decisions = evaluate_interface("Ethernet0/3 (spare)", 2, None, self.thresholds)
        oper = [decision for decision in decisions if decision.kind == KIND_OPER_DOWN][0]
        self.assertTrue(oper.active)
        self.assertEqual(oper.severity, SEVERITY_CRITICAL)
        self.assertIn("down", oper.message)
        self.assertEqual(oper.value, 2.0)

    def test_oper_testing_is_warning(self) -> None:
        decisions = evaluate_interface("if2", 3, None, self.thresholds)
        oper = [decision for decision in decisions if decision.kind == KIND_OPER_DOWN][0]
        self.assertTrue(oper.active)
        self.assertEqual(oper.severity, SEVERITY_WARNING)
        self.assertIn("testing", oper.message)

    def test_oper_up_resolves(self) -> None:
        decisions = evaluate_interface("if2", 1, None, self.thresholds)
        oper = [decision for decision in decisions if decision.kind == KIND_OPER_DOWN][0]
        self.assertFalse(oper.active)
        self.assertIn("up", oper.message)

    def test_oper_rule_can_be_disabled(self) -> None:
        decisions = evaluate_interface("if2", 2, None, Thresholds(oper_status_down=False))
        self.assertEqual(decisions, [])


class UnreachableRuleTests(unittest.TestCase):
    def test_unreachable_opens_critical_alert(self) -> None:
        decision = evaluate_unreachable("192.0.2.50", "no SNMP response after 2 attempt(s)", Thresholds())
        self.assertTrue(decision.active)
        self.assertEqual(decision.kind, KIND_UNREACHABLE)
        self.assertEqual(decision.severity, SEVERITY_CRITICAL)
        self.assertIn("unreachable", decision.message)
        self.assertIn("192.0.2.50", decision.message)

    def test_reachable_resolves(self) -> None:
        decision = evaluate_unreachable("192.0.2.50", None, Thresholds())
        self.assertFalse(decision.active)
        self.assertTrue(decision.resolve)

    def test_unreachable_rule_can_be_disabled(self) -> None:
        decision = evaluate_unreachable(
            "192.0.2.50", "timeout", Thresholds(device_unreachable=False)
        )
        self.assertFalse(decision.active)


class DecisionTests(unittest.TestCase):
    def test_alert_decision_resolve_property(self) -> None:
        self.assertTrue(AlertDecision("x", active=True, severity="warning", message="m").active)
        self.assertTrue(AlertDecision("x", active=False, severity="warning", message="m").resolve)


if __name__ == "__main__":
    unittest.main()
