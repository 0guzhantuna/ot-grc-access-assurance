import hashlib
import json
import unittest
from pathlib import Path

from ot_access_assurance import analyze, parse_events, validate_config


ROOT = Path(__file__).parent
CONFIG = json.loads((ROOT / "ot_lab_config.json").read_text(encoding="utf-8"))
EVENTS_TEXT = (ROOT / "ot_auth_events.jsonl").read_text(encoding="utf-8")


class OtAccessAssuranceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.report = analyze(
            EVENTS_TEXT,
            CONFIG,
            "ot_auth_events.jsonl",
            hashlib.sha256(EVENTS_TEXT.encode("utf-8")).hexdigest(),
        )

    def test_synthetic_scenarios_produce_expected_review_findings(self) -> None:
        rule_ids = {finding["rule_id"] for finding in self.report["findings"]}

        self.assertEqual(self.report["summary"]["valid_events"], 13)
        self.assertEqual(self.report["summary"]["failed_logins"], 12)
        self.assertEqual(self.report["summary"]["successful_logins"], 1)
        self.assertEqual(
            rule_ids,
            {"AUTH-01", "AUTH-02", "AUTH-03", "AUTH-04", "SEG-01"},
        )
        self.assertEqual(self.report["lab_context"]["review_status"], "REVIEW_REQUIRED")
        self.assertEqual(self.report["summary"]["data_quality_issue_lines"], 0)

    def test_maintenance_context_is_evidence_not_an_alert_suppression(self) -> None:
        maintenance_finding = next(
            finding
            for finding in self.report["findings"]
            if finding["rule_id"] == "AUTH-01"
            and "EVT-011" in finding["evidence"]["event_ids"]
        )

        self.assertEqual(maintenance_finding["status"], "REVIEW_REQUIRED")
        self.assertEqual(
            maintenance_finding["approved_change_context"][0]["change_id"],
            "CHG-SIM-001",
        )
        self.assertEqual(
            self.report["summary"]["events_with_approved_change_context"], 3
        )

    def test_failures_outside_window_do_not_form_a_burst(self) -> None:
        lines = [
            '{"event_id":"T-1","timestamp":"2026-10-12T08:00:00Z",'
            '"event_type":"auth_failure","source_ip":"10.30.10.11",'
            '"source_asset":"ENG-WS-01","target_asset":"HMI-PACK-01",'
            '"username":"operator"}',
            '{"event_id":"T-2","timestamp":"2026-10-12T08:20:00Z",'
            '"event_type":"auth_failure","source_ip":"10.30.10.11",'
            '"source_asset":"ENG-WS-01","target_asset":"HMI-PACK-01",'
            '"username":"operator"}',
            '{"event_id":"T-3","timestamp":"2026-10-12T08:40:00Z",'
            '"event_type":"auth_failure","source_ip":"10.30.10.11",'
            '"source_asset":"ENG-WS-01","target_asset":"HMI-PACK-01",'
            '"username":"operator"}',
        ]

        report = analyze("\n".join(lines), CONFIG, "test.jsonl", "test-hash")

        self.assertNotIn(
            "AUTH-01", {finding["rule_id"] for finding in report["findings"]}
        )

    def test_malformed_and_unknown_asset_events_are_reported(self) -> None:
        text = "\n".join(
            [
                "{not-json",
                '{"event_id":"BAD-1","timestamp":"2026-10-12T08:00:00Z",'
                '"event_type":"auth_failure","source_ip":"10.0.0.1",'
                '"source_asset":"UNKNOWN","target_asset":"HMI-PACK-01",'
                '"username":"operator"}',
            ]
        )

        events, issues = parse_events(text, CONFIG)

        self.assertEqual(events, [])
        self.assertEqual([issue["line_number"] for issue in issues], [1, 2])
        report = analyze(text, CONFIG, "test.jsonl", "test-hash")
        self.assertEqual(report["lab_context"]["review_status"], "REVIEW_REQUIRED")
        self.assertEqual(
            report["summary"]["findings_by_rule"]["DQ-01"], 1
        )

    def test_configuration_rejects_non_positive_thresholds(self) -> None:
        invalid_config = json.loads(json.dumps(CONFIG))
        invalid_config["thresholds"]["spray_unique_accounts"] = 0

        with self.assertRaises(ValueError):
            validate_config(invalid_config)

    def test_empty_input_is_not_reported_as_compliant(self) -> None:
        report = analyze("", CONFIG, "empty.jsonl", "empty-hash")

        self.assertEqual(report["lab_context"]["review_status"], "NO_EVENTS")
        self.assertEqual(report["lab_context"]["compliance_status"], "NOT_ASSESSED")


if __name__ == "__main__":
    unittest.main()
