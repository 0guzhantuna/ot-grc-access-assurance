import argparse
import hashlib
import ipaddress
import json
from collections import defaultdict
from collections.abc import Callable, Hashable
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


THRESHOLD_KEYS = (
    "same_source_account_failures",
    "spray_unique_accounts",
    "distributed_sources_per_account",
)
EVENT_TYPES = {"auth_failure", "auth_success"}
RULE_TITLES = {
    "AUTH-01": "Repeated failed logins for one account",
    "AUTH-02": "Multiple accounts targeted from one source",
    "AUTH-03": "One account targeted from multiple sources",
    "AUTH-04": "Successful login after recent failures",
    "SEG-01": "Cross-zone auth event has no declared conduit",
    "DQ-01": "Input events need data-quality review",
}


def parse_timestamp(value: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError("timestamp must be a string")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("timestamp must include a UTC offset")
    return parsed.astimezone(timezone.utc)


def validate_config(config: Any) -> None:
    if not isinstance(config, dict):
        raise ValueError("configuration must be a JSON object")
    if not isinstance(config.get("lab_name"), str) or not config["lab_name"].strip():
        raise ValueError("lab_name must be a non-empty string")

    window_minutes = config.get("window_minutes")
    if not isinstance(window_minutes, int) or isinstance(window_minutes, bool) or window_minutes < 1:
        raise ValueError("window_minutes must be a positive integer")

    thresholds = config.get("thresholds")
    if not isinstance(thresholds, dict):
        raise ValueError("thresholds must be a JSON object")
    for key in THRESHOLD_KEYS:
        value = thresholds.get(key)
        if not isinstance(value, int) or isinstance(value, bool) or value < 1:
            raise ValueError(f"threshold '{key}' must be a positive integer")

    assets = config.get("assets")
    if not isinstance(assets, dict) or not assets:
        raise ValueError("assets must be a non-empty JSON object")
    zones = set()
    for asset_id, asset in assets.items():
        if (
            not isinstance(asset_id, str)
            or not isinstance(asset, dict)
            or not isinstance(asset.get("zone"), str)
            or not asset["zone"].strip()
            or not isinstance(asset.get("purdue_level"), str)
            or not asset["purdue_level"].strip()
        ):
            raise ValueError(f"asset '{asset_id}' needs a zone and purdue_level")
        zones.add(asset["zone"])

    conduits = config.get("allowed_conduits")
    if not isinstance(conduits, list):
        raise ValueError("allowed_conduits must be a JSON list")
    for conduit in conduits:
        if not isinstance(conduit, dict):
            raise ValueError("each allowed conduit must be a JSON object")
        source_zone = conduit.get("source_zone")
        target_zone = conduit.get("target_zone")
        if source_zone not in zones or target_zone not in zones:
            raise ValueError("each conduit must reference configured zones")

    maintenance_windows = config.get("approved_maintenance_windows", [])
    if not isinstance(maintenance_windows, list):
        raise ValueError("approved_maintenance_windows must be a JSON list")
    for window in maintenance_windows:
        if not isinstance(window, dict):
            raise ValueError("each maintenance window must be a JSON object")
        required = (
            "change_id",
            "ticket",
            "approver",
            "username",
            "source_asset",
            "target_asset",
            "start_utc",
            "end_utc",
        )
        if any(not isinstance(window.get(key), str) or not window[key] for key in required):
            raise ValueError("maintenance windows need change, asset, and time fields")
        if window["source_asset"] not in assets or window["target_asset"] not in assets:
            raise ValueError("maintenance windows must reference configured assets")
        if parse_timestamp(window["start_utc"]) > parse_timestamp(window["end_utc"]):
            raise ValueError("maintenance window start must not be after its end")


def _validate_event(
    payload: Any,
    line_number: int,
    config: dict[str, Any],
    seen_event_ids: set[str],
) -> tuple[dict[str, Any] | None, list[str]]:
    if not isinstance(payload, dict):
        return None, ["event must be a JSON object"]

    issues = []
    required_strings = (
        "event_id",
        "timestamp",
        "event_type",
        "source_ip",
        "source_asset",
        "target_asset",
        "username",
    )
    for key in required_strings:
        if not isinstance(payload.get(key), str) or not payload[key].strip():
            issues.append(f"{key} is missing or not a non-empty string")

    event_id = payload.get("event_id")
    if isinstance(event_id, str) and event_id:
        if event_id in seen_event_ids:
            issues.append("duplicate event_id")
        seen_event_ids.add(event_id)

    timestamp = None
    raw_timestamp = payload.get("timestamp")
    if isinstance(raw_timestamp, str):
        try:
            timestamp = parse_timestamp(raw_timestamp)
        except ValueError:
            issues.append("timestamp is invalid or has no UTC offset")

    event_type = payload.get("event_type")
    if isinstance(event_type, str) and event_type not in EVENT_TYPES:
        issues.append("event_type must be auth_failure or auth_success")

    source_ip = None
    raw_source_ip = payload.get("source_ip")
    if isinstance(raw_source_ip, str):
        try:
            source_ip = str(ipaddress.ip_address(raw_source_ip))
        except ValueError:
            issues.append("source_ip is not a valid IPv4 or IPv6 address")

    assets = config["assets"]
    source_asset_id = payload.get("source_asset")
    target_asset_id = payload.get("target_asset")
    if isinstance(source_asset_id, str) and source_asset_id not in assets:
        issues.append("source_asset is not in the lab inventory")
    if isinstance(target_asset_id, str) and target_asset_id not in assets:
        issues.append("target_asset is not in the lab inventory")

    if issues:
        return None, issues

    source_asset = assets[source_asset_id]
    target_asset = assets[target_asset_id]
    event = {
        "event_id": event_id,
        "line_number": line_number,
        "timestamp": timestamp,
        "event_type": event_type,
        "source_ip": source_ip,
        "source_asset": source_asset_id,
        "source_zone": source_asset["zone"],
        "source_purdue_level": source_asset["purdue_level"],
        "target_asset": target_asset_id,
        "target_zone": target_asset["zone"],
        "target_purdue_level": target_asset["purdue_level"],
        "username": payload["username"].strip(),
        "maintenance_context": [],
    }

    for window in config.get("approved_maintenance_windows", []):
        if (
            event["source_asset"] == window["source_asset"]
            and event["target_asset"] == window["target_asset"]
            and event["username"] == window["username"]
            and parse_timestamp(window["start_utc"])
            <= timestamp
            <= parse_timestamp(window["end_utc"])
        ):
            event["maintenance_context"].append(
                {
                    "change_id": window["change_id"],
                    "ticket": window.get("ticket", ""),
                    "approver": window.get("approver", ""),
                }
            )

    return event, []


def parse_events(
    jsonl_text: str, config: dict[str, Any]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    events = []
    data_quality_issues = []
    seen_event_ids: set[str] = set()

    for line_number, line in enumerate(jsonl_text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            data_quality_issues.append(
                {"line_number": line_number, "issues": ["invalid JSON"]}
            )
            continue

        event, issues = _validate_event(
            payload, line_number, config, seen_event_ids
        )
        if issues:
            data_quality_issues.append(
                {"line_number": line_number, "issues": issues}
            )
        elif event is not None:
            events.append(event)

    return events, data_quality_issues


def _peak_window(
    events: list[dict[str, Any]],
    window: timedelta,
    score: Callable[[list[dict[str, Any]]], int],
) -> tuple[list[dict[str, Any]], int]:
    ordered = sorted(events, key=lambda event: event["timestamp"])
    best_events: list[dict[str, Any]] = []
    best_score = 0

    for start_index, start_event in enumerate(ordered):
        candidate = []
        for event in ordered[start_index:]:
            if event["timestamp"] - start_event["timestamp"] > window:
                break
            candidate.append(event)
        candidate_score = score(candidate)
        if candidate_score > best_score:
            best_events = candidate
            best_score = candidate_score

    return best_events, best_score


def _group_events(
    events: list[dict[str, Any]],
    key_function: Callable[[dict[str, Any]], Hashable],
) -> dict[Hashable, list[dict[str, Any]]]:
    groups: dict[Hashable, list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        groups[key_function(event)].append(event)
    return groups


def _make_finding(
    rule_id: str,
    events: list[dict[str, Any]],
    rationale: str,
    review_question: str,
    priority: str = "MEDIUM",
    extra_evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    ordered = sorted(events, key=lambda event: event["timestamp"])
    all_context = {}
    for event in ordered:
        for context in event["maintenance_context"]:
            all_context[context["change_id"]] = context

    evidence = {
        "event_ids": sorted({event["event_id"] for event in ordered}),
        "source_ips": sorted({event["source_ip"] for event in ordered}),
        "usernames": sorted({event["username"] for event in ordered}),
        "source_assets": sorted({event["source_asset"] for event in ordered}),
        "target_assets": sorted({event["target_asset"] for event in ordered}),
        "source_zones": sorted({event["source_zone"] for event in ordered}),
        "target_zones": sorted({event["target_zone"] for event in ordered}),
        "source_purdue_levels": sorted(
            {event["source_purdue_level"] for event in ordered}
        ),
        "target_purdue_levels": sorted(
            {event["target_purdue_level"] for event in ordered}
        ),
    }
    if extra_evidence:
        evidence.update(extra_evidence)

    return {
        "rule_id": rule_id,
        "title": RULE_TITLES[rule_id],
        "status": "REVIEW_REQUIRED",
        "priority": priority,
        "observed_start_utc": ordered[0]["timestamp"].isoformat(),
        "observed_end_utc": ordered[-1]["timestamp"].isoformat(),
        "rationale": rationale,
        "review_question": review_question,
        "evidence": evidence,
        "approved_change_context": sorted(
            all_context.values(), key=lambda context: context["change_id"]
        ),
    }


def analyze(
    jsonl_text: str,
    config: dict[str, Any],
    input_file: str,
    input_sha256: str,
) -> dict[str, Any]:
    validate_config(config)
    events, data_quality_issues = parse_events(jsonl_text, config)
    window = timedelta(minutes=config["window_minutes"])
    thresholds = config["thresholds"]
    findings = []

    failures = [event for event in events if event["event_type"] == "auth_failure"]
    successes = [event for event in events if event["event_type"] == "auth_success"]

    for key, group in _group_events(
        failures,
        lambda event: (
            event["source_ip"],
            event["username"],
            event["target_asset"],
        ),
    ).items():
        cluster, count = _peak_window(group, window, len)
        if count >= thresholds["same_source_account_failures"]:
            findings.append(
                _make_finding(
                    "AUTH-01",
                    cluster,
                    "Repeated failures for the same account, source IP, and target "
                    f"within {config['window_minutes']} minutes.",
                    "Was this expected user activity, a service issue, or an "
                    "unauthorized access attempt?",
                    extra_evidence={
                        "attempt_count": count,
                        "window_minutes": config["window_minutes"],
                    },
                )
            )

    for source_ip, group in _group_events(
        failures, lambda event: event["source_ip"]
    ).items():
        cluster, distinct_accounts = _peak_window(
            group, window, lambda items: len({item["username"] for item in items})
        )
        if distinct_accounts >= thresholds["spray_unique_accounts"]:
            findings.append(
                _make_finding(
                    "AUTH-02",
                    cluster,
                    "One source IP generated failed logins for multiple accounts "
                    f"within {config['window_minutes']} minutes.",
                    "Is this source an approved shared service, or should the "
                    "account-targeting pattern be investigated?",
                    extra_evidence={
                        "distinct_account_count": distinct_accounts,
                        "window_minutes": config["window_minutes"],
                    },
                )
            )

    for (username, target_asset), group in _group_events(
        failures, lambda event: (event["username"], event["target_asset"])
    ).items():
        cluster, distinct_sources = _peak_window(
            group, window, lambda items: len({item["source_ip"] for item in items})
        )
        if distinct_sources >= thresholds["distributed_sources_per_account"]:
            findings.append(
                _make_finding(
                    "AUTH-03",
                    cluster,
                    f"Account '{username}' on '{target_asset}' received failed "
                    f"logins from multiple source IPs within "
                    f"{config['window_minutes']} minutes.",
                    "Are these expected separate operators or should distributed "
                    "attempts against this account be investigated?",
                    extra_evidence={
                        "distinct_source_count": distinct_sources,
                        "window_minutes": config["window_minutes"],
                    },
                )
            )

    failures_by_identity = _group_events(
        failures,
        lambda event: (
            event["source_ip"],
            event["username"],
            event["target_asset"],
        ),
    )
    for success in successes:
        identity = (
            success["source_ip"],
            success["username"],
            success["target_asset"],
        )
        recent_failures = [
            event
            for event in failures_by_identity.get(identity, [])
            if timedelta(0) <= success["timestamp"] - event["timestamp"] <= window
        ]
        if recent_failures:
            findings.append(
                _make_finding(
                    "AUTH-04",
                    recent_failures + [success],
                    "A successful login followed one or more failed logins from the "
                    "same source IP for the same account and target.",
                    "Was the successful login expected, and do the failed attempts "
                    "need to be linked to an incident or user-support record?",
                )
            )

    allowed_conduits = {
        (item["source_zone"], item["target_zone"])
        for item in config["allowed_conduits"]
    }
    for event in events:
        zone_path = (event["source_zone"], event["target_zone"])
        if zone_path[0] != zone_path[1] and zone_path not in allowed_conduits:
            findings.append(
                _make_finding(
                    "SEG-01",
                    [event],
                    "The authentication event's source/target zone pair is absent "
                    "from the lab's declared conduit policy. Event logs alone do "
                    "not establish the actual network route.",
                    "Is the corresponding network path explicitly approved and "
                    "documented by the asset owner?",
                    priority=(
                        "HIGH" if event["event_type"] == "auth_success" else "MEDIUM"
                    ),
                    extra_evidence={
                        "event_type": event["event_type"],
                        "zone_path": {
                            "source": event["source_zone"],
                            "target": event["target_zone"],
                        },
                    },
                )
            )

    if data_quality_issues:
        findings.append(
            {
                "rule_id": "DQ-01",
                "title": RULE_TITLES["DQ-01"],
                "status": "REVIEW_REQUIRED",
                "priority": "MEDIUM",
                "observed_start_utc": None,
                "observed_end_utc": None,
                "rationale": "One or more JSONL lines could not be validated.",
                "review_question": "Can the source or event schema be corrected "
                "before this evidence is used?",
                "evidence": {"data_quality_issues": data_quality_issues},
                "approved_change_context": [],
            }
        )

    findings.sort(
        key=lambda finding: (
            finding["observed_start_utc"] or "",
            finding["rule_id"],
            finding["evidence"].get("event_ids", []),
        )
    )
    for index, finding in enumerate(findings, start=1):
        finding["finding_id"] = f"OT-{index:03d}"

    counts_by_rule = {}
    for finding in findings:
        counts_by_rule[finding["rule_id"]] = (
            counts_by_rule.get(finding["rule_id"], 0) + 1
        )

    maintenance_event_count = sum(
        bool(event["maintenance_context"]) for event in events
    )
    status = (
        "REVIEW_REQUIRED"
        if findings
        else "NO_EVENTS"
        if not events and not data_quality_issues
        else "NO_RULES_TRIGGERED"
    )

    return {
        "schema_version": 1,
        "metadata": {
            "generated_at_utc": datetime.now(timezone.utc).isoformat(
                timespec="seconds"
            ),
            "input_file": Path(input_file).name,
            "input_sha256": input_sha256,
            "collection_mode": "offline_file_analysis",
        },
        "lab_context": {
            "name": config["lab_name"],
            "review_status": status,
            "compliance_status": "NOT_ASSESSED",
            "purdue_model_note": (
                "Purdue levels are illustrative asset labels for this lab, not a "
                "validated network architecture."
            ),
            "isa_iec_62443_note": (
                "Zones and conduits are used as educational review concepts. "
                "No IEC 62443 requirement, security level, or compliance status "
                "is assessed."
            ),
        },
        "analysis_policy": {
            "window_minutes": config["window_minutes"],
            "thresholds": config["thresholds"],
            "allowed_conduits": config["allowed_conduits"],
        },
        "summary": {
            "valid_events": len(events),
            "failed_logins": len(failures),
            "successful_logins": len(successes),
            "data_quality_issue_lines": len(data_quality_issues),
            "events_with_approved_change_context": maintenance_event_count,
            "findings": len(findings),
            "findings_by_rule": counts_by_rule,
        },
        "data_quality": {"issues": data_quality_issues},
        "findings": findings,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Analyze synthetic OT access evidence for human review."
    )
    parser.add_argument(
        "--input", default="ot_auth_events.jsonl", help="JSONL event file"
    )
    parser.add_argument(
        "--config", default="ot_lab_config.json", help="Lab inventory and policy"
    )
    parser.add_argument(
        "--output", default="ot_evidence_report.json", help="JSON evidence report"
    )
    args = parser.parse_args(argv)

    input_path = Path(args.input)
    config_path = Path(args.config)
    output_path = Path(args.output)
    if output_path.resolve() in {input_path.resolve(), config_path.resolve()}:
        parser.error("output path must not overwrite the input or lab config")

    try:
        config = json.loads(config_path.read_text(encoding="utf-8"))
        validate_config(config)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        parser.error(f"cannot load lab config '{config_path}': {exc}")

    try:
        input_bytes = input_path.read_bytes()
        input_text = input_bytes.decode("utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        parser.error(f"cannot read event file '{input_path}': {exc}")

    report = analyze(
        input_text,
        config,
        str(input_path),
        hashlib.sha256(input_bytes).hexdigest(),
    )
    try:
        with output_path.open("w", encoding="utf-8") as report_file:
            json.dump(report, report_file, indent=2, ensure_ascii=False)
            report_file.write("\n")
    except OSError as exc:
        parser.error(f"cannot write report '{output_path}': {exc}")

    print(f"Evidence report generated: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
