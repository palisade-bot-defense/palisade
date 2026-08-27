#!/usr/bin/env python3
"""Evaluate normalized PALISADE events without emitting row-level data."""

from __future__ import annotations

import argparse
import bisect
import calendar
import collections
import datetime as dt
import hashlib
import hmac
import heapq
import json
import os
import re
import secrets
import statistics
import tempfile
from pathlib import Path


SCHEMA = "palisade.offline-evaluation.v1"
WINDOW_SECONDS = 300
TIME_RE = re.compile(
    r"^([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})"
    r"(?:[.]([0-9]{1,9}))?Z$"
)


def timestamp(value: str) -> float:
    match = TIME_RE.match(value)
    if not match:
        raise ValueError("observed_at is not UTC RFC3339")
    seconds = calendar.timegm(
        dt.datetime.strptime(match.group(1), "%Y-%m-%dT%H:%M:%S").timetuple()
    )
    nanos = int((match.group(2) or "").ljust(9, "0"))
    return seconds + nanos / 1_000_000_000


def candidate_rules(window: dict[str, object]) -> dict[str, bool]:
    count = int(window["count"])
    duration = float(window["last"]) - float(window["first"])
    errors = int(window["errors"])
    compare = int(window["compare"])
    current_burst = count >= 41
    volume_100 = count >= 100
    fast_burst_50 = count >= 50 and duration <= 60
    error_heavy_20 = count >= 20 and errors * 2 >= count
    compare_50 = compare >= 50
    return {
        "current_session_burst_41": current_burst,
        "volume_100": volume_100,
        "fast_burst_50": fast_burst_50,
        "error_heavy_20": error_heavy_20,
        "compare_50": compare_50,
        "combined_candidate": volume_100
        or fast_burst_50
        or error_heavy_20
        or compare_50,
    }


def empty_metrics() -> dict[str, object]:
    return {
        "weak_windows": 0,
        "unknown_windows": 0,
        "weak_requests": 0,
        "unknown_requests": 0,
        "rules": collections.defaultdict(lambda: {"weak": 0, "unknown": 0}),
    }


def iter_events(root: Path, manifest: dict[str, object]):
    for shard in manifest["shards"]:
        path = root / shard["filename"]
        with path.open("rb") as handle:
            for line in handle:
                yield json.loads(line)


def load_manifest(root: Path) -> dict[str, object]:
    if not (root / "COMPLETE").is_file():
        raise ValueError("normalized input is incomplete")
    with (root / "manifest.json").open("rb") as handle:
        manifest = json.load(handle)
    if manifest.get("schema_version") != "palisade.offline-manifest.v1":
        raise ValueError("unsupported normalized manifest")
    if manifest.get("provenance") != "offline_export":
        raise ValueError("evaluation accepts offline_export only")
    if not isinstance(manifest.get("shards"), list):
        raise ValueError("manifest shards must be an array")
    return manifest


def private_jsonl(path: Path):
    if path.is_symlink() or not path.is_file():
        raise ValueError("derived input must be a regular file, not a symlink")
    if os.stat(path).st_mode & 0o077:
        raise ValueError("derived input must be owner-only")
    with path.open("rb") as handle:
        for line_number, line in enumerate(handle, 1):
            if len(line) > 1 << 20:
                raise ValueError(f"derived input line {line_number} exceeds 1 MiB")
            try:
                yield json.loads(line)
            except (json.JSONDecodeError, UnicodeDecodeError) as error:
                raise ValueError(f"derived input line {line_number} is invalid JSON") from error


def file_fingerprint(path: Path) -> dict[str, object]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
            size += len(chunk)
    return {"size_bytes": size, "sha256": digest.hexdigest()}


def evaluate_derived(client_features: Path, challenge_outcomes: Path) -> dict[str, object]:
    join_key = secrets.token_bytes(32)

    def local_value(value: object, *, require_nonempty: bool = False) -> bytes:
        if not isinstance(value, str) or (require_nonempty and not value):
            raise ValueError("derived input contains an invalid direct identifier")
        return hmac.new(join_key, value.encode("utf-8"), hashlib.sha256).digest()

    allowed_outcomes = {"solved", "failed", "abandoned_after_start", "abandoned_before_start"}
    outcomes: dict[bytes, str] = {}
    outcome_counts: collections.Counter[str] = collections.Counter()
    for row in private_jsonl(challenge_outcomes):
        outcome = row.get("outcome")
        if outcome not in allowed_outcomes:
            raise ValueError("derived challenge input contains an unsupported outcome")
        outcomes[local_value(row.get("ip"), require_nonempty=True)] = outcome
        outcome_counts[outcome] += 1

    allowed_labels = {"human_confirmed", "campaign_signature", "unlabeled"}
    label_counts: collections.Counter[str] = collections.Counter()
    challenge_by_label: dict[str, collections.Counter[str]] = collections.defaultdict(collections.Counter)
    gaps: dict[str, list[float]] = collections.defaultdict(list)
    user_agents: collections.Counter[bytes] = collections.Counter()
    campaign_definition_mismatches = 0
    for row in private_jsonl(client_features):
        label = row.get("label")
        if label not in allowed_labels:
            raise ValueError("derived client input contains an unsupported label")
        label_counts[label] += 1
        user_agents[local_value(row.get("user_agent", ""))] += 1
        outcome = outcomes.get(local_value(row.get("ip"), require_nonempty=True))
        if outcome is not None:
            challenge_by_label[label][outcome] += 1
        content_pages = int(row.get("content_pages", 0))
        compare_pages = int(row.get("compare_pages", 0))
        if label == "campaign_signature" and not (
            compare_pages >= 3 and compare_pages >= 0.6 * max(1, content_pages)
        ):
            campaign_definition_mismatches += 1
        gap = row.get("gap_cv")
        if gap is not None and (
            label == "campaign_signature" or (label == "unlabeled" and content_pages >= 3)
        ):
            gaps[label].append(float(gap))

    joined = {}
    for label in sorted(allowed_labels):
        counts = challenge_by_label[label]
        total = sum(counts.values())
        solved = counts["solved"]
        joined[label] = {
            "clients_with_challenge_outcome": total,
            "outcomes": {name: counts[name] for name in sorted(allowed_outcomes)},
            "solved_share": solved / total if total else None,
        }

    return {
        "input_fingerprints": {
            "client_features": file_fingerprint(client_features),
            "challenge_outcomes": file_fingerprint(challenge_outcomes),
        },
        "label_contract": {
            "human_confirmed": "authenticated_admin_only_too_small_for_fp_estimation",
            "campaign_signature": "weak_compare_enumeration_signature_not_ground_truth",
            "unlabeled": "unknown_not_human",
            "challenge_solved": "outcome_not_human_label",
        },
        "clients": sum(label_counts.values()),
        "label_counts": {name: label_counts[name] for name in sorted(allowed_labels)},
        "challenge_outcome_counts": {name: outcome_counts[name] for name in sorted(allowed_outcomes)},
        "challenge_outcomes_by_label": joined,
        "quality_checks": {
            "campaign_definition_mismatches": campaign_definition_mismatches,
            "dominant_user_agent_count_without_value": user_agents.most_common(1)[0][1] if user_agents else 0,
            "gap_cv": {
                label: {"n": len(values), "median": statistics.median(values)}
                for label, values in sorted(gaps.items())
            },
        },
        "feature_rejections": [
            "assets_per_page and internal referers do not distinguish rendered browser automation",
            "gap regularity is reversed in this campaign and is unstable across rotating proxies",
            "challenge completion does not establish humanity",
            "single request-level features are insufficient for this campaign",
        ],
        "false_positive_rate_available": False,
        "limitations": [
            "only 16 authenticated-admin clients are confirmed human",
            "campaign_signature is defined from compare enumeration and is not independent ground truth",
            "aggregate client rows have no event timestamp and cannot form a temporal holdout",
            "IP-based challenge outcomes are noisy under rotating proxies",
        ],
    }


def evaluate(
    root: Path,
    client_features: Path | None = None,
    challenge_outcomes: Path | None = None,
) -> dict[str, object]:
    manifest = load_manifest(root)
    weak_times: dict[str, list[float]] = collections.defaultdict(list)
    weak_events = 0
    for event in iter_events(root, manifest):
        if str(event["source"]).startswith("crowdsec_"):
            weak_times[event["subject_id"]].append(timestamp(event["observed_at"]))
            weak_events += 1
    flat_weak_times = sorted(value for values in weak_times.values() for value in values)
    cutoff = flat_weak_times[len(flat_weak_times) // 2] if flat_weak_times else None
    for values in weak_times.values():
        values.sort()

    metrics = {
        "all": empty_metrics(),
        "before_weak_median": empty_metrics(),
        "after_weak_median": empty_metrics(),
    }
    active: dict[str, dict[str, object]] = {}
    expiry: list[tuple[float, int, str]] = []
    generation = 0

    def is_weak(window: dict[str, object]) -> bool:
        values = weak_times.get(str(window["subject"]))
        if not values:
            return False
        position = bisect.bisect_left(values, float(window["first"]) - WINDOW_SECONDS)
        return position < len(values) and values[position] <= float(window["last"]) + WINDOW_SECONDS

    def record(window: dict[str, object]) -> None:
        label = "weak" if is_weak(window) else "unknown"
        split = (
            "before_weak_median"
            if cutoff is not None and float(window["first"]) < cutoff
            else "after_weak_median"
        )
        for name in ("all", split):
            current = metrics[name]
            current[f"{label}_windows"] += 1
            current[f"{label}_requests"] += int(window["count"])
            for rule, matched in candidate_rules(window).items():
                if matched:
                    current["rules"][rule][label] += 1

    for event in iter_events(root, manifest):
        if event["source"] != "access":
            continue
        observed = timestamp(event["observed_at"])
        while expiry and expiry[0][0] < observed - WINDOW_SECONDS:
            _, expected_generation, key = heapq.heappop(expiry)
            window = active.get(key)
            if window is not None and window["generation"] == expected_generation:
                record(window)
                del active[key]
        key = event.get("session_id") or "subject:" + event["subject_id"]
        window = active.get(key)
        if window is None or observed - float(window["last"]) > WINDOW_SECONDS:
            if window is not None:
                record(window)
            window = {
                "subject": event["subject_id"],
                "first": observed,
                "last": observed,
                "count": 0,
                "errors": 0,
                "compare": 0,
                "generation": 0,
            }
            active[key] = window
        window["last"] = observed
        window["count"] = int(window["count"]) + 1
        if event["status_class"] in ("client_error", "server_error"):
            window["errors"] = int(window["errors"]) + 1
        if event["endpoint_class"] in ("compare_index", "compare_noindex"):
            window["compare"] = int(window["compare"]) + 1
        generation += 1
        window["generation"] = generation
        heapq.heappush(expiry, (observed, generation, key))
    for window in active.values():
        record(window)

    normalized_metrics: dict[str, object] = {}
    for split, split_metrics in metrics.items():
        weak_windows = int(split_metrics["weak_windows"])
        unknown_windows = int(split_metrics["unknown_windows"])
        base = weak_windows / (weak_windows + unknown_windows) if weak_windows + unknown_windows else 0
        rules = {}
        for rule, counts in sorted(split_metrics["rules"].items()):
            flagged = counts["weak"] + counts["unknown"]
            share = counts["weak"] / flagged if flagged else 0
            rules[rule] = {
                "weak_flagged": counts["weak"],
                "unknown_flagged": counts["unknown"],
                "weak_capture_rate": counts["weak"] / weak_windows if weak_windows else 0,
                "unknown_flag_rate": counts["unknown"] / unknown_windows if unknown_windows else 0,
                "weak_share_among_flagged": share,
                "lift_over_base": share / base if base else 0,
            }
        normalized_metrics[split] = {
            key: value for key, value in split_metrics.items() if key != "rules"
        }
        normalized_metrics[split]["weak_base_rate"] = base
        normalized_metrics[split]["rules"] = rules

    report = {
        "schema_version": SCHEMA,
        "source_schema_version": manifest["schema_version"],
        "window_seconds": WINDOW_SECONDS,
        "label_contract": {
            "positive": "crowdsec_within_300_seconds_weak_policy_label",
            "negative": "unknown_not_human",
            "ground_truth_available": False,
        },
        "weak_policy_events": weak_events,
        "weak_subject_days": len(weak_times),
        "temporal_split": {
            "method": "median_weak_policy_event_time",
            "cutoff": (
                dt.datetime.fromtimestamp(cutoff, tz=dt.timezone.utc).isoformat().replace("+00:00", "Z")
                if cutoff is not None
                else None
            ),
        },
        "metrics": normalized_metrics,
        "limitations": [
            "unknown traffic is not a confirmed-human cohort",
            "CrowdSec is a weak policy label and not ground truth",
            "no enforcement threshold can be approved from this export alone",
        ],
    }
    peer_source = manifest.get("config", {}).get("anubis_peer_source", "direct_peer_only")
    if peer_source == "trusted_x_real_ip":
        report["limitations"].append(
            "Anubis linkage depends on the operator-asserted Cloudflare edge trust boundary recorded in the manifest"
        )
    else:
        report["limitations"].append("Anubis rows without a trusted direct peer are excluded")
    if (client_features is None) != (challenge_outcomes is None):
        raise ValueError("client features and challenge outcomes must be supplied together")
    if client_features is not None and challenge_outcomes is not None:
        report["derived_evidence"] = evaluate_derived(client_features, challenge_outcomes)
    return report


def write_report(path: Path, report: dict[str, object]) -> None:
    prepare_output(path)
    descriptor, temporary = tempfile.mkstemp(prefix=".evaluation-", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def prepare_output(path: Path) -> None:
    if path.exists():
        raise ValueError("output report already exists")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if os.stat(path.parent).st_mode & 0o077:
        raise ValueError("output parent must be owner-only")
    current = path.parent
    while current != current.parent:
        if (current / ".git").exists():
            raise ValueError("output report must be outside every Git worktree")
        current = current.parent


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-dir", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--client-features", type=Path)
    parser.add_argument("--challenge-outcomes", type=Path)
    arguments = parser.parse_args()
    prepare_output(arguments.output.resolve())
    client_features = arguments.client_features.resolve() if arguments.client_features else None
    challenge_outcomes = arguments.challenge_outcomes.resolve() if arguments.challenge_outcomes else None
    report = evaluate(arguments.input_dir.resolve(), client_features, challenge_outcomes)
    write_report(arguments.output.resolve(), report)
    all_metrics = report["metrics"]["all"]
    print(
        "offline evaluation complete: "
        f"windows={all_metrics['weak_windows'] + all_metrics['unknown_windows']} "
        f"weak={all_metrics['weak_windows']} unknown={all_metrics['unknown_windows']}"
    )


if __name__ == "__main__":
    main()
