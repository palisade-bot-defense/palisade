#!/usr/bin/env python3
"""Run a bounded synthetic load diagnostic against PALISADE's loopback HTTP path."""

from __future__ import annotations

import argparse
import base64
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
import http.client
import json
import math
import os
from pathlib import Path
import re
import secrets
import signal
import socket
import stat
import subprocess
import sys
import threading
import time


PLAN_SCHEMA_VERSION = "palisade.local-load-plan.v1"
REPORT_SCHEMA_VERSION = "palisade.local-load-diagnostic.v1"
MIN_DURATION_SECONDS = 1
MAX_DURATION_SECONDS = 300
MIN_CONCURRENCY = 1
MAX_CONCURRENCY = 64
MIN_OPERATIONS = 1
MAX_OPERATIONS = 200_000
MAX_RESPONSE_BYTES = 64 * 1024
REQUEST_TIMEOUT_SECONDS = 5
FAILURE_CLASSES = (
    "connection",
    "response_too_large",
    "invalid_json",
    "session_contract",
    "token_contract",
    "origin_contract",
    "server_exit",
)
LIMITATIONS = (
    "synthetic closed signals only; no deployment or customer records",
    "single PALISADE process on loopback using HTTP/1.1 without TLS or a proxy",
    "one persistent HTTP/1.1 connection per worker; no reverse-proxy pool semantics",
    "measures token issuance plus origin-check transaction latency after session setup",
    "excludes encrypted shadow-log persistence, browser, challenge and outcome flows",
    "not a detection-efficacy, false-positive, accessibility or production-capacity claim",
    "results vary with hardware, operating system, scheduling and concurrent local workloads",
)
OBSERVATIONS = {
    "user_agent_present": True,
    "browser_event_count": 0,
    "honeypot_hits": 0,
    "policy_alert": False,
    "verified_bot": False,
    "transport_protocol": "http1",
    "transport_security": "plaintext",
    "client_address_source": "direct",
    "network_reputation": "unknown",
    "network_type": "unknown",
}


class LoadTestError(RuntimeError):
    """The local load diagnostic violated a closed safety or protocol contract."""

    def __init__(self, message: str, failure_class: str | None = None) -> None:
        super().__init__(message)
        self.failure_class = failure_class


@dataclass(frozen=True)
class Config:
    duration_seconds: int = 30
    concurrency: int = 8
    max_operations: int = MAX_OPERATIONS


@dataclass(frozen=True)
class Session:
    session_id: str
    cookie: str


@dataclass
class WorkerResult:
    completed: int
    failed: int
    http_requests: int
    latencies_ns: list[int]
    failures: Counter[str]


def validate_config(config: Config) -> None:
    if type(config.duration_seconds) is not int or not MIN_DURATION_SECONDS <= config.duration_seconds <= MAX_DURATION_SECONDS:
        raise LoadTestError(f"duration must be {MIN_DURATION_SECONDS}-{MAX_DURATION_SECONDS} seconds")
    if type(config.concurrency) is not int or not MIN_CONCURRENCY <= config.concurrency <= MAX_CONCURRENCY:
        raise LoadTestError(f"concurrency must be {MIN_CONCURRENCY}-{MAX_CONCURRENCY}")
    if type(config.max_operations) is not int or not MIN_OPERATIONS <= config.max_operations <= MAX_OPERATIONS:
        raise LoadTestError(f"max operations must be {MIN_OPERATIONS}-{MAX_OPERATIONS}")


def execution_plan(config: Config) -> dict[str, object]:
    validate_config(config)
    return {
        "schema_version": PLAN_SCHEMA_VERSION,
        "synthetic_only": True,
        "raw_deployment_records_used": False,
        "network_scope": "loopback_only",
        "server_mode": "shadow",
        "session_cookie_required": True,
        "measured_transaction": "token_then_origin_check",
        "configured": {
            "duration_seconds": config.duration_seconds,
            "concurrency": config.concurrency,
            "max_operations": config.max_operations,
            "max_response_bytes": MAX_RESPONSE_BYTES,
            "request_timeout_seconds": REQUEST_TIMEOUT_SECONDS,
        },
        "limitations": list(LIMITATIONS),
    }


def _secret() -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii").rstrip("=")


def _base_environment() -> dict[str, str]:
    environment = {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}
    if os.environ.get("TMPDIR"):
        environment["TMPDIR"] = os.environ["TMPDIR"]
    return environment


def _reserve_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _validate_binary(path: Path) -> Path:
    if path.is_symlink():
        raise LoadTestError("binary must be a regular non-symlink file")
    try:
        resolved = path.resolve(strict=True)
        info = resolved.stat()
    except OSError as error:
        raise LoadTestError("binary is unavailable") from error
    if not stat.S_ISREG(info.st_mode) or not os.access(resolved, os.X_OK):
        raise LoadTestError("binary must be a regular executable file")
    return resolved


def _decode_object(raw: bytes) -> dict[str, object]:
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise LoadTestError("loopback response was not valid JSON", "invalid_json") from error
    if not isinstance(document, dict):
        raise LoadTestError("loopback response root was not an object", "invalid_json")
    return document


def _request(
    port: int,
    method: str,
    path: str,
    payload: dict[str, object] | None = None,
    bearer: str = "",
    cookie: str = "",
    challenge_binding: str = "",
    connection: http.client.HTTPConnection | None = None,
) -> tuple[int, bytes, dict[str, str]]:
    headers = {"Accept": "application/json"}
    body = None
    if payload is not None:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if bearer:
        headers["Authorization"] = "Bearer " + bearer
    if cookie:
        headers["Cookie"] = cookie
    if challenge_binding:
        headers["X-Palisade-Challenge-Binding"] = challenge_binding
    owns_connection = connection is None
    if connection is None:
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=REQUEST_TIMEOUT_SECONDS)
    try:
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        raw = response.read(MAX_RESPONSE_BYTES + 1)
        if len(raw) > MAX_RESPONSE_BYTES:
            raise LoadTestError("loopback response exceeded the bounded response budget", "response_too_large")
        return response.status, raw, {key.lower(): value for key, value in response.getheaders()}
    except LoadTestError:
        raise
    except (OSError, http.client.HTTPException) as error:
        raise LoadTestError("loopback request failed", "connection") from error
    finally:
        if owns_connection:
            connection.close()


def _wait_ready(process: subprocess.Popen[bytes], port: int) -> None:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise LoadTestError("PALISADE exited before loopback readiness", "server_exit")
        try:
            status, _, _ = _request(port, "GET", "/health/ready")
            if status == 200:
                return
        except LoadTestError:
            pass
        time.sleep(0.05)
    raise LoadTestError("PALISADE did not become ready within ten seconds", "server_exit")


def _start_server(binary: Path, environment: dict[str, str]) -> tuple[subprocess.Popen[bytes], int]:
    public_port = _reserve_loopback_port()
    admin_port = _reserve_loopback_port()
    process = subprocess.Popen(
        [
            os.fspath(binary),
            "serve",
            "--listen",
            f"127.0.0.1:{public_port}",
            "--admin-listen",
            f"127.0.0.1:{admin_port}",
            "--mode",
            "shadow",
            "--require-session-cookie",
        ],
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        _wait_ready(process, public_port)
    except Exception:
        _stop_server(process, require_success=False)
        raise
    return process, public_port


def _stop_server(process: subprocess.Popen[bytes], require_success: bool = True) -> None:
    if process.poll() is None:
        process.send_signal(signal.SIGTERM)
    try:
        return_code = process.wait(timeout=10)
    except subprocess.TimeoutExpired as error:
        process.kill()
        process.wait(timeout=5)
        raise LoadTestError("PALISADE did not stop within ten seconds", "server_exit") from error
    if require_success and return_code != 0:
        raise LoadTestError("PALISADE returned an error during graceful shutdown", "server_exit")


def _issue_session(port: int, api_key: str) -> Session:
    status, raw, headers = _request(port, "POST", "/v1/session", bearer=api_key)
    document = _decode_object(raw)
    session_id = document.get("session_id")
    cookie = headers.get("set-cookie", "").split(";", 1)[0]
    if (
        status != 201
        or not isinstance(session_id, str)
        or re.fullmatch(r"[A-Za-z0-9_.:-]{8,128}", session_id) is None
        or not cookie.startswith("__Host-palisade_session=")
        or len(cookie) > 1024
    ):
        raise LoadTestError("session issuance violated the closed contract", "session_contract")
    return Session(session_id=session_id, cookie=cookie)


def _issue_proof(
    port: int,
    api_key: str,
    session: Session,
    connection: http.client.HTTPConnection | None = None,
) -> str:
    status, raw, _ = _request(
        port,
        "POST",
        "/v1/token",
        {"session_id": session.session_id, "action": "read", "ttl_seconds": 60},
        bearer=api_key,
        cookie=session.cookie,
        connection=connection,
    )
    document = _decode_object(raw)
    proof = document.get("proof_token")
    if status != 201 or not isinstance(proof, str) or not 32 <= len(proof) <= 4096:
        raise LoadTestError("proof issuance violated the closed contract", "token_contract")
    return proof


def _check_origin(
    port: int,
    session: Session,
    proof: str,
    sequence: int,
    connection: http.client.HTTPConnection | None = None,
) -> None:
    status, raw, headers = _request(
        port,
        "POST",
        "/v1/origin-check",
        {
            "session_id": session.session_id,
            "action": "read",
            "endpoint_class": "public_content",
            "evaluation_cohort": "unknown",
            "sequence": sequence,
            "proof_token": proof,
            "observations": dict(OBSERVATIONS),
        },
        cookie=session.cookie,
        challenge_binding=_secret(),
        connection=connection,
    )
    decision_id = headers.get("x-palisade-decision-id", "")
    if (
        status != 204
        or raw != b""
        or headers.get("x-palisade-action") not in ("allow", "observe")
        or headers.get("x-palisade-handling") != "pass"
        or headers.get("x-palisade-mode") != "shadow"
        or headers.get("x-palisade-rollout-id", "") != ""
        or re.fullmatch(r"[A-Za-z0-9_.:-]{8,128}", decision_id) is None
    ):
        raise LoadTestError("origin-check violated the closed Shadow contract", "origin_contract")


def _worker(
    port: int,
    api_key: str,
    session: Session,
    deadline: float,
    max_operations: int,
    counter: list[int],
    counter_lock: threading.Lock,
) -> WorkerResult:
    result = WorkerResult(completed=0, failed=0, http_requests=0, latencies_ns=[], failures=Counter())
    sequence = 0
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=REQUEST_TIMEOUT_SECONDS)
    try:
        while time.monotonic() < deadline:
            with counter_lock:
                if counter[0] >= max_operations:
                    break
                counter[0] += 1
            sequence += 1
            started = time.perf_counter_ns()
            try:
                result.http_requests += 1
                proof = _issue_proof(port, api_key, session, connection)
                result.http_requests += 1
                _check_origin(port, session, proof, sequence, connection)
            except LoadTestError as error:
                result.failed += 1
                failure_class = error.failure_class if error.failure_class in FAILURE_CLASSES else "origin_contract"
                result.failures[failure_class] += 1
                connection.close()
                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=REQUEST_TIMEOUT_SECONDS)
            else:
                result.completed += 1
                result.latencies_ns.append(time.perf_counter_ns() - started)
    finally:
        connection.close()
    return result


def _nearest_rank(values: list[int], percentile: int) -> int | None:
    if not values:
        return None
    if not 1 <= percentile <= 100:
        raise LoadTestError("percentile must be 1-100")
    ordered = sorted(values)
    rank = max(1, math.ceil(percentile * len(ordered) / 100))
    return ordered[rank - 1]


def _milliseconds(value: int | None) -> float | None:
    if value is None:
        return None
    return round(value / 1_000_000, 3)


def _validate_report(report: dict[str, object]) -> None:
    if set(report) != {
        "schema_version",
        "synthetic_only",
        "raw_deployment_records_used",
        "network_scope",
        "server_profile",
        "configured",
        "observed",
        "latency_ms",
        "failures",
        "limitations",
        "result",
    }:
        raise LoadTestError("diagnostic report top-level fields are not closed")
    if (
        report["schema_version"] != REPORT_SCHEMA_VERSION
        or report["synthetic_only"] is not True
        or report["raw_deployment_records_used"] is not False
        or report["network_scope"] != "loopback_only"
        or report["limitations"] != list(LIMITATIONS)
        or report["result"] not in ("passed", "failed")
    ):
        raise LoadTestError("diagnostic report identity or safety boundary changed")
    profile = report["server_profile"]
    if profile != {
        "mode": "shadow",
        "transport": "http1_plaintext",
        "processes": 1,
        "shadow_log": False,
        "session_cookie_required": True,
        "measured_transaction": "token_then_origin_check",
    }:
        raise LoadTestError("diagnostic server profile changed")
    configured = report["configured"]
    if not isinstance(configured, dict) or set(configured) != {"duration_seconds", "concurrency", "max_operations"}:
        raise LoadTestError("diagnostic configuration fields are not closed")
    validate_config(Config(**configured))
    observed = report["observed"]
    if not isinstance(observed, dict) or set(observed) != {
        "wall_duration_ms",
        "attempted_operations",
        "completed_operations",
        "failed_operations",
        "http_requests",
        "throughput_operations_per_second",
        "stop_reason",
    }:
        raise LoadTestError("diagnostic observation fields are not closed")
    integer_fields = ("attempted_operations", "completed_operations", "failed_operations", "http_requests")
    if any(type(observed[key]) is not int or observed[key] < 0 for key in integer_fields):
        raise LoadTestError("diagnostic counters are invalid")
    if observed["attempted_operations"] != observed["completed_operations"] + observed["failed_operations"]:
        raise LoadTestError("diagnostic operation counters do not balance")
    for field in ("wall_duration_ms", "throughput_operations_per_second"):
        if type(observed[field]) not in (int, float) or not math.isfinite(float(observed[field])) or observed[field] < 0:
            raise LoadTestError("diagnostic timing values are invalid")
    if observed["stop_reason"] not in ("duration", "max_operations", "server_error"):
        raise LoadTestError("diagnostic stop reason is invalid")
    failures = report["failures"]
    if not isinstance(failures, dict) or tuple(failures) != FAILURE_CLASSES:
        raise LoadTestError("diagnostic failure classes are not closed")
    if any(type(value) is not int or value < 0 for value in failures.values()):
        raise LoadTestError("diagnostic failure counts are invalid")
    if sum(failures.values()) != observed["failed_operations"] + (1 if failures["server_exit"] else 0):
        raise LoadTestError("diagnostic failure counts do not balance")
    latency = report["latency_ms"]
    if not isinstance(latency, dict) or set(latency) != {"samples", "p50", "p95", "p99", "maximum", "method"}:
        raise LoadTestError("diagnostic latency fields are not closed")
    if latency["samples"] != observed["completed_operations"] or latency["method"] != "nearest_rank_successes":
        raise LoadTestError("diagnostic latency sample contract changed")
    values = [latency[key] for key in ("p50", "p95", "p99", "maximum")]
    if latency["samples"] == 0:
        if any(value is not None for value in values):
            raise LoadTestError("empty diagnostic must not invent latency values")
    elif any(type(value) not in (int, float) or not math.isfinite(float(value)) or value < 0 for value in values):
        raise LoadTestError("diagnostic latency values are invalid")
    elif not latency["p50"] <= latency["p95"] <= latency["p99"] <= latency["maximum"]:
        raise LoadTestError("diagnostic latency percentiles are not ordered")
    expected_result = "passed" if observed["failed_operations"] == 0 and failures["server_exit"] == 0 else "failed"
    if report["result"] != expected_result:
        raise LoadTestError("diagnostic result does not match failures")


def run_load_test(binary: Path, config: Config) -> dict[str, object]:
    validate_config(config)
    binary = _validate_binary(binary)
    api_key = _secret()
    environment = _base_environment()
    environment.update(
        {
            "PALISADE_HMAC_KEY": _secret(),
            "PALISADE_API_KEY": api_key,
            "PALISADE_ADMIN_KEY": _secret(),
        }
    )
    process, public_port = _start_server(binary, environment)
    server_exit = 0
    try:
        sessions = [_issue_session(public_port, api_key) for _ in range(config.concurrency)]
        counter = [0]
        counter_lock = threading.Lock()
        started = time.monotonic()
        deadline = started + config.duration_seconds
        with ThreadPoolExecutor(max_workers=config.concurrency, thread_name_prefix="palisade-load") as executor:
            results = list(
                executor.map(
                    lambda session: _worker(
                        public_port,
                        api_key,
                        session,
                        deadline,
                        config.max_operations,
                        counter,
                        counter_lock,
                    ),
                    sessions,
                )
            )
        elapsed = max(time.monotonic() - started, 0.000001)
        if process.poll() is not None:
            server_exit = 1
    finally:
        _stop_server(process, require_success=process.poll() is None)

    completed = sum(result.completed for result in results)
    failed = sum(result.failed for result in results)
    http_requests = config.concurrency + sum(result.http_requests for result in results)
    latencies = [latency for result in results for latency in result.latencies_ns]
    failures: Counter[str] = Counter()
    for result in results:
        failures.update(result.failures)
    failures["server_exit"] += server_exit
    attempted = completed + failed
    stop_reason = "server_error" if server_exit else "max_operations" if attempted >= config.max_operations else "duration"
    report: dict[str, object] = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "synthetic_only": True,
        "raw_deployment_records_used": False,
        "network_scope": "loopback_only",
        "server_profile": {
            "mode": "shadow",
            "transport": "http1_plaintext",
            "processes": 1,
            "shadow_log": False,
            "session_cookie_required": True,
            "measured_transaction": "token_then_origin_check",
        },
        "configured": {
            "duration_seconds": config.duration_seconds,
            "concurrency": config.concurrency,
            "max_operations": config.max_operations,
        },
        "observed": {
            "wall_duration_ms": round(elapsed * 1000, 3),
            "attempted_operations": attempted,
            "completed_operations": completed,
            "failed_operations": failed,
            "http_requests": http_requests,
            "throughput_operations_per_second": round(completed / elapsed, 3),
            "stop_reason": stop_reason,
        },
        "latency_ms": {
            "samples": len(latencies),
            "p50": _milliseconds(_nearest_rank(latencies, 50)),
            "p95": _milliseconds(_nearest_rank(latencies, 95)),
            "p99": _milliseconds(_nearest_rank(latencies, 99)),
            "maximum": _milliseconds(max(latencies) if latencies else None),
            "method": "nearest_rank_successes",
        },
        "failures": {name: failures[name] for name in FAILURE_CLASSES},
        "limitations": list(LIMITATIONS),
        "result": "passed" if failed == 0 and server_exit == 0 else "failed",
    }
    _validate_report(report)
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, help="locally built PALISADE executable")
    parser.add_argument("--duration-seconds", type=int, default=30)
    parser.add_argument("--concurrency", type=int, default=8)
    parser.add_argument("--max-operations", type=int, default=MAX_OPERATIONS)
    parser.add_argument("--plan", action="store_true", help="print the closed synthetic plan without starting PALISADE")
    arguments = parser.parse_args(argv)
    config = Config(arguments.duration_seconds, arguments.concurrency, arguments.max_operations)
    try:
        if arguments.plan:
            result = execution_plan(config)
        else:
            if arguments.binary is None:
                raise LoadTestError("--binary is required unless --plan is used")
            result = run_load_test(arguments.binary, config)
    except (LoadTestError, OSError, subprocess.SubprocessError) as error:
        print(f"load-test-local: failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result.get("result", "passed") == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
