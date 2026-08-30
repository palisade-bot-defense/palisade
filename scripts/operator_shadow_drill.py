#!/usr/bin/env python3
"""Exercise a production-configured PALISADE shadow start, record, analysis and fail-safe restart."""

from __future__ import annotations

import argparse
import base64
import http.client
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time


SCHEMA_VERSION = "palisade.operator-shadow-drill.v1"
RISKY_OBSERVATIONS = {
    "user_agent_present": False,
    "honeypot_hits": 2,
    "challenge_verdict": "suspicious",
    "policy_alert": True,
}
EXPECTED_CHECKS = [
    "production_secrets_accepted",
    "public_admin_route_absent",
    "backend_session_cookie_issued",
    "one_time_proof_accepted",
    "risky_decision_enforced_observe",
    "risky_decision_computed_block",
    "shadow_override_explained",
    "normalized_outcome_recorded",
    "admin_summary_reports_shadow",
    "encrypted_chain_verified",
    "unsafe_cli_enforcement_rejected",
    "shadow_restart_succeeded",
    "aggregate_analysis_remains_non_enforcing",
]


class DrillError(RuntimeError):
    """The local operator drill failed one of its closed safety assertions."""


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


def _request(
    port: int,
    method: str,
    path: str,
    payload: dict[str, object] | None = None,
    bearer: str = "",
    cookie: str = "",
    expect_json: bool = True,
) -> tuple[int, dict[str, object], dict[str, str]]:
    headers = {"Accept": "application/json"}
    body = None
    if payload is not None:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if bearer:
        headers["Authorization"] = "Bearer " + bearer
    if cookie:
        headers["Cookie"] = cookie
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
    try:
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        raw = response.read(256 * 1024 + 1)
        if len(raw) > 256 * 1024:
            raise DrillError("local response exceeded the 256 KiB drill budget")
        document: dict[str, object] = {}
        if raw and expect_json:
            try:
                decoded = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                raise DrillError("local response was not bounded JSON") from error
            if not isinstance(decoded, dict):
                raise DrillError("local response root was not an object")
            document = decoded
        return response.status, document, {key.lower(): value for key, value in response.getheaders()}
    except OSError as error:
        raise DrillError("local loopback request failed") from error
    finally:
        connection.close()


def validate_decision(document: dict[str, object]) -> None:
    if document.get("action") != "observe" or document.get("computed_action") != "block":
        raise DrillError("risky synthetic decision did not preserve the shadow boundary")
    if document.get("mode") != "shadow" or document.get("rollout_id") not in (None, ""):
        raise DrillError("decision unexpectedly carried enforcement authority")
    reasons = document.get("reason_codes")
    if not isinstance(reasons, list) or "SHADOW_ACTION_OVERRIDDEN" not in reasons:
        raise DrillError("decision did not explain the shadow override")
    decision_id = document.get("decision_id")
    if not isinstance(decision_id, str) or not 8 <= len(decision_id) <= 128:
        raise DrillError("decision ID is missing or malformed")


def validate_admin_summary(document: dict[str, object], minimum_decisions: int, minimum_outcomes: int) -> None:
    if document.get("schema_version") != "palisade.admin-summary.v10":
        raise DrillError("admin summary version changed")
    runtime = document.get("runtime")
    capabilities = document.get("capabilities")
    traffic = document.get("traffic")
    recording = document.get("recording")
    if not isinstance(runtime, dict) or runtime.get("mode") != "shadow" or runtime.get("rollout_id") not in (None, ""):
        raise DrillError("admin summary did not report an unprivileged shadow runtime")
    if not isinstance(capabilities, dict) or capabilities.get("shadow_log") is not True:
        raise DrillError("admin summary did not report the encrypted shadow sink")
    if not isinstance(traffic, dict) or type(traffic.get("decisions")) is not int or traffic["decisions"] < minimum_decisions:
        raise DrillError("admin decision counter did not advance")
    if (
        not isinstance(recording, dict)
        or type(recording.get("decisions")) is not int
        or type(recording.get("outcomes")) is not int
        or recording["decisions"] < minimum_decisions
        or recording["outcomes"] < minimum_outcomes
        or recording.get("dropped") != 0
    ):
        raise DrillError("admin recording counters did not match the accepted synthetic flow")


def validate_analysis(document: dict[str, object]) -> None:
    if document.get("schema_version") != "palisade.shadow-analysis.v4":
        raise DrillError("aggregate shadow analysis version changed")
    source = document.get("source")
    readiness = document.get("readiness")
    decisions = document.get("decisions")
    if (
        not isinstance(source, dict)
        or source.get("records") != 3
        or source.get("decisions") != 2
        or source.get("outcomes") != 1
    ):
        raise DrillError("aggregate analysis did not authenticate the exact synthetic record set")
    if (
        not isinstance(readiness, dict)
        or readiness.get("automatic_enforcement") is not False
        or readiness.get("operator_action") != "remain_shadow"
    ):
        raise DrillError("aggregate analysis attempted to authorize enforcement")
    if (
        not isinstance(decisions, dict)
        or decisions.get("shadow_risky_enforcements") != 0
        or not isinstance(decisions.get("modes"), dict)
        or decisions["modes"].get("shadow") != 2
    ):
        raise DrillError("aggregate analysis reported an unsafe shadow action")


def _wait_ready(process: subprocess.Popen[bytes], port: int) -> None:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise DrillError("PALISADE exited before loopback readiness")
        try:
            status, _, _ = _request(port, "GET", "/health/ready", expect_json=False)
            if status == 200:
                return
        except DrillError:
            pass
        time.sleep(0.05)
    raise DrillError("PALISADE did not become ready within ten seconds")


def _start_server(binary: Path, environment: dict[str, str], log_dir: Path, key_file: Path) -> tuple[subprocess.Popen[bytes], int, int]:
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
            "--shadow-log-dir",
            os.fspath(log_dir),
            "--shadow-log-key-file",
            os.fspath(key_file),
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
    return process, public_port, admin_port


def _stop_server(process: subprocess.Popen[bytes], require_success: bool = True) -> None:
    if process.poll() is None:
        process.send_signal(signal.SIGTERM)
    try:
        return_code = process.wait(timeout=10)
    except subprocess.TimeoutExpired as error:
        process.kill()
        process.wait(timeout=5)
        raise DrillError("PALISADE did not stop within ten seconds") from error
    if require_success and return_code != 0:
        raise DrillError("PALISADE returned an error during graceful shutdown")


def _exercise_server(
    public_port: int,
    admin_port: int,
    api_key: str,
    admin_key: str,
    round_number: int,
    record_outcome: bool,
) -> dict[str, object]:
    status, _, _ = _request(public_port, "GET", "/v1/admin/summary", expect_json=False)
    if status != 404:
        raise DrillError("administrative summary was exposed on the public listener")

    status, session, headers = _request(public_port, "POST", "/v1/session", bearer=api_key)
    if status != 201 or not isinstance(session.get("session_id"), str):
        raise DrillError("backend session issuance failed")
    session_id = session["session_id"]
    set_cookie = headers.get("set-cookie", "")
    cookie = set_cookie.split(";", 1)[0]
    if not cookie.startswith("__Host-palisade_session="):
        raise DrillError("secure session cookie was not issued")

    status, proof, _ = _request(
        public_port,
        "POST",
        "/v1/token",
        {"session_id": session_id, "action": "read", "ttl_seconds": 60},
        api_key,
        cookie,
    )
    proof_token = proof.get("proof_token")
    if status != 201 or not isinstance(proof_token, str):
        raise DrillError("one-time proof issuance failed")

    status, decision, _ = _request(
        public_port,
        "POST",
        "/v1/decision",
        {
            "session_id": session_id,
            "action": "read",
            "endpoint_class": "public_content",
            "evaluation_cohort": "unknown",
            "sequence": round_number,
            "proof_token": proof_token,
            "observations": dict(RISKY_OBSERVATIONS),
        },
        cookie=cookie,
    )
    if status != 200:
        raise DrillError("synthetic decision request failed")
    validate_decision(decision)

    if record_outcome:
        status, _, _ = _request(
            public_port,
            "POST",
            "/v1/outcome",
            {
                "session_id": session_id,
                "decision_id": decision["decision_id"],
                "endpoint_class": "public_content",
                "outcome": "operator_confirmed_abuse",
                "provenance": "operator_review",
                "confidence": "confirmed",
            },
            api_key,
            cookie,
        )
        if status != 202:
            raise DrillError("normalized synthetic outcome was not accepted")

    status, summary, _ = _request(admin_port, "GET", "/v1/admin/summary", bearer=admin_key)
    if status != 200:
        raise DrillError("loopback admin summary was unavailable")
    validate_admin_summary(summary, minimum_decisions=1, minimum_outcomes=1 if record_outcome else 0)
    return decision


def _assert_unsafe_mode_rejected(binary: Path, environment: dict[str, str]) -> None:
    completed = subprocess.run(
        [
            os.fspath(binary),
            "serve",
            "--listen",
            f"127.0.0.1:{_reserve_loopback_port()}",
            "--admin-listen",
            f"127.0.0.1:{_reserve_loopback_port()}",
            "--mode",
            "enforce",
        ],
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        timeout=5,
        check=False,
    )
    if completed.returncode == 0 or b"requires a signed rollout plan" not in completed.stderr:
        raise DrillError("unsigned CLI enforcement did not fail closed")


def _run_checked(command: list[str], phase: str, environment: dict[str, str]) -> str:
    try:
        completed = subprocess.run(
            command,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=30,
            check=True,
            text=True,
            encoding="utf-8",
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        raise DrillError(f"local PALISADE {phase} command failed") from error
    if len(completed.stdout) > 64 * 1024:
        raise DrillError("local verification output exceeded the drill budget")
    return completed.stdout


def _validate_binary(path: Path) -> Path:
    if path.is_symlink():
        raise DrillError("binary must be a regular non-symlink file")
    try:
        resolved = path.resolve(strict=True)
        info = resolved.stat()
    except OSError as error:
        raise DrillError("binary is unavailable") from error
    if not stat.S_ISREG(info.st_mode) or not os.access(resolved, os.X_OK):
        raise DrillError("binary must be a regular executable file")
    return resolved


def run_drill(binary: Path) -> dict[str, object]:
    binary = _validate_binary(binary)
    temporary_root = Path(tempfile.mkdtemp(prefix="palisade-operator-drill-")).resolve(strict=True)
    temporary_root.chmod(0o700)
    try:
        log_dir = temporary_root / "shadow"
        log_dir.mkdir(mode=0o700)
        key_file = temporary_root / "shadow.key"
        descriptor = os.open(key_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(secrets.token_bytes(32))
            handle.flush()
            os.fsync(handle.fileno())

        api_key = _secret()
        admin_key = _secret()
        base_environment = _base_environment()
        environment = dict(base_environment)
        environment.update(
            {
                "PALISADE_HMAC_KEY": _secret(),
                "PALISADE_API_KEY": api_key,
                "PALISADE_ADMIN_KEY": admin_key,
            }
        )

        process, public_port, admin_port = _start_server(binary, environment, log_dir, key_file)
        try:
            _exercise_server(public_port, admin_port, api_key, admin_key, 1, True)
        finally:
            _stop_server(process)

        first_verification = _run_checked(
            [os.fspath(binary), "verify-shadow-log", "--dir", os.fspath(log_dir), "--key-file", os.fspath(key_file)],
            "first chain verification",
            base_environment,
        )
        if "records=2 decisions=1 outcomes=1" not in first_verification:
            raise DrillError("first encrypted chain verification did not match the synthetic flow")

        _assert_unsafe_mode_rejected(binary, environment)
        process, public_port, admin_port = _start_server(binary, environment, log_dir, key_file)
        try:
            _exercise_server(public_port, admin_port, api_key, admin_key, 1, False)
        finally:
            _stop_server(process)

        final_verification = _run_checked(
            [os.fspath(binary), "verify-shadow-log", "--dir", os.fspath(log_dir), "--key-file", os.fspath(key_file)],
            "post-restart chain verification",
            base_environment,
        )
        if "records=3 decisions=2 outcomes=1" not in final_verification:
            raise DrillError("post-restart encrypted chain verification did not match the synthetic flow")

        analysis_path = temporary_root / "analysis.json"
        _run_checked(
            [
                os.fspath(binary),
                "analyze-shadow-log",
                "--dir",
                os.fspath(log_dir),
                "--key-file",
                os.fspath(key_file),
                "--output",
                os.fspath(analysis_path),
            ],
            "aggregate analysis",
            base_environment,
        )
        if analysis_path.is_symlink() or analysis_path.stat().st_mode & 0o077:
            raise DrillError("aggregate analysis output was not owner-only")
        try:
            analysis = json.loads(analysis_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
            raise DrillError("aggregate analysis output was not valid JSON") from error
        if not isinstance(analysis, dict):
            raise DrillError("aggregate analysis root was not an object")
        validate_analysis(analysis)
        return {
            "schema_version": SCHEMA_VERSION,
            "synthetic_only": True,
            "network_scope": "loopback_only",
            "raw_deployment_records_used": False,
            "checks": list(EXPECTED_CHECKS),
            "records": {"decisions": 2, "outcomes": 1, "total": 3},
            "result": "passed",
        }
    finally:
        for root, directories, files in os.walk(temporary_root, topdown=False):
            for name in files:
                os.unlink(Path(root) / name)
            for name in directories:
                os.rmdir(Path(root) / name)
        os.rmdir(temporary_root)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path, help="locally built PALISADE executable")
    arguments = parser.parse_args(argv)
    try:
        result = run_drill(arguments.binary)
    except (DrillError, OSError, subprocess.SubprocessError) as error:
        print(f"operator-shadow-drill: failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
