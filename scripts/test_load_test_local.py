from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import os
import tempfile
import threading
import time
import unittest
from unittest import mock

from scripts import load_test_local


class _ProtocolHandler(BaseHTTPRequestHandler):
    requests: list[tuple[str, dict[str, object], dict[str, str]]] = []
    malformed_origin = False

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        payload = json.loads(self.rfile.read(length) or b"{}")
        type(self).requests.append((self.path, payload, {key.lower(): value for key, value in self.headers.items()}))
        if self.path == "/v1/session":
            body = json.dumps({"session_id": "synthetic-session-0001"}).encode("utf-8")
            self.send_response(201)
            self.send_header("Content-Type", "application/json")
            self.send_header("Set-Cookie", "__Host-palisade_session=synthetic-cookie; Secure; HttpOnly")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path == "/v1/token":
            body = json.dumps({"proof_token": "p" * 64}).encode("utf-8")
            self.send_response(201)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path == "/v1/origin-check":
            self.send_response(204)
            self.send_header("X-Palisade-Decision-ID", "synthetic-decision-0001")
            self.send_header("X-Palisade-Action", "block" if type(self).malformed_origin else "observe")
            self.send_header("X-Palisade-Handling", "pass")
            self.send_header("X-Palisade-Mode", "shadow")
            self.end_headers()
            return
        self.send_error(404)

    def log_message(self, _format, *_arguments):
        return


class LoadTestLocalTests(unittest.TestCase):
    def setUp(self):
        _ProtocolHandler.requests = []
        _ProtocolHandler.malformed_origin = False

    def _server(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), _ProtocolHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return server

    def _valid_report(self):
        return {
            "schema_version": load_test_local.REPORT_SCHEMA_VERSION,
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
            "configured": {"duration_seconds": 1, "concurrency": 1, "max_operations": 1},
            "observed": {
                "wall_duration_ms": 1.5,
                "attempted_operations": 1,
                "completed_operations": 1,
                "failed_operations": 0,
                "http_requests": 3,
                "throughput_operations_per_second": 666.667,
                "stop_reason": "max_operations",
            },
            "latency_ms": {
                "samples": 1,
                "p50": 1.0,
                "p95": 1.0,
                "p99": 1.0,
                "maximum": 1.0,
                "method": "nearest_rank_successes",
            },
            "failures": {name: 0 for name in load_test_local.FAILURE_CLASSES},
            "limitations": list(load_test_local.LIMITATIONS),
            "result": "passed",
        }

    def test_plan_is_bounded_loopback_and_synthetic(self):
        plan = load_test_local.execution_plan(load_test_local.Config())
        self.assertEqual(plan["schema_version"], load_test_local.PLAN_SCHEMA_VERSION)
        self.assertEqual(plan["network_scope"], "loopback_only")
        self.assertTrue(plan["synthetic_only"])
        self.assertFalse(plan["raw_deployment_records_used"])
        self.assertEqual(plan["configured"]["max_operations"], load_test_local.MAX_OPERATIONS)
        flattened = json.dumps(plan, sort_keys=True)
        self.assertNotIn("http://", flattened)
        self.assertNotIn("https://", flattened)
        self.assertNotIn("session_id", flattened)

    def test_configuration_rejects_boolean_and_out_of_range_values(self):
        invalid = (
            load_test_local.Config(duration_seconds=True),
            load_test_local.Config(duration_seconds=301),
            load_test_local.Config(concurrency=0),
            load_test_local.Config(concurrency=65),
            load_test_local.Config(max_operations=0),
            load_test_local.Config(max_operations=200_001),
        )
        for config in invalid:
            with self.subTest(config=config):
                with self.assertRaises(load_test_local.LoadTestError):
                    load_test_local.validate_config(config)

    def test_nearest_rank_percentiles_are_exact_and_ordered(self):
        values = list(range(1, 101))
        self.assertEqual(load_test_local._nearest_rank(values, 50), 50)
        self.assertEqual(load_test_local._nearest_rank(values, 95), 95)
        self.assertEqual(load_test_local._nearest_rank(values, 99), 99)
        self.assertIsNone(load_test_local._nearest_rank([], 95))

    def test_closed_report_accepts_balanced_aggregate(self):
        load_test_local._validate_report(self._valid_report())

    def test_report_rejects_counter_and_result_poisoning(self):
        report = self._valid_report()
        report["observed"]["failed_operations"] = 1
        with self.assertRaisesRegex(load_test_local.LoadTestError, "balance"):
            load_test_local._validate_report(report)
        report = self._valid_report()
        report["result"] = "failed"
        with self.assertRaisesRegex(load_test_local.LoadTestError, "result"):
            load_test_local._validate_report(report)

    def test_protocol_uses_cookie_fresh_proof_binding_and_closed_signals(self):
        server = self._server()
        port = server.server_address[1]
        session = load_test_local._issue_session(port, "a" * 43)
        proof = load_test_local._issue_proof(port, "a" * 43, session)
        load_test_local._check_origin(port, session, proof, 1)
        self.assertEqual([request[0] for request in _ProtocolHandler.requests], ["/v1/session", "/v1/token", "/v1/origin-check"])
        token = _ProtocolHandler.requests[1]
        origin = _ProtocolHandler.requests[2]
        self.assertEqual(token[1], {"session_id": session.session_id, "action": "read", "ttl_seconds": 60})
        self.assertEqual(origin[1]["observations"], load_test_local.OBSERVATIONS)
        self.assertEqual(origin[1]["sequence"], 1)
        self.assertEqual(origin[2]["cookie"], session.cookie)
        self.assertEqual(len(origin[2]["x-palisade-challenge-binding"]), 43)
        self.assertNotEqual(origin[1]["proof_token"], "")

    def test_origin_contract_rejects_risky_shadow_response(self):
        server = self._server()
        _ProtocolHandler.malformed_origin = True
        session = load_test_local.Session("synthetic-session-0001", "__Host-palisade_session=synthetic-cookie")
        with self.assertRaisesRegex(load_test_local.LoadTestError, "Shadow contract"):
            load_test_local._check_origin(server.server_address[1], session, "p" * 64, 1)

    def test_worker_stops_at_global_operation_budget(self):
        server = self._server()
        port = server.server_address[1]
        session = load_test_local._issue_session(port, "a" * 43)
        counter = [0]
        result = load_test_local._worker(
            port,
            "a" * 43,
            session,
            time.monotonic() + 10,
            3,
            counter,
            threading.Lock(),
        )
        self.assertEqual((result.completed, result.failed, result.http_requests), (3, 0, 6))
        self.assertEqual(counter[0], 3)
        self.assertEqual(len(result.latencies_ns), 3)

    def test_symlink_binary_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "palisade"
            target.write_text("synthetic\n", encoding="utf-8")
            target.chmod(0o700)
            link = Path(directory) / "linked"
            link.symlink_to(target)
            with self.assertRaisesRegex(load_test_local.LoadTestError, "non-symlink"):
                load_test_local._validate_binary(link)

    def test_subprocess_environment_does_not_inherit_unrelated_secrets(self):
        with mock.patch.dict(os.environ, {"AWS_SECRET_ACCESS_KEY": "synthetic-secret"}, clear=False):
            environment = load_test_local._base_environment()
        self.assertNotIn("AWS_SECRET_ACCESS_KEY", environment)
        self.assertIn("PATH", environment)


if __name__ == "__main__":
    unittest.main()
