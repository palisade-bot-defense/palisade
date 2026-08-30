import json
from pathlib import Path
import subprocess
import unittest


class NginxDeploymentContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = Path(__file__).resolve().parent.parent
        cls.script = cls.root / "scripts" / "nginx-deployment-test.sh"
        cls.compose = (cls.root / "deployments" / "nginx" / "compose.yaml").read_text(encoding="utf-8")
        cls.nginx = (cls.root / "deployments" / "nginx" / "nginx.conf").read_text(encoding="utf-8")
        cls.dockerfile = (cls.root / "deployments" / "nginx" / "Dockerfile").read_text(encoding="utf-8")
        cls.fixture = (cls.root / "internal" / "proxytlsdiag" / "nginx_test.go").read_text(encoding="utf-8")

    def test_plan_is_closed_synthetic_and_digest_pinned(self):
        result = subprocess.run(
            [str(self.script), "--plan"], cwd=self.root, check=True, capture_output=True, text=True
        )
        plan = json.loads(result.stdout)
        self.assertEqual(
            set(plan),
            {
                "schema_version",
                "synthetic_only",
                "raw_deployment_records_used",
                "network_scope",
                "host_ports_published",
                "proxy_image",
                "profiles",
                "limitations",
            },
        )
        self.assertEqual(plan["schema_version"], "palisade.nginx-deployment-plan.v1")
        self.assertTrue(plan["synthetic_only"])
        self.assertFalse(plan["raw_deployment_records_used"])
        self.assertEqual(plan["network_scope"], "internal_docker_network_only")
        self.assertFalse(plan["host_ports_published"])
        self.assertRegex(plan["proxy_image"], r"^nginx@sha256:[0-9a-f]{64}$")
        self.assertEqual(plan["profiles"], ["trusted_nginx_http2_tls", "direct_header_spoof"])
        self.assertEqual(len(plan["limitations"]), 4)

    def test_plan_rejects_extra_arguments(self):
        result = subprocess.run(
            [str(self.script), "--plan", "unexpected"], cwd=self.root, capture_output=True, text=True
        )
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")

    def test_compose_is_internal_fixed_and_least_privilege(self):
        digest = "nginx@sha256:db35bfc6b2951e7f8a72db5db120288c127ffaeeb4a6d4b95a26fead017d5913"
        self.assertIn(f"image: {digest}", self.compose)
        self.assertNotIn("image: nginx:alpine", self.compose)
        self.assertIn("internal: true", self.compose)
        self.assertNotIn("ports:", self.compose)
        for address in ("192.0.2.10", "192.0.2.20", "192.0.2.30", "192.0.2.40"):
            self.assertEqual(self.compose.count(f"ipv4_address: {address}"), 1)
        self.assertIn('user: "101:101"', self.compose)
        self.assertIn("fixture_certs:/certs:ro", self.compose)
        self.assertGreaterEqual(self.compose.count('cap_drop: ["ALL"]'), 4)
        self.assertGreaterEqual(self.compose.count('security_opt: ["no-new-privileges:true"]'), 4)
        self.assertNotIn("-----BEGIN", self.compose)
        self.assertRegex(self.dockerfile, r"FROM golang:1\.27\.0-alpine@sha256:[0-9a-f]{64} AS build")

    def test_nginx_overwrites_only_closed_proxy_headers(self):
        self.assertIn("listen 8443 ssl;", self.nginx)
        self.assertIn("http2 on;", self.nginx)
        self.assertIn("access_log off;", self.nginx)
        self.assertIn("proxy_http_version 1.1;", self.nginx)
        self.assertIn("proxy_set_header X-Real-IP $remote_addr;", self.nginx)
        self.assertIn("proxy_set_header X-Forwarded-Proto $scheme;", self.nginx)
        for header in ("CF-Connecting-IP", "X-Forwarded-For", "Forwarded"):
            self.assertIn(f'proxy_set_header {header} "";', self.nginx)
        self.assertNotIn("access_log /", self.nginx)

    def test_fixture_trusts_only_exact_nginx_peer(self):
        self.assertIn('nginxAddress + "/32"', self.fixture)
        self.assertIn('TrustedClientIPHeader: "X-Real-IP"', self.fixture)
        self.assertIn('TrustedProtoHeader:    "X-Forwarded-Proto"', self.fixture)
        self.assertIn('peer == verifierAddress', self.fixture)
        self.assertIn('case nginxAddress:', self.fixture)
        private_key_marker = "-----BEGIN " + "PRIVATE KEY-----"
        self.assertNotIn(private_key_marker, self.fixture)


if __name__ == "__main__":
    unittest.main()
