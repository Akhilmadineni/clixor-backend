from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent
class IngressBoundaryTests(unittest.TestCase):
    def test_tcp_listener_cannot_proxy_forged_cloudflare_identity(self) -> None:
        nginx = (ROOT / "api-gateway-nginx.conf").read_text(encoding="utf-8")
        socket_server, health_server = nginx.split("  server {", 2)[1:]
        self.assertIn("listen unix:/run/clixor-origin/gateway.sock;", socket_server)
        self.assertIn("proxy_set_header CF-Connecting-IP $http_cf_connecting_ip;", socket_server)
        self.assertIn("listen 8080;", health_server)
        self.assertIn('proxy_set_header CF-Connecting-IP "";', health_server)
        self.assertIn("location / { return 404; }", health_server)
        compose = (ROOT / "compose.yaml").read_text(encoding="utf-8")
        unit = (ROOT / "cloudflared.service").read_text(encoding="utf-8")
        self.assertIn('user: "101:987"', compose)
        self.assertIn("umask 007", compose)
        self.assertIn("create_host_path: false", compose)
        self.assertIn("SupplementaryGroups=clixor-origin", unit)
        self.assertIn("ExecStartPre=+/usr/bin/install -d -m 0750 -o 101 -g 987", unit)
        route = (ROOT / "cloudflared-config.yml.example").read_text(encoding="utf-8")
        self.assertIn("service: unix:/run/clixor-origin/gateway.sock", route)
        self.assertNotIn("172.30.254.2:8080", route)

    def test_cold_boot_boundary_precedes_docker_and_is_idempotent(self) -> None:
        tmpfiles = (ROOT / "clixor-origin.conf").read_text(encoding="utf-8")
        bootstrap = (ROOT / "bootstrap.sh").read_text(encoding="utf-8")
        deploy = (ROOT / "deploy.sh").read_text(encoding="utf-8")
        compose = (ROOT / "compose.yaml").read_text(encoding="utf-8")
        self.assertEqual(
            [line for line in tmpfiles.splitlines() if line and not line.startswith("#")],
            ["d /run/clixor-origin 0750 101 clixor-origin -"],
        )
        install_at = bootstrap.index("/etc/tmpfiles.d/clixor-origin.conf")
        create_at = bootstrap.index("systemd-tmpfiles --create", install_at)
        self.assertLess(install_at, create_at)
        bootstrap_call = deploy.index("CLIXOR_DEFER_HOST_TOOL_ACTIVATION=true")
        first_compose_mutation = deploy.index("docker compose", bootstrap_call)
        self.assertLess(bootstrap_call, first_compose_mutation)
        self.assertIn("create_host_path: false", compose)

    def test_legacy_persistent_token_fallback_is_absent(self) -> None:
        installer = (ROOT / "install-cloudflared-service.sh").read_text(encoding="utf-8")
        retirement = (ROOT / "quarantine-staging-secrets.sh").read_text(encoding="utf-8")
        self.assertNotIn("/etc/cloudflared/token", installer)
        self.assertIn("Vault tmpfs generation", installer)
        self.assertIn("revoke and remove the retired Cloudflare connector token", retirement)
        self.assertNotIn("cloudflare_quarantine", retirement)
        self.assertNotIn("cloudflare-file)", retirement)

    def test_actions_are_canary_only_and_require_disposable_smoke(self) -> None:
        actions = (ROOT / "actions-deploy.sh").read_text(encoding="utf-8")
        deploy = (ROOT / "deploy.sh").read_text(encoding="utf-8")
        self.assertIn("CLIXOR_INGRESS_STAGE=canary", actions)
        self.assertIn("CLIXOR_PUBLIC_SMOKE_BASE_URL=https://clixor-oci-canary", actions)
        self.assertIn("production route ownership is a separate evidence-gated promotion", deploy)
        self.assertIn('verify_production_not_candidate "${source_sha}"', deploy)
        self.assertIn("candidate connector unexpectedly owns the production hostname", deploy)
        self.assertIn('run_disposable_public_smoke "${source_sha}"', deploy)

if __name__ == "__main__":
    unittest.main()
