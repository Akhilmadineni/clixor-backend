from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent
class IngressBoundaryTests(unittest.TestCase):
    def test_tcp_listener_cannot_proxy_forged_cloudflare_identity(self) -> None:
        nginx = (ROOT / "api-gateway-nginx.conf").read_text(encoding="utf-8")
        self.assertIn("listen unix:/run/clixor-origin/gateway.sock default_server;", nginx)
        self.assertGreaterEqual(nginx.count("listen unix:/run/clixor-origin/gateway.sock;"), 2)
        self.assertIn("proxy_set_header CF-Connecting-IP $http_cf_connecting_ip;", nginx)
        health_server = nginx[nginx.index("listen 8080;") - 200 :]
        self.assertIn('proxy_set_header CF-Connecting-IP "";', health_server)
        self.assertIn("location / { return 404; }", health_server)
        compose = (ROOT / "compose.yaml").read_text(encoding="utf-8")
        unit = (ROOT / "cloudflared.service").read_text(encoding="utf-8")
        self.assertIn('user: "986:987"', compose)
        self.assertIn("uid=986,gid=987", compose)
        self.assertIn("umask 007", compose)
        self.assertIn("create_host_path: false", compose)
        self.assertIn("source: /var/lib/clixor/origin-gate-public", compose)
        self.assertIn("target: /run/clixor-origin-gate", compose)
        self.assertIn("SupplementaryGroups=clixor-origin", unit)
        self.assertIn("ExecStartPre=+/usr/bin/install -d -m 0750 -o 986 -g 987", unit)
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
            ["d /run/clixor-origin 0750 clixor-gateway clixor-origin -"],
        )
        install_at = bootstrap.index("/etc/tmpfiles.d/clixor-origin.conf")
        create_at = bootstrap.index("systemd-tmpfiles --create", install_at)
        self.assertLess(install_at, create_at)
        bootstrap_call = deploy.index("CLIXOR_DEFER_HOST_TOOL_ACTIVATION=true")
        first_compose_mutation = deploy.index("docker compose", bootstrap_call)
        self.assertLess(bootstrap_call, first_compose_mutation)
        self.assertIn("create_host_path: false", compose)

    def test_persistent_origin_gate_is_root_controlled_and_canary_is_independent(self) -> None:
        nginx = (ROOT / "api-gateway-nginx.conf").read_text(encoding="utf-8")
        compose = (ROOT / "compose.yaml").read_text(encoding="utf-8")
        tmpfiles = (ROOT / "clixor-cloudflare-origin-gate.conf").read_text(
            encoding="utf-8"
        )
        bootstrap = (ROOT / "bootstrap.sh").read_text(encoding="utf-8")
        unit = (ROOT / "clixor-cloudflare-promote.service").read_text(
            encoding="utf-8"
        )
        self.assertIn("if (!-f /run/clixor-origin-gate/public-open)", nginx)
        self.assertIn('return 503 "clixor-origin-gate-closed\\n";', nginx)
        prod = nginx.index("server_name clustr-api.atlanteanz.com clixor.atlanteanz.com;")
        canary = nginx.index("server_name clixor-oci-canary.atlanteanz.com;")
        health = nginx.index("listen 8080;")
        self.assertLess(prod, canary)
        self.assertNotIn("public-open", nginx[canary:health])
        self.assertIn("source: /var/lib/clixor/origin-gate-public", compose)
        mount = compose[compose.index("source: /var/lib/clixor/origin-gate-public") :]
        self.assertIn("read_only: true", mount[:300])
        self.assertIn("create_host_path: false", mount[:300])
        self.assertIn("d /var/lib/clixor/origin-gate-public 0755 root root -", tmpfiles)
        self.assertIn("public-open 0400 root root", tmpfiles)
        self.assertIn("cloudflare-promote.py initialize-gate", bootstrap)
        self.assertIn("ReadWritePaths=/var/lib/clixor", unit)
        self.assertIn("RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6", unit)
        deploy = (ROOT / "deploy.sh").read_text(encoding="utf-8")
        restore = deploy.index('"${previous_runtime_root}/api-gateway/nginx.conf"')
        self.assertIn("install -m 0400 -o 986 -g 987", deploy[restore - 100 : restore])

    def test_existing_release_installs_gate_before_reconciling_gateway(self) -> None:
        bootstrap = (ROOT / "bootstrap.sh").read_text(encoding="utf-8")
        deploy = (ROOT / "deploy.sh").read_text(encoding="utf-8")
        gate_install = bootstrap.index("clixor-cloudflare-origin-gate.conf")
        gate_create = bootstrap.index(
            "systemd-tmpfiles --create /etc/tmpfiles.d/clixor-cloudflare-origin-gate.conf",
            gate_install,
        )
        nginx_install = bootstrap.index(
            'install -m 0400 -o 986 -g 987 "${script_root}/api-gateway-nginx.conf"'
        )
        gate_initialize = bootstrap.index("cloudflare-promote.py initialize-gate")
        self.assertLess(gate_install, gate_create)
        self.assertLess(gate_create, nginx_install)
        self.assertLess(nginx_install, gate_initialize)

        bootstrap_call = deploy.index('sh "${source_root}/deploy/oci/bootstrap.sh"')
        gateway_reconcile = deploy.index("--remove-orphans api-gateway", bootstrap_call)
        nginx_test = deploy.index(
            "docker exec clixor-oci-api-gateway nginx -t", gateway_reconcile
        )
        nginx_reload = deploy.index(
            "docker exec clixor-oci-api-gateway nginx -s reload", nginx_test
        )
        self.assertLess(bootstrap_call, gateway_reconcile)
        self.assertLess(gateway_reconcile, nginx_test)
        self.assertLess(nginx_test, nginx_reload)

    def test_legacy_persistent_token_fallback_is_absent(self) -> None:
        installer = (ROOT / "install-cloudflared-service.sh").read_text(encoding="utf-8")
        retirement = (ROOT / "quarantine-staging-secrets.sh").read_text(encoding="utf-8")
        self.assertNotIn("/etc/cloudflared/token", installer)
        self.assertIn("/run/clixor/cloudflare-connector/current/token", installer)
        self.assertIn("selected release connector credential", installer)
        self.assertIn("runtime-reconciler.py validate-release", installer)
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

    def test_release_bound_canary_connector_cannot_promote_or_hydrate_partial_cohort(self) -> None:
        deploy = (ROOT / "deploy.sh").read_text(encoding="utf-8")
        helper = (ROOT / "cloudflare-canary-credential.py").read_text(encoding="utf-8")
        unit = (ROOT / "cloudflared.service").read_text(encoding="utf-8")
        self.assertIn('CLIXOR_ENABLE_CANARY_CONNECTOR', deploy)
        self.assertIn('the canary connector cannot bypass the complete Vault cohort', deploy)
        self.assertIn('production origin gate must remain closed during canary', deploy)
        self.assertIn('CLUSTER_ENV=staging', deploy)
        self.assertIn('--version-number', helper)
        self.assertIn('OCI_CLI_AUTH": "instance_principal"', helper)
        self.assertNotIn('print(token', helper)
        self.assertIn('/run/clixor/cloudflare-connector/current/token', unit)
        self.assertIn('--metrics 127.0.0.1:20241', unit)
        self.assertIn("candidate connector unexpectedly owns the production hostname", deploy)
        self.assertIn('run_disposable_public_smoke "${source_sha}"', deploy)

    def test_deploy_source_and_connector_transitions_are_fail_closed(self) -> None:
        deploy = (ROOT / "deploy.sh").read_text(encoding="utf-8")
        wrapper = (ROOT / "actions-deploy.sh").read_text(encoding="utf-8")
        bootstrap = (ROOT / "bootstrap.sh").read_text(encoding="utf-8")
        installer = (ROOT / "install-cloudflared-service.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("CLIXOR_APPROVED_GIT_DIR is required", deploy)
        self.assertIn("verify-approved-source", deploy)
        self.assertIn('--git-dir "${approved_git_directory}"', deploy)
        self.assertIn('stat -c \'%u:%g:%a\' "${source_root}"', deploy)
        self.assertIn('CLIXOR_APPROVED_GIT_DIR="${mirror_root}"', wrapper)
        self.assertIn('-type d -exec /usr/bin/chmod 0500', wrapper)

        disabled = deploy.index("deactivate_cloudflared()")
        stopped = deploy.index("systemctl stop cloudflared.service", disabled)
        disabled_unit = deploy.index("systemctl disable cloudflared.service", stopped)
        credential_clean = deploy.index(
            '"${host_tool_stage}/bin/cloudflare-canary-credential.py" prepare',
            disabled_unit,
        )
        credential_verify = deploy.index(
            '"${host_tool_stage}/bin/cloudflare-canary-credential.py" verify',
            credential_clean,
        )
        self.assertLess(stopped, disabled_unit)
        self.assertLess(disabled_unit, credential_clean)
        self.assertLess(credential_clean, credential_verify)
        candidate_else = deploy.index(
            "else\n  deactivate_cloudflared\nfi", credential_verify
        )
        publication = deploy.index("journal_phase publishing", candidate_else)
        self.assertLess(candidate_else, publication)

        restore = deploy.index("restore_cloudflared()")
        credential_restore = deploy.index(
            "if restore_previous_connector_credential; then", restore
        )
        refusal = deploy.index(
            'if [ "${previous_connector_credential_restored}" != "true" ]',
            credential_restore,
        )
        prior_restart = deploy.index(
            "systemctl restart --no-block cloudflared.service", refusal
        )
        self.assertLess(credential_restore, refusal)
        self.assertLess(refusal, prior_restart)
        refusal_block = deploy[refusal:prior_restart]
        self.assertIn("systemctl stop cloudflared.service", refusal_block)
        self.assertIn("systemctl disable cloudflared.service", refusal_block)
        self.assertIn("return 1", refusal_block)
        self.assertIn(
            'if [ "${cloudflare_rollback_failed}" -ne 0 ]; then', deploy
        )
        self.assertIn(
            "skipping selected-release reconciliation after connector credential restoration failed",
            deploy,
        )
        self.assertEqual(deploy.count("cloudflare_rollback_failed=0"), 1)

        # No bootstrap-side restart may bypass the reconciler's synchronous
        # local and remote authority checks.  The standalone installer has the
        # same start -> verify -> fail-closed contract.
        self.assertNotIn("try-restart cloudflared.service", bootstrap)
        install_start = installer.index("systemctl enable --now cloudflared.service")
        install_remote = installer.index("verify-remote", install_start)
        install_refusal = installer.index("rm -f -- /run/clixor/runtime-ready", install_remote)
        install_stop = installer.index("systemctl stop cloudflared.service", install_refusal)
        install_disable = installer.index("systemctl disable cloudflared.service", install_stop)
        self.assertLess(install_start, install_remote)
        self.assertLess(install_remote, install_refusal)
        self.assertLess(install_refusal, install_stop)
        self.assertLess(install_stop, install_disable)

    def test_promoter_is_immutable_installed_and_hardened(self) -> None:
        bootstrap=(ROOT/"bootstrap.sh").read_text()
        unit=(ROOT/"clixor-cloudflare-promote.service").read_text()
        self.assertIn('install -m 0555 -o 0 -g 0 "${script_root}/cloudflare-promote.py"',bootstrap)
        self.assertIn("cloudflare-promote.py.sha256",bootstrap)
        self.assertIn("ExecStartPre=/usr/bin/sha256sum --check --strict",unit)
        self.assertIn("ExecStart=/usr/local/libexec/clixor/cloudflare-promote.py execute",unit)
        self.assertIn("LoadCredential=cloudflare-control-token:",unit)
        self.assertNotIn("/srv/clixor/repo",unit)

if __name__ == "__main__":
    unittest.main()
