from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import multiprocessing
import os
import signal
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("cloudflare_promote", ROOT / "cloudflare-promote.py")
module = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(module)

OLD_TUNNEL = "11111111-1111-1111-1111-111111111111"
NEW_TUNNEL = "22222222-2222-2222-2222-222222222222"

def reviewed_old_config():
    return {"ingress":[
        {"hostname":module.PRODUCTION_HOSTS[0],"service":"http://retired-nas:8080"},
        {"hostname":module.PRODUCTION_HOSTS[1],"service":"http://retired-nas:8080"},
        {"service":"http_status:404"},
    ]}

def expected_remote_writes(value):
    def patch_body(state):
        return {key:item for key, item in module.expected_rule(value, state).items()
                if key != "id"}
    return [
        ("PATCH", module.rule_path(value), patch_body("block-all")),
        ("PUT", f"/accounts/{value.account}/cfd_tunnel/{value.old_tunnel}/configurations",
         {"config":value.old_retired_config}),
        ("PUT", f"/accounts/{value.account}/cfd_tunnel/{value.candidate_tunnel}/configurations",
         {"config":value.candidate_live_config}),
        ("POST", f"/zones/{value.zone}/dns_records/batch",
         {"patches":module.expected_dns(value.dns, value.candidate_target)}),
        ("PATCH", module.rule_path(value), patch_body("exception")),
        ("PATCH", module.rule_path(value), patch_body("disabled")),
    ]

class FakeAPI:
    """Cloudflare-shaped fixture: rule PATCH returns a complete ruleset."""
    def __init__(self):
        self.options = None
        self.configs = {OLD_TUNNEL:reviewed_old_config(), NEW_TUNNEL:module.candidate_config()}
        self.records = [
            {"id":f"{index + 1:032x}","name":hostname,"type":"CNAME",
             "content":f"{OLD_TUNNEL}.cfargotunnel.com","proxied":True,"ttl":1}
            for index, hostname in enumerate(module.PRODUCTION_HOSTS)
        ]
        self.rule = None
        self.versions = {OLD_TUNNEL:7, NEW_TUNNEL:11}
        self.connectors = {
            OLD_TUNNEL:{"33333333-3333-3333-3333-333333333333":7},
            NEW_TUNNEL:{"44444444-4444-4444-4444-444444444444":11},
        }
        self.calls = []
        self.remote_writes = []
        self.after_write = None

    def bind(self, options):
        self.options = options
        if self.rule is None:
            self.rule = dict(module.expected_rule(options, "disabled"),
                             version="1", last_updated="2026-08-30T00:00:00Z")

    def ruleset(self):
        return {
            "id":self.options.maintenance_ruleset,
            "name":"default",
            "description":"zone custom rules",
            "kind":"zone",
            "version":"42",
            "last_updated":"2026-08-30T00:00:00Z",
            "phase":"http_request_firewall_custom",
            "rules":[copy.deepcopy(self.rule), {
                "id":"e"*32,"version":"9","action":"block","expression":"ip.src eq 192.0.2.2",
                "description":"unrelated reviewed rule","last_updated":"2026-08-29T00:00:00Z",
                "ref":"unrelated-reviewed-rule","enabled":False,
            }],
        }

    def production_hosts(self, config):
        return {rule.get("hostname") for rule in config.get("ingress", [])
                if isinstance(rule, dict) and rule.get("hostname") in module.PRODUCTION_HOSTS}

    def record_write(self, method, path, body):
        snapshot = {
            "method":method,"path":path,"body":copy.deepcopy(body),
            "old_hosts":sorted(self.production_hosts(self.configs[OLD_TUNNEL])),
            "candidate_hosts":sorted(self.production_hosts(self.configs[NEW_TUNNEL])),
            "dns":sorted({record["content"] for record in self.records}),
            "rule":module.rule_projection(self.rule),
        }
        self.remote_writes.append(snapshot)
        if self.after_write:
            self.after_write(len(self.remote_writes), snapshot)

    def request(self, method, path, body=None):
        self.calls.append((method, path, copy.deepcopy(body)))
        if "/cfd_tunnel/" in path:
            tunnel = path.split("/cfd_tunnel/", 1)[1].split("/", 1)[0]
            if method == "GET" and path.endswith("/connections"):
                return [{"id":client,"config_version":version}
                        for client, version in sorted(self.connectors[tunnel].items())]
            if method == "GET":
                return {"tunnel_id":tunnel,"version":self.versions[tunnel],
                        "config":copy.deepcopy(self.configs[tunnel])}
            self.configs[tunnel] = copy.deepcopy(body["config"])
            self.versions[tunnel] += 1
            self.connectors[tunnel] = {
                client:self.versions[tunnel] for client in self.connectors[tunnel]
            }
            self.record_write(method, path, body)
            return {"tunnel_id":tunnel,"version":self.versions[tunnel],
                    "config":copy.deepcopy(self.configs[tunnel])}
        if "/rulesets/" in path:
            if method == "GET":
                if "/rules/" in path:
                    raise AssertionError("Cloudflare has no individual-rule GET contract")
                return self.ruleset()
            if method == "PATCH" and "/rules/" in path:
                self.rule = dict(body, id=self.options.maintenance_rule,
                                 version=str(int(self.rule["version"]) + 1),
                                 last_updated="2026-08-30T00:00:01Z")
                self.record_write(method, path, body)
                return self.ruleset()
            raise AssertionError((method, path, body))
        if method == "GET" and "/dns_records?" in path:
            query = path.split("name=", 1)[1].replace("%3A", ":")
            return [copy.deepcopy(record) for record in self.records if record["name"] == query]
        if method == "POST" and path.endswith("/dns_records/batch"):
            for patch in body["patches"]:
                for record in self.records:
                    if record["id"] == patch["id"]:
                        record.update(patch)
            self.record_write(method, path, body)
            return {"patches":copy.deepcopy(body["patches"])}
        raise AssertionError((method, path, body))

def options(root: Path, api: FakeAPI):
    evidence = root / "canary-public-smoke.txt"
    raw = (f"revision={'a'*40}\nstage=canary\n"
           "smoke=passed prefix=unit checks=5 cleanup=passed\n").encode()
    evidence.write_bytes(raw); evidence.chmod(0o400)
    gate_directory = root / "origin-gate-public"
    gate_directory.mkdir(mode=0o755); gate_directory.chmod(0o755)
    release = root / f"oci-{'a'*12}-unit"
    bundle = release / "runtime-bundle"
    controller = root / "cloudflare-promote.py"
    controller.write_bytes((ROOT / "cloudflare-promote.py").read_bytes())
    controller.chmod(0o555)
    release.mkdir(mode=0o700)
    bundle.mkdir(mode=0o700)
    release_evidence = release / evidence.name
    evidence.replace(release_evidence); evidence = release_evidence
    controller_sha = hashlib.sha256(controller.read_bytes()).hexdigest()
    manifest = {
        "release": release.name,
        "source_sha": "a" * 40,
        "files": [
            {
                "path": "source-sha",
                "sha256": "f" * 64,
                "size": 41,
                "mode": 0o400,
            },
            *[
            {
                "path": path,
                "sha256": controller_sha
                if path == "host-tools/bin/cloudflare-promote.py"
                else "0" * 64,
                "size": len(controller.read_bytes())
                if path == "host-tools/bin/cloudflare-promote.py"
                else 1,
                "mode": mode,
            }
            for path, mode in sorted(module.PROMOTION_PATH_MODES.items())
            ],
        ],
    }
    manifest_path = bundle / "manifest.json"
    manifest_path.write_text(json.dumps(manifest)); manifest_path.chmod(0o400)
    current = root / "current"; current.symlink_to(release)
    value = argparse.Namespace(
        change_window="FROZEN-UNIT-1", account="a"*32, zone="b"*32,
        controller_release=str(release), controller_sha256=controller_sha,
        current_release_link=current, installed_controller=controller,
        old_tunnel=OLD_TUNNEL, candidate_tunnel=NEW_TUNNEL,
        old_config_version=api.versions[OLD_TUNNEL],
        candidate_config_version=api.versions[NEW_TUNNEL],
        old_connector_ids=sorted(api.connectors[OLD_TUNNEL]),
        candidate_connector_ids=sorted(api.connectors[NEW_TUNNEL]),
        old_target=f"{OLD_TUNNEL}.cfargotunnel.com",
        candidate_target=f"{NEW_TUNNEL}.cfargotunnel.com",
        revision="a"*40, old_config=copy.deepcopy(api.configs[OLD_TUNNEL]),
        old_retired_config=module.derive_retired_config(api.configs[OLD_TUNNEL]),
        candidate_config=module.candidate_config(),
        candidate_live_config=module.candidate_live_config(),
        state=root/"cloudflare-promotion.json", evidence=evidence,
        evidence_sha=hashlib.sha256(raw).hexdigest(),
        maintenance_ruleset="c"*32, maintenance_rule="d"*32,
        probe_source_ip="203.0.113.9", dns=[module.dns_tuple(record) for record in api.records],
        gate_directory=gate_directory, gate_state=root/"cloudflare-origin-gate.json",
        topology_state=root/"cloudflare-topology-authority.json",
    )
    api.bind(value)
    baseline = module.strip_dynamic(api.ruleset())
    baseline["rules"][0] = module.expected_rule(value, "disabled")
    value.maintenance_ruleset_sha = module.digest(baseline)
    value.maintenance_rule_sha = module.digest(module.expected_rule(value, "disabled"))
    module.initialize_gate(value.gate_directory, value.gate_state)
    return value

def select_extension_controller(value: argparse.Namespace) -> Path:
    release = Path(value.controller_release)
    manifest_path = release / "runtime-bundle/manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["files"] = [
        record
        for record in manifest["files"]
        if record["path"] not in module.PROMOTION_PATH_MODES
    ]
    manifest_path.chmod(0o600)
    manifest_path.write_text(json.dumps(manifest))
    manifest_path.chmod(0o400)

    extension = release / module.PROMOTION_EXTENSION_DIRECTORY
    for directory in (
        extension,
        extension / "host-tools",
        extension / "host-tools/bin",
        extension / "host-tools/systemd",
        extension / "host-tools/tmpfiles",
    ):
        directory.mkdir(mode=0o700)
        directory.chmod(0o700)
    contents = {
        "host-tools/bin/cloudflare-promote.py": value.installed_controller.read_bytes(),
        "host-tools/bin/cloudflare-promote.py.sha256": (
            value.controller_sha256
            + "  /usr/local/libexec/clixor/cloudflare-promote.py\n"
        ).encode("ascii"),
        "host-tools/systemd/clixor-cloudflare-promote.service": b"fixture unit\n",
        "host-tools/tmpfiles/clixor-cloudflare-origin-gate.conf": b"fixture policy\n",
    }
    records = []
    for relative, mode in sorted(module.PROMOTION_PATH_MODES.items()):
        path = extension / relative
        path.write_bytes(contents[relative])
        path.chmod(mode)
        records.append(
            {
                "path": relative,
                "sha256": hashlib.sha256(contents[relative]).hexdigest(),
                "size": len(contents[relative]),
                "mode": mode,
            }
        )
    extension_manifest = {
        "schema": 1,
        "release": release.name,
        "source_sha": value.revision,
        "controller_sha256": value.controller_sha256,
        "files": records,
    }
    extension_manifest_path = extension / "manifest.json"
    extension_manifest_path.write_text(json.dumps(extension_manifest))
    extension_manifest_path.chmod(0o400)
    return extension

class FileAPI(FakeAPI):
    def __init__(self, path: Path, initial: FakeAPI | None = None, kill_at: int | None = None):
        super().__init__()
        self.path, self.kill_at = path, kill_at
        if initial is not None:
            self.configs = copy.deepcopy(initial.configs)
            self.records = copy.deepcopy(initial.records)
            self.rule = copy.deepcopy(initial.rule)
            self.versions = copy.deepcopy(initial.versions)
            self.connectors = copy.deepcopy(initial.connectors)
            self.remote_writes = copy.deepcopy(initial.remote_writes)
            self.save()
        else:
            self.load()

    def bind(self, options):
        self.options = options
        if self.rule is None:
            self.load()

    def load(self):
        doc = json.loads(self.path.read_text())
        self.configs = doc["configs"]
        self.records = doc["records"]
        self.rule = doc["rule"]
        self.versions = doc["versions"]
        self.connectors = doc["connectors"]
        self.remote_writes = doc["remote_writes"]

    def save(self):
        temporary = self.path.with_suffix(".partial")
        temporary.write_text(json.dumps({"configs":self.configs,"records":self.records,
                                         "rule":self.rule,"versions":self.versions,
                                         "connectors":self.connectors,
                                         "remote_writes":self.remote_writes}))
        os.replace(temporary, self.path)

    def request(self, method, path, body=None):
        self.load()
        before = len(self.remote_writes)
        result = super().request(method, path, body)
        if len(self.remote_writes) != before:
            self.save()
            if self.kill_at == len(self.remote_writes):
                os.kill(os.getpid(), signal.SIGKILL)
        return result

def child_promote(remote_path, value, kill_at):
    api = FileAPI(Path(remote_path), kill_at=kill_at); api.bind(value)
    module.verify_local_gate = lambda *_: None
    module.verify_edge_blocked = lambda *_: None
    module.verify_edge_reaches_closed_gate = lambda *_: None
    module.verify_public = lambda *_: None
    module.promote(api, value)

class Tests(unittest.TestCase):
    def setUp(self):
        self.root_uid, self.root_gid = module.ROOT_UID, module.ROOT_GID
        module.ROOT_UID = os.getuid()
        module.ROOT_GID = os.getgid()
        self.parent_patch = mock.patch.object(module, "validate_parent_chain")
        self.parent_patch.start()

    def tearDown(self):
        self.parent_patch.stop()
        module.ROOT_UID, module.ROOT_GID = self.root_uid, self.root_gid

    def run_promote(self, api, value):
        with mock.patch.object(module,"verify_local_gate"), \
             mock.patch.object(module,"verify_edge_blocked"), \
             mock.patch.object(module,"verify_edge_reaches_closed_gate"), \
             mock.patch.object(module,"verify_public"):
            module.promote(api, value)

    def test_success_is_one_way_edge_safe_and_never_has_dual_route_authority(self):
        with tempfile.TemporaryDirectory() as directory:
            api = FakeAPI(); value = options(Path(directory), api)
            self.run_promote(api, value)
            writes = api.remote_writes
            self.assertEqual(
                [(item["method"], item["path"], item["body"]) for item in writes],
                expected_remote_writes(value),
            )
            self.assertEqual(writes[0]["rule"], module.expected_rule(value,"block-all"))
            self.assertEqual(writes[-2]["rule"], module.expected_rule(value,"exception"))
            self.assertEqual(writes[-1]["rule"], module.expected_rule(value,"disabled"))
            self.assertTrue(all(item["rule"]["enabled"] for item in writes[:-1]))
            for item in writes:
                self.assertFalse(item["old_hosts"] and item["candidate_hosts"], item)
            self.assertEqual(api.configs[OLD_TUNNEL], value.old_retired_config)
            self.assertEqual(api.configs[OLD_TUNNEL],
                             {"ingress":[{"service":"http_status:404"}]})
            self.assertEqual(json.loads(value.state.read_text())["phase"], "promoted")
            journal = json.loads(value.state.read_text())
            self.assertEqual(journal["old_live_config_version"], 8)
            self.assertEqual(journal["candidate_live_config_version"], 12)
            self.assertEqual(journal["old_connector_versions"],
                             {value.old_connector_ids[0]:8})
            self.assertEqual(journal["candidate_connector_versions"],
                             {value.candidate_connector_ids[0]:12})
            self.assertEqual(module.read_topology_state(value.topology_state)["state"],
                             "oci-live")
            self.assertEqual(module.marker_state(value.gate_directory), "open")

    def test_only_full_ruleset_get_is_used_and_patch_fixture_is_complete_ruleset(self):
        with tempfile.TemporaryDirectory() as directory:
            api = FakeAPI(); value = options(Path(directory), api)
            self.run_promote(api, value)
            self.assertFalse(any(method == "GET" and "/rules/" in path
                                 for method, path, _ in api.calls))
            self.assertTrue(any(method == "GET" and path == module.ruleset_path(value)
                                for method, path, _ in api.calls))

    def test_individual_patch_response_must_be_a_complete_ruleset(self):
        with tempfile.TemporaryDirectory() as directory:
            api = FakeAPI(); value = options(Path(directory), api)
            request = api.request
            def individual_rule_response(method, path, body=None):
                result = request(method, path, body)
                if method == "PATCH" and "/rules/" in path:
                    return copy.deepcopy(api.rule)
                return result
            api.request = individual_rule_response
            with self.assertRaisesRegex(RuntimeError,"ruleset authority is unknown"):
                self.run_promote(api, value)
            self.assertEqual(len(api.remote_writes), 1)
            self.assertEqual(api.remote_writes[0]["rule"],
                             module.expected_rule(value,"block-all"))

    def test_rule_must_be_unique_first_and_all_unrelated_rule_authority_is_bound(self):
        with tempfile.TemporaryDirectory() as directory:
            api = FakeAPI(); value = options(Path(directory), api)
            original = api.ruleset
            def reordered():
                result = original(); result["rules"] = list(reversed(result["rules"])); return result
            api.ruleset = reordered
            with self.assertRaisesRegex(RuntimeError,"uniquely first"):
                module.promote(api, value)
            self.assertFalse(value.state.exists())
        with tempfile.TemporaryDirectory() as directory:
            api = FakeAPI(); value = options(Path(directory), api)
            original = api.ruleset
            def drifted():
                result = original(); result["rules"][1]["expression"] = "true"; return result
            api.ruleset = drifted
            with self.assertRaisesRegex(RuntimeError,"authority or order"):
                module.promote(api, value)

    def test_candidate_live_config_has_one_exact_rule_per_production_hostname(self):
        config = module.candidate_live_config()
        ingress = config["ingress"]
        self.assertEqual(
            [rule.get("hostname") for rule in ingress],
            [module.CANARY_HOST, *module.PRODUCTION_HOSTS, None],
        )
        self.assertEqual(len(ingress), 4)
        for hostname in module.PRODUCTION_HOSTS:
            self.assertEqual(
                sum(rule.get("hostname") == hostname for rule in ingress),
                1,
            )
        self.assertEqual(ingress[-1], {"service":"http_status:404"})

    def test_archive_path_has_one_fixed_directory_and_one_authority_filename(self):
        with tempfile.TemporaryDirectory() as directory:
            api = FakeAPI(); value = options(Path(directory), api)
            expected_name = f"{value.revision}-{module.digest(module.authority(value))}.json"
            path = module.archive_path(value)
            self.assertEqual(
                path.parent,
                value.state.parent / "cloudflare-promotion-archive",
            )
            self.assertEqual(path.name, expected_name)
            self.assertEqual(path.parts.count(expected_name), 1)
            next_window = argparse.Namespace(**vars(value))
            next_window.change_window = "FROZEN-UNIT-2"
            self.assertNotEqual(module.archive_path(next_window), path)

    def test_shared_or_ambiguous_old_routes_fail_without_remote_writes(self):
        for extra in (
            {"hostname":module.PRODUCTION_HOSTS[0],"service":"http://duplicate"},
            {"hostname":"*.atlanteanz.com","service":"http://ambiguous"},
            {"hostname":"tradingbot.atlanteanz.com","service":"http://tradingbot:9000"},
        ):
            with self.subTest(extra=extra), tempfile.TemporaryDirectory() as directory:
                api = FakeAPI(); api.configs[OLD_TUNNEL]["ingress"].insert(-1, extra)
                root = Path(directory)
                with self.assertRaisesRegex(RuntimeError,"Clixor-only|ambiguous"):
                    options(root, api)
                self.assertEqual(api.remote_writes, [])

    def test_live_shared_tunnel_is_a_prejournal_hard_prerequisite(self):
        with tempfile.TemporaryDirectory() as directory:
            api = FakeAPI(); value = options(Path(directory), api)
            api.configs[OLD_TUNNEL]["ingress"].insert(
                -1, {"hostname":"tradingbot.atlanteanz.com",
                     "service":"http://tradingbot:9000"})
            with self.assertRaisesRegex(RuntimeError,"differs from the reviewed"):
                module.promote(api, value)
            self.assertEqual(api.remote_writes, [])
            self.assertFalse(value.state.exists())
            self.assertFalse(value.topology_state.exists())
            self.assertEqual(module.marker_state(value.gate_directory), "closed")

    def test_reviewed_shared_tunnel_rejection_changes_no_gate_or_state(self):
        with tempfile.TemporaryDirectory() as directory:
            api = FakeAPI(); value = options(Path(directory), api)
            value.old_config["ingress"].insert(
                -1,
                {
                    "hostname": "tradingbot.atlanteanz.com",
                    "service": "http://tradingbot:9000",
                },
            )
            gate_before = value.gate_state.read_bytes()
            with self.assertRaisesRegex(RuntimeError, "Clixor-only"):
                module.promote(api, value)
            self.assertEqual(api.remote_writes, [])
            self.assertFalse(value.state.exists())
            self.assertFalse(value.topology_state.exists())
            self.assertEqual(value.gate_state.read_bytes(), gate_before)
            self.assertEqual(module.marker_state(value.gate_directory), "closed")

    def test_connector_config_version_must_converge_for_every_reviewed_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            api = FakeAPI(); value = options(Path(directory), api)
            client = value.candidate_connector_ids[0]
            api.connectors[NEW_TUNNEL][client] = value.candidate_config_version - 1
            with self.assertRaisesRegex(RuntimeError,"did not converge"):
                module.connector_version_map(
                    api, value.account, NEW_TUNNEL,
                    value.candidate_connector_ids, value.candidate_config_version,
                    timeout=0,
                )
            api.connectors[NEW_TUNNEL] = {
                "55555555-5555-5555-5555-555555555555":value.candidate_config_version
            }
            with self.assertRaisesRegex(RuntimeError,"did not converge"):
                module.connector_version_map(
                    api, value.account, NEW_TUNNEL,
                    value.candidate_connector_ids, value.candidate_config_version,
                    timeout=0,
                )

    def test_connector_poll_waits_for_exact_outer_config_version(self):
        with tempfile.TemporaryDirectory() as directory:
            api = FakeAPI(); value = options(Path(directory), api)
            client = value.candidate_connector_ids[0]
            original = api.request; reads = 0
            def lag(method, path, body=None):
                nonlocal reads
                result = original(method, path, body)
                if path.endswith("/connections"):
                    reads += 1
                    if reads == 1:
                        result[0]["config_version"] -= 1
                return result
            api.request = lag
            with mock.patch.object(module.time,"sleep"):
                self.assertEqual(
                    module.connector_version_map(
                        api, value.account, NEW_TUNNEL, [client],
                        value.candidate_config_version, timeout=1),
                    {client:value.candidate_config_version},
                )
            self.assertEqual(reads, 2)

    def test_outer_config_version_drift_fails_before_journal_or_write(self):
        with tempfile.TemporaryDirectory() as directory:
            api = FakeAPI(); value = options(Path(directory), api)
            api.versions[NEW_TUNNEL] += 1
            api.connectors[NEW_TUNNEL] = {
                client:api.versions[NEW_TUNNEL]
                for client in value.candidate_connector_ids
            }
            with self.assertRaisesRegex(RuntimeError,"reviewed configuration"):
                module.promote(api, value)
            self.assertEqual(api.remote_writes, [])
            self.assertFalse(value.state.exists())
            self.assertFalse(value.topology_state.exists())

    def test_partial_dns_batch_is_reapplied_forward_to_exact_candidate(self):
        with tempfile.TemporaryDirectory() as directory:
            api = FakeAPI(); value = options(Path(directory), api)
            api.records[0]["content"] = value.candidate_target
            module.switch_dns(api, value.zone, value.dns,
                              value.old_target, value.candidate_target)
            self.assertEqual({record["content"] for record in api.records},
                             {value.candidate_target})

    def test_controller_must_match_current_release_manifest_and_request_sha(self):
        with tempfile.TemporaryDirectory() as directory:
            api = FakeAPI(); value = options(Path(directory), api)
            other = value.current_release_link.parent / f"oci-{'b'*12}-other"
            other.mkdir(mode=0o700)
            value.current_release_link.unlink(); value.current_release_link.symlink_to(other)
            with self.assertRaisesRegex(RuntimeError,"current committed release"):
                module.promote(api, value)
            self.assertEqual(api.remote_writes, [])
            self.assertFalse(value.state.exists())

    def test_extended_current_release_controller_validates_and_prepares_read_only(self):
        with tempfile.TemporaryDirectory() as directory:
            api = FakeAPI(); value = options(Path(directory), api)
            extension = select_extension_controller(value)
            module.validate_controller_binding(value)
            state = module.prepare(api, value)
            self.assertEqual(state["phase"], "prepared")
            self.assertEqual(api.remote_writes, [])
            self.assertTrue(value.state.is_file())
            self.assertEqual(
                module.read_topology_state(value.topology_state)["state"],
                "pre-cutover-old",
            )
            self.assertEqual(
                module.file_sha256(
                    extension / "host-tools/bin/cloudflare-promote.py"
                ),
                value.controller_sha256,
            )

    def test_extension_manifest_extra_record_is_rejected_before_any_write(self):
        with tempfile.TemporaryDirectory() as directory:
            api = FakeAPI(); value = options(Path(directory), api)
            extension = select_extension_controller(value)
            manifest_path = extension / "manifest.json"
            manifest = json.loads(manifest_path.read_text())
            manifest["files"].append(
                {
                    "path": "host-tools/bin/unbound-controller",
                    "sha256": "e" * 64,
                    "size": 1,
                    "mode": 0o400,
                }
            )
            manifest_path.chmod(0o600)
            manifest_path.write_text(json.dumps(manifest))
            manifest_path.chmod(0o400)
            with self.assertRaisesRegex(RuntimeError, "extension file inventory"):
                module.promote(api, value)
            self.assertEqual(api.remote_writes, [])
            self.assertFalse(value.state.exists())
            self.assertFalse(value.topology_state.exists())

    def test_exact_dns_identity_proxied_and_ttl_are_required(self):
        for key, replacement in (("id","f"*32),("proxied",False),("ttl",300)):
            with self.subTest(key=key), tempfile.TemporaryDirectory() as directory:
                api = FakeAPI(); value = options(Path(directory), api)
                api.records[0][key] = replacement
                with self.assertRaisesRegex(RuntimeError,"identity or value drift"):
                    module.promote(api, value)
                self.assertEqual(api.remote_writes, [])

    def test_real_sigkill_after_every_remote_write_resumes_forward_only(self):
        if "fork" not in multiprocessing.get_all_start_methods():
            self.skipTest("fork is required for real SIGKILL recovery test")
        for kill_at in range(1, 7):
            with self.subTest(kill_at=kill_at), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); initial = FakeAPI(); value = options(root, initial)
                remote = root / "remote.json"
                FileAPI(remote, initial=initial)
                process = multiprocessing.get_context("fork").Process(
                    target=child_promote, args=(str(remote), value, kill_at))
                process.start(); process.join(20)
                self.assertEqual(process.exitcode, -signal.SIGKILL)
                api = FileAPI(remote); api.bind(value)
                self.run_promote(api, value); api.load()
                self.assertEqual(len(api.remote_writes), 6)
                self.assertEqual(
                    [(item["method"], item["path"], item["body"])
                     for item in api.remote_writes],
                    expected_remote_writes(value),
                )
                journal = json.loads(value.state.read_text())
                self.assertEqual(journal["phase"], "promoted")
                for entry in journal["write_history"]:
                    if entry.startswith("before:"):
                        self.assertIn("after:" + entry.split(":", 1)[1],
                                      journal["write_history"])
                for item in api.remote_writes:
                    self.assertFalse(item["old_hosts"] and item["candidate_hosts"])

    def test_crash_after_unfreeze_checkpoint_never_closes_gate_or_reenables_waf(self):
        with tempfile.TemporaryDirectory() as directory:
            api = FakeAPI(); value = options(Path(directory), api)
            real_checkpoint = module.checkpoint
            def die_after_checkpoint(path, state, phase, operation=None):
                real_checkpoint(path, state, phase, operation)
                if phase == "after-waf-disable":
                    raise SystemExit(137)
            with mock.patch.object(module,"checkpoint",side_effect=die_after_checkpoint):
                with self.assertRaises(SystemExit):
                    self.run_promote(api, value)
            self.assertEqual(json.loads(value.state.read_text())["phase"], "after-waf-disable")
            self.assertEqual(module.marker_state(value.gate_directory), "open")
            before = len(api.remote_writes)
            self.run_promote(api, value)
            self.assertEqual(len(api.remote_writes), before)
            self.assertEqual(module.marker_state(value.gate_directory), "open")
            self.assertEqual(json.loads(value.state.read_text())["phase"], "promoted")

    def test_concurrent_controller_lock_is_nonblocking_and_exclusive(self):
        if "fork" not in multiprocessing.get_all_start_methods():
            self.skipTest("fork is required for lock test")
        with tempfile.TemporaryDirectory() as directory:
            lock_path = Path(directory) / "state.lock"
            first = module.acquire_lock(lock_path)
            read_end, write_end = multiprocessing.Pipe(duplex=False)
            def contender(path, sender):
                try:
                    descriptor = module.acquire_lock(Path(path)); os.close(descriptor); sender.send("acquired")
                except BlockingIOError:
                    sender.send("blocked")
            process = multiprocessing.get_context("fork").Process(
                target=contender, args=(str(lock_path), write_end))
            process.start(); self.assertEqual(read_end.recv(), "blocked"); process.join(5)
            os.close(first)
            process = multiprocessing.get_context("fork").Process(
                target=contender, args=(str(lock_path), write_end))
            process.start(); self.assertEqual(read_end.recv(), "acquired"); process.join(5)

    def test_controller_uses_shared_deploy_lock_before_private_state_lock(self):
        if "fork" not in multiprocessing.get_all_start_methods():
            self.skipTest("fork is required for lock test")
        with tempfile.TemporaryDirectory() as directory:
            deploy = Path(directory) / "deploy.lock"
            state = Path(directory) / "promotion.json"
            held = module.acquire_lock(deploy)
            read_end, write_end = multiprocessing.Pipe(duplex=False)
            def contender(deploy_path, state_path, sender):
                try:
                    first, second = module.acquire_controller_locks(
                        Path(deploy_path), Path(state_path))
                    os.close(second); os.close(first); sender.send("acquired")
                except BlockingIOError:
                    sender.send("blocked")
            process = multiprocessing.get_context("fork").Process(
                target=contender, args=(str(deploy), str(state), write_end))
            process.start(); self.assertEqual(read_end.recv(), "blocked"); process.join(5)
            self.assertFalse(Path(str(state) + ".lock").exists())
            os.close(held)

    def test_gate_journal_and_marker_are_fsynced_and_archive_is_idempotent(self):
        with tempfile.TemporaryDirectory() as directory:
            api = FakeAPI(); value = options(Path(directory), api); calls = []
            real = os.fsync
            with mock.patch.object(module.os,"fsync",side_effect=lambda fd:(calls.append(fd),real(fd))[1]):
                self.run_promote(api, value)
            self.assertGreaterEqual(len(calls), 20)
            with mock.patch.object(module,"verify_local_gate"), mock.patch.object(module,"verify_public"):
                module.archive_terminal(api, value)
                module.archive_terminal(api, value)
            self.assertFalse(value.state.exists())
            archives = list((value.state.parent/"cloudflare-promotion-archive").glob("*.json"))
            self.assertEqual(len(archives), 1)
            self.assertEqual(json.loads(archives[0].read_text())["authority"], module.authority(value))

    def test_archive_collision_never_overwrites_or_removes_active_journal(self):
        with tempfile.TemporaryDirectory() as directory:
            api = FakeAPI(); value = options(Path(directory), api); self.run_promote(api, value)
            path = module.archive_path(value)
            path.parent.mkdir(mode=0o700)
            path.write_bytes(b"{}\n"); path.chmod(0o400)
            with mock.patch.object(module,"verify_local_gate"), \
                 mock.patch.object(module,"verify_public"):
                with self.assertRaisesRegex(RuntimeError,"archive collision"):
                    module.archive_terminal(api, value)
            self.assertEqual(path.read_bytes(), b"{}\n")
            self.assertTrue(value.state.exists())

    def test_terminal_rerun_is_read_only(self):
        with tempfile.TemporaryDirectory() as directory:
            api = FakeAPI(); value = options(Path(directory), api); self.run_promote(api, value)
            before = len(api.remote_writes); self.run_promote(api, value)
            self.assertEqual(len(api.remote_writes), before)

    def test_disabled_fence_before_unfreeze_closes_open_gate_and_stops(self):
        with tempfile.TemporaryDirectory() as directory:
            api = FakeAPI(); value = options(Path(directory), api)
            module.write_state(value.state, {"schema":4,"direction":"forward-only",
                               "phase":"after-dns-candidate","authority":module.authority(value),
                               "write_history":[]})
            (value.gate_directory/module.GATE_MARKER).touch(mode=0o400)
            with mock.patch.object(module,"verify_local_gate"):
                with self.assertRaisesRegex(RuntimeError,"disabled before final unfreeze"):
                    module.forward(api, value, module.read_state(value.state))
            self.assertEqual(module.marker_state(value.gate_directory), "closed")

    def test_crash_after_gate_open_resumes_forward_without_reclosing_it(self):
        with tempfile.TemporaryDirectory() as directory:
            api = FakeAPI(); value = options(Path(directory), api)
            api.configs[OLD_TUNNEL] = copy.deepcopy(value.old_retired_config)
            api.configs[NEW_TUNNEL] = copy.deepcopy(value.candidate_live_config)
            api.versions[OLD_TUNNEL] += 1
            api.versions[NEW_TUNNEL] += 1
            api.connectors[OLD_TUNNEL] = {
                client:api.versions[OLD_TUNNEL] for client in value.old_connector_ids
            }
            api.connectors[NEW_TUNNEL] = {
                client:api.versions[NEW_TUNNEL] for client in value.candidate_connector_ids
            }
            for record in api.records:
                record["content"] = value.candidate_target
            api.rule = dict(module.expected_rule(value,"exception"), version="3",
                            last_updated="2026-08-30T00:00:03Z")
            binding = module.topology_binding(value)
            module.write_state(value.topology_state,
                               {"schema":1,"state":"pre-cutover-old","binding":binding,
                                "binding_sha":module.digest(binding)})
            module.write_state(value.state, {"schema":4,"direction":"forward-only",
                               "phase":"before-origin-gate-open","authority":module.authority(value),
                               "write_history":["before:origin-gate-open"],
                               "old_live_config_version":api.versions[OLD_TUNNEL],
                               "candidate_live_config_version":api.versions[NEW_TUNNEL],
                               "old_connector_versions":copy.deepcopy(api.connectors[OLD_TUNNEL]),
                               "candidate_connector_versions":copy.deepcopy(api.connectors[NEW_TUNNEL])})
            (value.gate_directory/module.GATE_MARKER).touch(mode=0o400)
            self.run_promote(api, value)
            self.assertEqual(module.marker_state(value.gate_directory), "open")
            self.assertEqual(len(api.remote_writes), 1)
            self.assertEqual(api.remote_writes[0]["rule"], module.expected_rule(value,"disabled"))
            self.assertEqual(json.loads(value.state.read_text())["phase"], "promoted")

    def test_fd_reads_reject_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            token = Path(directory)/"token"; token.write_text("x"*30); token.chmod(0o400)
            link = Path(directory)/"link"; link.symlink_to(token)
            with self.assertRaises(OSError):
                module.read_token(link, os.getuid())

    def test_request_and_journal_reject_duplicate_or_ambiguous_json(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            request = root / "request.json"
            token = root / "token"
            state = root / "state.json"
            token.write_text("x" * 30); token.chmod(0o400)
            request.write_bytes(b'{"mode":"promote","mode":"archive"}')
            request.chmod(0o400)
            with self.assertRaisesRegex(RuntimeError, "duplicate field: mode"):
                module.parse_request(
                    request, token, state, root / "gate", root / "gate-state",
                    root / "topology", root / "current", root / "controller",
                )
            for raw in (
                b'{"schema":4,"schema":3}',
                b'\xff{"schema":4}',
                b'\xef\xbb\xbf{"schema":4}',
            ):
                with self.subTest(raw=raw):
                    if state.exists():
                        state.chmod(0o600)
                    state.write_bytes(raw); state.chmod(0o400)
                    with self.assertRaisesRegex(RuntimeError, "authority JSON"):
                        module.read_state(state, os.getuid())

    def test_public_validation_never_accepts_or_follows_redirects(self):
        headers = {"server":"cloudflare","cf-ray":"unit"}
        with mock.patch.object(module,"public_request",return_value=(302,headers,b"")) as request, \
             mock.patch.object(module.time,"sleep"):
            with self.assertRaisesRegex(RuntimeError,"without redirects"):
                module.verify_public("a"*40)
        self.assertEqual(request.call_count, 24)
        self.assertIsNone(module.NoRedirect().redirect_request(None,None,302,"",{},"https://evil"))

    def test_deploy_uses_durable_topology_state_for_pre_and_post_cutover_checks(self):
        deploy = (ROOT / "deploy.sh").read_text()
        unit = (ROOT / "clixor-cloudflare-promote.service").read_text()
        bootstrap = (ROOT / "bootstrap.sh").read_text()
        self.assertLess(deploy.index('flock -n 9'), deploy.index('topology-mode'))
        self.assertLess(deploy.index('topology-mode'), deploy.index('rollback_needed=1'))
        self.assertIn('uninitialized|pre-cutover-old)', deploy)
        self.assertIn('verify_production_not_candidate "${source_sha}"', deploy)
        self.assertIn('oci-live)', deploy)
        self.assertIn('verify_production_candidate "${source_sha}"', deploy)
        self.assertIn('https://clustr-api.atlanteanz.com/health/ready', deploy)
        self.assertIn('ReadWritePaths=/var/lib/clixor /srv/clixor/runtime/deploy.lock', unit)
        self.assertIn('CLIXOR_DEFER_HOST_TOOL_ACTIVATION=true', deploy)
        deferred = bootstrap.index('if [ "${defer_host_tool_activation}" = "false" ]; then',
                                   bootstrap.index('install -d -m 0755 -o 0 -g 0 /usr/local/libexec/clixor'))
        install_promoter = bootstrap.index('install -m 0555 -o 0 -g 0 "${script_root}/cloudflare-promote.py"')
        self.assertLess(deferred, install_promoter)

    def test_runtime_bundle_and_watchdog_restore_controller_unit_and_gate_policy(self):
        bundle = (ROOT / "runtime_bundle.py").read_text()
        reconciler = (ROOT / "runtime-reconciler.py").read_text()
        for path in (
            'host-tools/bin/cloudflare-promote.py',
            'host-tools/bin/cloudflare-promote.py.sha256',
            'host-tools/systemd/clixor-cloudflare-promote.service',
            'host-tools/tmpfiles/clixor-cloudflare-origin-gate.conf',
        ):
            self.assertIn(path, bundle)
        self.assertIn('HOST_TOOL_ROOT / "cloudflare-promote.py"', reconciler)
        self.assertIn('SYSTEMD_ROOT / "clixor-cloudflare-promote.service"', reconciler)
        self.assertIn('TMPFILES_ROOT / "clixor-cloudflare-origin-gate.conf"', reconciler)

    def test_deploy_arms_controller_rollback_before_publish_and_reloads_units(self):
        deploy = (ROOT / "deploy.sh").read_text()
        activation = deploy[deploy.index("activate_host_tooling() {"):
                            deploy.index("restore_host_tooling() {")]
        restore = deploy[deploy.index("restore_host_tooling() {"):
                         deploy.index("ensure_gateway_for_probe() {")]
        self.assertLess(activation.index("host_tools_activated=true"),
                        activation.index("cloudflare-promote.py\" 0555"))
        for artifact in (
            "cloudflare-promote.py",
            "cloudflare-promote.py.sha256",
            "clixor-cloudflare-promote.service",
            "clixor-cloudflare-origin-gate.conf",
        ):
            self.assertIn(artifact, restore)
        self.assertIn("systemctl daemon-reload || restore_status=1", restore)
        rollback_start = deploy.index(
            'if [ "${status}" -ne 0 ] && [ "${rollback_needed}" -eq 1 ]')
        rollback_branch = deploy[rollback_start:
                                 deploy.index('if [ "${first_deploy}" = "false" ]',
                                              rollback_start)]
        self.assertIn("restore_host_tooling", rollback_branch)

if __name__ == "__main__":
    unittest.main()
