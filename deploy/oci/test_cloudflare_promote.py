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
        {"hostname":"tradingbot.atlanteanz.com","service":"http://tradingbot:9000"},
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
            if method == "GET":
                return {"config":copy.deepcopy(self.configs[tunnel])}
            self.configs[tunnel] = copy.deepcopy(body["config"])
            self.record_write(method, path, body)
            return {"config":copy.deepcopy(self.configs[tunnel])}
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
    value = argparse.Namespace(
        change_window="FROZEN-UNIT-1", account="a"*32, zone="b"*32,
        old_tunnel=OLD_TUNNEL, candidate_tunnel=NEW_TUNNEL,
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
    )
    api.bind(value)
    baseline = module.strip_dynamic(api.ruleset())
    baseline["rules"][0] = module.expected_rule(value, "disabled")
    value.maintenance_ruleset_sha = module.digest(baseline)
    value.maintenance_rule_sha = module.digest(module.expected_rule(value, "disabled"))
    module.initialize_gate(value.gate_directory, value.gate_state)
    return value

class FileAPI(FakeAPI):
    def __init__(self, path: Path, initial: FakeAPI | None = None, kill_at: int | None = None):
        super().__init__()
        self.path, self.kill_at = path, kill_at
        if initial is not None:
            self.configs = copy.deepcopy(initial.configs)
            self.records = copy.deepcopy(initial.records)
            self.rule = copy.deepcopy(initial.rule)
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
        self.remote_writes = doc["remote_writes"]

    def save(self):
        temporary = self.path.with_suffix(".partial")
        temporary.write_text(json.dumps({"configs":self.configs,"records":self.records,
                                         "rule":self.rule,"remote_writes":self.remote_writes}))
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
        self.root_uid = module.ROOT_UID
        module.ROOT_UID = os.getuid()
        self.parent_patch = mock.patch.object(module, "validate_parent_chain")
        self.parent_patch.start()

    def tearDown(self):
        self.parent_patch.stop()
        module.ROOT_UID = self.root_uid

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
            self.assertEqual(api.configs[OLD_TUNNEL]["ingress"][0]["hostname"],
                             "tradingbot.atlanteanz.com")
            self.assertEqual(json.loads(value.state.read_text())["phase"], "promoted")
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

    def test_unknown_and_ambiguous_old_routes_fail_without_remote_writes(self):
        for extra in (
            {"hostname":module.PRODUCTION_HOSTS[0],"service":"http://duplicate"},
            {"hostname":"*.atlanteanz.com","service":"http://ambiguous"},
        ):
            with self.subTest(extra=extra), tempfile.TemporaryDirectory() as directory:
                api = FakeAPI(); api.configs[OLD_TUNNEL]["ingress"].insert(-1, extra)
                root = Path(directory)
                with self.assertRaisesRegex(RuntimeError,"ambiguous"):
                    options(root, api)
                self.assertEqual(api.remote_writes, [])

    def test_exact_dns_identity_proxied_and_ttl_are_required(self):
        for key, replacement in (("id","f"*32),("proxied",False),("ttl",300)):
            with self.subTest(key=key), tempfile.TemporaryDirectory() as directory:
                api = FakeAPI(); value = options(Path(directory), api)
                api.records[0][key] = replacement
                with self.assertRaisesRegex(RuntimeError,"identity or value drift"):
                    module.promote(api, value)
                self.assertEqual(api.remote_writes, [])

    def test_resume_after_every_remote_write_has_exactly_once_write_history(self):
        for kill_at in range(1, 7):
            with self.subTest(kill_at=kill_at), tempfile.TemporaryDirectory() as directory:
                api = FakeAPI(); value = options(Path(directory), api)
                def die(number, _snapshot):
                    if number == kill_at:
                        raise SystemExit(137)
                api.after_write = die
                with self.assertRaises(SystemExit):
                    self.run_promote(api, value)
                api.after_write = None
                self.run_promote(api, value)
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

    def test_real_sigkill_after_unfreeze_recovers_without_reenabling_fence(self):
        if "fork" not in multiprocessing.get_all_start_methods():
            self.skipTest("fork is required for real SIGKILL recovery test")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); initial = FakeAPI(); value = options(root, initial)
            remote = root / "remote.json"
            FileAPI(remote, initial=initial)
            process = multiprocessing.get_context("fork").Process(
                target=child_promote, args=(str(remote), value, 6))
            process.start(); process.join(20)
            self.assertEqual(process.exitcode, -signal.SIGKILL)
            self.assertEqual(json.loads(value.state.read_text())["phase"], "before-waf-disable")
            recovered = FileAPI(remote); recovered.bind(value)
            self.run_promote(recovered, value)
            recovered.load()
            self.assertEqual(len(recovered.remote_writes), 6)
            self.assertEqual(
                [(item["method"], item["path"], item["body"])
                 for item in recovered.remote_writes],
                expected_remote_writes(value),
            )
            self.assertEqual(recovered.remote_writes[-1]["rule"],
                             module.expected_rule(value,"disabled"))
            self.assertEqual(json.loads(value.state.read_text())["phase"], "promoted")

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
            module.write_state(value.state, {"schema":3,"direction":"forward-only",
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
            for record in api.records:
                record["content"] = value.candidate_target
            api.rule = dict(module.expected_rule(value,"exception"), version="3",
                            last_updated="2026-08-30T00:00:03Z")
            module.write_state(value.state, {"schema":3,"direction":"forward-only",
                               "phase":"before-origin-gate-open","authority":module.authority(value),
                               "write_history":["before:origin-gate-open"]})
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

    def test_public_validation_never_accepts_or_follows_redirects(self):
        headers = {"server":"cloudflare","cf-ray":"unit"}
        with mock.patch.object(module,"public_request",return_value=(302,headers,b"")) as request, \
             mock.patch.object(module.time,"sleep"):
            with self.assertRaisesRegex(RuntimeError,"without redirects"):
                module.verify_public("a"*40)
        self.assertEqual(request.call_count, 24)
        self.assertIsNone(module.NoRedirect().redirect_request(None,None,302,"",{},"https://evil"))

if __name__ == "__main__":
    unittest.main()
