from __future__ import annotations
import argparse,hashlib,importlib.util,json,os,tempfile,unittest
from pathlib import Path
from unittest import mock
ROOT=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location("cf",ROOT/"cloudflare-promote.py");module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)

def old_config():return {"ingress":[{"hostname":h,"service":module.ORIGIN} for h in module.PRODUCTION_HOSTS]+[{"service":"http_status:404"}]}
def new_config():return {"ingress":[{"hostname":module.CANARY_HOST,"service":module.ORIGIN},{"service":"http_status:404"}]}
class FakeAPI:
    def __init__(self):
        self.configs={"old":old_config(),"new":new_config()};self.records=[{"id":str(i+1),"name":h,"type":"CNAME","content":"old.cfargotunnel.com","proxied":True,"ttl":1} for i,h in enumerate(module.PRODUCTION_HOSTS)];self.options=None;self.rule=None;self.calls=[];self.after=None
    def bind(self,a):self.options=a;self.rule=module.expected_rule(a,False)
    def request(self,method,path,body=None):
        self.calls.append((method,path,body))
        if "/cfd_tunnel/" in path:
            t=path.split("/cfd_tunnel/",1)[1].split("/",1)[0]
            if method=="GET":return {"config":json.loads(module.canonical(self.configs[t]))}
            self.configs[t]=json.loads(module.canonical(body["config"]));self._after(method,path);return {}
        if "/rulesets/" in path:
            if "/rules/" not in path:return {"id":self.options.maintenance_ruleset,"kind":"zone","phase":"http_request_firewall_custom","rules":[dict(self.rule),{"id":"later-rule"}]}
            if method=="GET":return dict(self.rule)
            self.rule=dict(body,id=self.options.maintenance_rule);self._after(method,path);return dict(self.rule)
        if method=="GET":
            name=path.split("name=",1)[1];return [dict(r) for r in self.records if r["name"]==name]
        if path.endswith("/batch"):
            for p in body["patches"]:
                for r in self.records:
                    if r["id"]==p["id"]:r.update(p)
            self._after(method,path);return {}
        raise AssertionError((method,path))
    def _after(self,method,path):
        if self.after:self.after(method,path)

def options(root,api):
    ev=root/"evidence";raw=f"revision={'a'*40}\nstage=canary\nsmoke=passed prefix=x checks=5 cleanup=passed\n".encode();ev.write_bytes(raw);ev.chmod(0o400)
    a=argparse.Namespace(change_window="FROZEN-1",account="a"*32,zone="b"*32,old_tunnel="old",candidate_tunnel="new",old_target="old.cfargotunnel.com",candidate_target="new.cfargotunnel.com",revision="a"*40,old_revision="b"*40,old_config_sha=module.digest(api.configs["old"]),candidate_config_sha=module.digest(api.configs["new"]),state=root/"state",evidence=ev,evidence_sha=hashlib.sha256(raw).hexdigest(),maintenance_ruleset="c"*32,maintenance_rule="d"*32,probe_source_ip="203.0.113.9",dns=[module.dns_tuple(r) for r in api.records])
    a.maintenance_ruleset_sha=module.digest({"id":a.maintenance_ruleset,"kind":"zone","phase":"http_request_firewall_custom","rule_order":[a.maintenance_rule,"later-rule"]})
    a.maintenance_rule_sha=module.digest(module.expected_rule(a,False));api.bind(a);return a

class Tests(unittest.TestCase):
    def setUp(self):
        self.evidence_patch=mock.patch.object(module,"evidence_digest",side_effect=lambda path,revision:hashlib.sha256(path.read_bytes()).hexdigest())
        self.evidence_patch.start()
    def tearDown(self):self.evidence_patch.stop()
    def run_promote(self,api,a):
        with mock.patch.object(module,"verify_public"):module.promote(api,a)
    def test_success_fence_is_first_and_last_external_transition(self):
        with tempfile.TemporaryDirectory() as d:
            api=FakeAPI();a=options(Path(d),api);self.run_promote(api,a)
            writes=[x for x in api.calls if x[0] in ("PATCH","PUT","POST")]
            self.assertIn("/rulesets/",writes[0][1]);self.assertTrue(writes[0][2]["enabled"])
            self.assertIn("/rulesets/",writes[-1][1]);self.assertFalse(writes[-1][2]["enabled"])
            self.assertEqual({r["content"] for r in api.records},{a.candidate_target});self.assertEqual(json.loads(a.state.read_text())["phase"],"promoted")
    def test_unknown_tunnel_drift_retains_independent_fence(self):
        with tempfile.TemporaryDirectory() as d:
            api=FakeAPI();a=options(Path(d),api);api.configs["old"]["ingress"].insert(0,{"hostname":"unknown","service":"http://bad"})
            # Digest matches initial unknown only to reach strict allowlist, which rejects before fence.
            a.old_config_sha=module.digest(api.configs["old"])
            with self.assertRaisesRegex(RuntimeError,"allowlist"):module.promote(api,a)
        with tempfile.TemporaryDirectory() as d:
            # Drift after preparation is fenced before it is observed.
            api=FakeAPI();a=options(Path(d),api);original=module.write_state
            def drift(path,state):original(path,state);api.configs["old"]["ingress"].insert(0,{"hostname":"unknown","service":"http://bad"})
            with mock.patch.object(module,"write_state",side_effect=drift),self.assertRaisesRegex(RuntimeError,"drift"):module.promote(api,a)
            self.assertTrue(api.rule["enabled"])
    def test_unknown_fence_stops_without_claiming_fenced(self):
        with tempfile.TemporaryDirectory() as d:
            api=FakeAPI();a=options(Path(d),api);api.rule["expression"]="true"
            with self.assertRaisesRegex(RuntimeError,"fence authority"):module.promote(api,a)
            self.assertFalse(api.rule["enabled"]);self.assertFalse(a.state.exists())
    def test_fence_must_be_first_in_exact_ordered_ruleset(self):
        with tempfile.TemporaryDirectory() as d:
            api=FakeAPI();a=options(Path(d),api);original=api.request
            def reordered(method,path,body=None):
                value=original(method,path,body)
                if method=="GET" and path==module.ruleset_path(a):value["rules"]=[{"id":"skip-before"},dict(api.rule)]
                return value
            api.request=reordered
            with self.assertRaisesRegex(RuntimeError,"ruleset authority"):module.promote(api,a)
            self.assertFalse(api.rule["enabled"])
    def test_dns_delete_recreate_same_name_is_detected(self):
        with tempfile.TemporaryDirectory() as d:
            api=FakeAPI();a=options(Path(d),api);api.records[0]["id"]="replacement"
            with self.assertRaisesRegex(RuntimeError,"identity drift"):module.promote(api,a)
    def test_all_authority_mismatches_rejected_on_resume(self):
        for key in module.AUTH_KEYS:
            with self.subTest(key=key),tempfile.TemporaryDirectory() as d:
                api=FakeAPI();a=options(Path(d),api);s={"authority":module.authority(a)};s["authority"][key]="bad" if not isinstance(s["authority"][key],list) else []
                module.write_state(a.state,s)
                with mock.patch.object(module,"read_state",lambda p:json.loads(p.read_text())),self.assertRaisesRegex(RuntimeError,"authority mismatch"):module.promote(api,a)
    def test_death_at_every_forward_mutation_resumes(self):
        phases=("after-maintenance-enable","after-dns-candidate","after-candidate-live","after-maintenance-disable")
        for phase in phases:
            with self.subTest(phase=phase),tempfile.TemporaryDirectory() as d:
                api=FakeAPI();a=options(Path(d),api);real=module.checkpoint
                def kill(path,state,p,direction=None):
                    real(path,state,p,direction)
                    if p==phase:raise SystemExit(137)
                with mock.patch.object(module,"verify_public"),mock.patch.object(module,"checkpoint",side_effect=kill),self.assertRaises(SystemExit):module.promote(api,a)
                with mock.patch.object(module,"verify_public"),mock.patch.object(module,"read_state",lambda p:json.loads(p.read_text())):module.promote(api,a)
                self.assertEqual(json.loads(a.state.read_text())["phase"],"promoted")
    def test_death_after_each_forward_remote_write_before_after_checkpoint(self):
        for kill_at in range(1,5):
            with self.subTest(write=kill_at),tempfile.TemporaryDirectory() as d:
                api=FakeAPI();a=options(Path(d),api);seen=0
                def die(method,path):
                    nonlocal seen
                    seen+=1
                    if seen==kill_at:raise SystemExit(137)
                api.after=die
                with mock.patch.object(module,"verify_public"),self.assertRaises(SystemExit):module.promote(api,a)
                api.after=None
                with mock.patch.object(module,"verify_public"),mock.patch.object(module,"read_state",lambda p:json.loads(p.read_text())):module.promote(api,a)
                self.assertEqual(json.loads(a.state.read_text())["phase"],"promoted")
    def test_rollback_intent_survives_death_and_never_goes_forward(self):
        phases=("rollback-after-maintenance-enable","rollback-after-candidate-canary","rollback-after-dns-old","rollback-after-maintenance-disable")
        for phase in phases:
            with self.subTest(phase=phase),tempfile.TemporaryDirectory() as d:
                api=FakeAPI();a=options(Path(d),api);self.run_promote(api,a);real=module.checkpoint
                def kill(path,state,p,direction=None):
                    real(path,state,p,direction)
                    if p==phase:raise SystemExit(137)
                with mock.patch.object(module,"verify_public"),mock.patch.object(module,"read_state",lambda p:json.loads(p.read_text())),mock.patch.object(module,"checkpoint",side_effect=kill),self.assertRaises(SystemExit):module.rollback(api,a)
                with mock.patch.object(module,"verify_public"),mock.patch.object(module,"read_state",lambda p:json.loads(p.read_text())):module.promote(api,a)
                self.assertEqual(json.loads(a.state.read_text())["phase"],"rolled-back");self.assertEqual({r["content"] for r in api.records},{a.old_target})
    def test_death_after_each_rollback_remote_write_before_after_checkpoint(self):
        for kill_at in range(1,5):
            with self.subTest(write=kill_at),tempfile.TemporaryDirectory() as d:
                api=FakeAPI();a=options(Path(d),api);self.run_promote(api,a);seen=0
                def die(method,path):
                    nonlocal seen
                    seen+=1
                    if seen==kill_at:raise SystemExit(137)
                api.after=die
                with mock.patch.object(module,"verify_public"),mock.patch.object(module,"read_state",lambda p:json.loads(p.read_text())),self.assertRaises(SystemExit):module.rollback(api,a)
                api.after=None
                with mock.patch.object(module,"verify_public"),mock.patch.object(module,"read_state",lambda p:json.loads(p.read_text())):module.promote(api,a)
                self.assertEqual(json.loads(a.state.read_text())["phase"],"rolled-back")
    def test_prewrite_remote_mutation_is_detected(self):
        with tempfile.TemporaryDirectory() as d:
            api=FakeAPI();a=options(Path(d),api)
            def mutate(method,path):
                if method=="PATCH":api.records[0]["ttl"]=60;api.after=None
            api.after=mutate
            with self.assertRaisesRegex(RuntimeError,"identity drift"):module.promote(api,a)
            self.assertTrue(api.rule["enabled"])
    def test_fd_read_and_journal_fsync(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"token";p.write_text("x"*30);p.chmod(0o400);link=Path(d)/"link";link.symlink_to(p)
            with self.assertRaises(OSError):module.read_token(link,os.getuid())
            calls=[];real=os.fsync
            with mock.patch.object(module.os,"fsync",side_effect=lambda fd:(calls.append(fd),real(fd))[1]):module.write_state(Path(d)/"state",{"x":1})
            self.assertGreaterEqual(len(calls),2)
    def test_service_owns_state_directory_before_exec_and_disables_cores(self):
        unit=(ROOT/"clixor-cloudflare-promote.service").read_text()
        self.assertIn("StateDirectory=clixor",unit);self.assertIn("StateDirectoryMode=0700",unit);self.assertIn("LimitCORE=0",unit)
        self.assertLess(unit.index("StateDirectory=clixor"),unit.index("ExecStart="))
    def test_terminal_rerun_is_read_only_and_archive_allows_next_window(self):
        with tempfile.TemporaryDirectory() as d:
            api=FakeAPI();a=options(Path(d),api);self.run_promote(api,a);before=len([c for c in api.calls if c[0] in ("PATCH","PUT","POST")])
            with mock.patch.object(module,"verify_public"),mock.patch.object(module,"read_state",lambda p:json.loads(p.read_text())):module.promote(api,a)
            after=len([c for c in api.calls if c[0] in ("PATCH","PUT","POST")]);self.assertEqual(before,after)
            with mock.patch.object(module,"verify_public"),mock.patch.object(module,"read_state",lambda p:json.loads(p.read_text())):module.archive_terminal(api,a)
            self.assertFalse(a.state.exists());archives=list((a.state.parent/"cloudflare-promotion-archive").glob("*.json"));self.assertEqual(len(archives),1)
if __name__=="__main__":unittest.main()
