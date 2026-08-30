from __future__ import annotations
import argparse, importlib.util, json, os, tempfile, unittest
from pathlib import Path
from unittest import mock

ROOT=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location("cfpromote",ROOT/"cloudflare-promote.py"); assert spec and spec.loader
module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)

class FakeAPI:
    def __init__(self, *, partial=False,mutate_after_put=False):
        self.configs={"old":{"ingress":[{"hostname":h,"service":"http://old:8080"} for h in module.PRODUCTION_HOSTS]+[{"service":"http_status:404"}]},"new":{"ingress":[{"hostname":module.CANARY_HOST,"service":module.ORIGIN},{"service":"http_status:404"}]}}
        self.records=[{"id":"1","type":"CNAME","name":module.PRODUCTION_HOSTS[0],"content":"old.cfargotunnel.com","proxied":True},{"id":"2","type":"CNAME","name":module.PRODUCTION_HOSTS[1],"content":"old.cfargotunnel.com","proxied":True}]
        self.partial=partial; self.mutate_after_put=mutate_after_put; self.calls=[]
    def request(self,method,path,body=None):
        self.calls.append((method,path,body))
        if "/cfd_tunnel/" in path:
            tunnel=path.split("/cfd_tunnel/",1)[1].split("/",1)[0]
            if method=="GET": return {"config":json.loads(module.canonical(self.configs[tunnel]))}
            self.configs[tunnel]=json.loads(module.canonical(body["config"]))
            if self.mutate_after_put:
                self.mutate_after_put=False; self.configs[tunnel]["ingress"].insert(0,{"hostname":"drift.invalid","service":"http://attacker"})
            return {}
        if method=="GET":
            name=path.split("name=",1)[1]; return [dict(r) for r in self.records if r["name"]==name]
        if path.endswith("/batch"):
            for index,patch in enumerate(body["patches"]):
                if self.partial and index: continue
                for record in self.records:
                    if record["id"]==patch["id"]: record.update(patch)
            return {}
        raise AssertionError((method,path))

def args(root:Path,api:FakeAPI):
    evidence=root/"evidence"; evidence.write_text(f"revision={'a'*40}\nstage=canary\nsmoke=passed prefix=clixor-smoke-x checks=1 cleanup=passed\n"); evidence.chmod(0o400)
    return argparse.Namespace(change_window="FROZEN-CHANGE-1",account="acct",zone="zone",old_tunnel="old",candidate_tunnel="new",old_target="old.cfargotunnel.com",candidate_target="new.cfargotunnel.com",revision="a"*40,old_revision="b"*40,old_config_sha=module.digest(api.configs["old"]),candidate_config_sha=module.digest(api.configs["new"]),state=root/"state.json",evidence=evidence)

class PromotionTests(unittest.TestCase):
    def test_success_batches_both_records_and_preserves_single_owner(self):
        with tempfile.TemporaryDirectory() as temporary:
            api=FakeAPI(); options=args(Path(temporary),api)
            with mock.patch.object(module,"verify_public") as verify, mock.patch.object(module,"validate_evidence",lambda *a:None): module.promote(api,options)
            self.assertEqual({r["content"] for r in api.records},{options.candidate_target})
            self.assertTrue(all(any(rule.get("hostname")==host and rule.get("service")==module.ORIGIN for rule in api.configs["new"]["ingress"]) for host in module.PRODUCTION_HOSTS))
            batches=[call for call in api.calls if call[1].endswith("/batch")]
            self.assertEqual(len(batches),1); self.assertEqual(len(batches[0][2]["patches"]),2)
            verify.assert_called_once_with(options.revision)

    def test_config_cas_conflict_changes_nothing(self):
        with tempfile.TemporaryDirectory() as temporary:
            api=FakeAPI(); options=args(Path(temporary),api); options.old_config_sha="0"*64
            with mock.patch.object(module,"validate_evidence",lambda *a:None), self.assertRaisesRegex(RuntimeError,"CAS conflict"): module.promote(api,options)
            self.assertEqual({r["content"] for r in api.records},{options.old_target})

    def test_partial_dns_is_ambiguous_and_remains_fenced(self):
        with tempfile.TemporaryDirectory() as temporary:
            api=FakeAPI(partial=True); options=args(Path(temporary),api)
            with mock.patch.object(module,"verify_public"), mock.patch.object(module,"validate_evidence",lambda *a:None), self.assertRaises(RuntimeError): module.promote(api,options)
            state=json.loads(options.state.read_text()); self.assertEqual(state["phase"],"ambiguous-fenced")
            for tunnel in ("old","new"):
                services={r.get("service") for r in api.configs[tunnel]["ingress"] if r.get("hostname") in module.PRODUCTION_HOSTS}
                self.assertEqual(services,{module.FENCE})

    def test_exact_candidate_rolls_back(self):
        with tempfile.TemporaryDirectory() as temporary:
            api=FakeAPI(); options=args(Path(temporary),api)
            with mock.patch.object(module,"verify_public"), mock.patch.object(module,"validate_evidence",lambda *a:None):
                module.promote(api,options)
                with mock.patch.object(module,"read_state",lambda path:json.loads(path.read_text())):
                    module.rollback(api,options)
            self.assertEqual({r["content"] for r in api.records},{options.old_target})
            self.assertEqual(json.loads(options.state.read_text())["phase"],"rolled-back")

    def test_token_file_never_enters_request_path_or_body(self):
        with tempfile.TemporaryDirectory() as temporary:
            path=Path(temporary)/"credential"; path.write_text("secret-control-token-123456789\n"); path.chmod(0o400)
            self.assertEqual(module.read_token(path,expected_uid=os.getuid()),b"secret-control-token-123456789")
            source=(ROOT/"cloudflare-promote.py").read_text()
            self.assertNotIn("print(self.token",source); self.assertNotIn("--token\"",source)

    def test_evidence_is_exact_revision_root_equivalent_and_read_only(self):
        with tempfile.TemporaryDirectory() as temporary:
            api=FakeAPI(); options=args(Path(temporary),api)
            module.validate_evidence(options.evidence,options.revision,expected_uid=os.getuid())
            options.evidence.chmod(0o600)
            with self.assertRaisesRegex(RuntimeError,"unsafe"):
                module.validate_evidence(options.evidence,options.revision,expected_uid=os.getuid())

    def test_journal_rejects_writable_or_wrong_owner_equivalent(self):
        with tempfile.TemporaryDirectory() as temporary:
            path=Path(temporary)/"state"; path.write_text('{"phase":"promoted"}\n'); path.chmod(0o400)
            self.assertEqual(module.read_state(path,expected_uid=os.getuid())["phase"],"promoted")
            path.chmod(0o600)
            with self.assertRaisesRegex(RuntimeError,"unsafe"):
                module.read_state(path,expected_uid=os.getuid())

    def test_process_death_at_every_external_transition_is_resumable(self):
        phases=("after-old-fence","after-candidate-fence","after-dns-candidate","after-candidate-unfence")
        for phase in phases:
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as temporary:
                api=FakeAPI(); options=args(Path(temporary),api); original=module.checkpoint
                def kill(path,state,current,*,target=phase):
                    if current==target: raise SystemExit(137)
                    original(path,state,current)
                with mock.patch.object(module,"validate_evidence",lambda *a:None), mock.patch.object(module,"verify_public"), mock.patch.object(module,"checkpoint",side_effect=kill), self.assertRaises(SystemExit):
                    module.promote(api,options)
                original_read=module.read_state
                with mock.patch.object(module,"validate_evidence",lambda *a:None), mock.patch.object(module,"verify_public"), mock.patch.object(module,"read_state",lambda path:original_read(path,expected_uid=os.getuid())):
                    module.promote(api,options)
                self.assertEqual(json.loads(options.state.read_text())["phase"],"promoted")
                self.assertEqual({r["content"] for r in api.records},{options.candidate_target})

    def test_remote_mutation_after_write_is_detected_and_refenced(self):
        with tempfile.TemporaryDirectory() as temporary:
            api=FakeAPI(mutate_after_put=True); options=args(Path(temporary),api)
            with mock.patch.object(module,"validate_evidence",lambda *a:None), mock.patch.object(module,"verify_public"), self.assertRaisesRegex(RuntimeError,"did not converge"):
                module.promote(api,options)
            self.assertIn(json.loads(options.state.read_text())["phase"],{"aborted-before-switch","ambiguous-fenced"})

    def test_process_death_during_every_rollback_transition_resumes(self):
        phases=("rollback-after-candidate-fence","rollback-after-dns-old","rollback-after-old-unfence")
        for phase in phases:
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as temporary:
                api=FakeAPI(); options=args(Path(temporary),api); original_read=module.read_state; original_checkpoint=module.checkpoint
                with mock.patch.object(module,"verify_public"), mock.patch.object(module,"validate_evidence",lambda *a:None): module.promote(api,options)
                def kill(path,state,current,*,target=phase):
                    if current==target: raise SystemExit(137)
                    original_checkpoint(path,state,current)
                with mock.patch.object(module,"verify_public"), mock.patch.object(module,"read_state",lambda p:original_read(p,expected_uid=os.getuid())), mock.patch.object(module,"checkpoint",side_effect=kill), self.assertRaises(SystemExit): module.rollback(api,options)
                with mock.patch.object(module,"verify_public"), mock.patch.object(module,"read_state",lambda p:original_read(p,expected_uid=os.getuid())): module.rollback(api,options)
                self.assertEqual(json.loads(options.state.read_text())["phase"],"rolled-back")

    def test_fd_relative_reads_reject_symlink_and_resist_path_swap(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary); authority=root/"authority"; authority.write_text("original-authority-value-12345"); authority.chmod(0o400)
            link=root/"link"; link.symlink_to(authority)
            with self.assertRaises(OSError): module.read_token(link,expected_uid=os.getuid())
            replacement=root/"replacement"; replacement.write_text("attacker-authority-value-12345"); replacement.chmod(0o400)
            original_open=module.os.open; swapped=False
            def swapping_open(path,*args,**kwargs):
                nonlocal swapped
                fd=original_open(path,*args,**kwargs)
                if path==authority.name and kwargs.get("dir_fd") is not None and not swapped:
                    swapped=True; os.replace(replacement,authority)
                return fd
            with mock.patch.object(module.os,"open",side_effect=swapping_open):
                self.assertEqual(module.read_token(authority,expected_uid=os.getuid()),b"original-authority-value-12345")

    def test_journal_fsyncs_file_and_parent_before_return(self):
        with tempfile.TemporaryDirectory() as temporary:
            path=Path(temporary)/"state"; calls=[]; original=module.os.fsync
            with mock.patch.object(module.os,"fsync",side_effect=lambda fd:(calls.append(fd),original(fd))[1]):
                module.write_state(path,{"phase":"test"})
            self.assertGreaterEqual(len(calls),2)

if __name__=="__main__": unittest.main()
