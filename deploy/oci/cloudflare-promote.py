#!/usr/bin/env python3
"""Manual, CAS-driven single-owner Cloudflare production promotion."""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

PRODUCTION_HOSTS = ("clustr-api.atlanteanz.com", "clixor.atlanteanz.com")
CANARY_HOST = "clixor-oci-canary.atlanteanz.com"
ORIGIN = "unix:/run/clixor-origin/gateway.sock"
FENCE = "http_status:503"
HEX_ID=re.compile(r"[0-9a-f]{32}")
UUID=re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
REVISION=re.compile(r"[0-9a-f]{40}")
ASSOCIATION = {"applinks":{"apps":[],"details":[{"appIDs":["H9S3BAQ9U8.com.Clustr.Clustr.Clustr"],"components":[{"/":"/join","comment":"Matches only the fixed Clixor invite landing path."}]}]}}

def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()

def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()

def validate_parent_chain(directory:Path,expected_uid:int)->None:
    if not directory.is_absolute(): raise RuntimeError("authority path is invalid")
    current=Path("/")
    for part in directory.parts[1:]:
        current/=part; metadata=current.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid!=expected_uid or stat.S_IMODE(metadata.st_mode)&0o022:
            raise RuntimeError("authority parent chain is unsafe")

def secure_read(path:Path,expected_uid:int,mode:int,maximum:int)->bytes:
    if path.name in ("",".","..") or not path.is_absolute(): raise RuntimeError("authority path is invalid")
    if expected_uid==0:
        validate_parent_chain(path.parent,0)
    parent=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=parent)
        try:
            metadata=os.fstat(fd)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid!=expected_uid or stat.S_IMODE(metadata.st_mode)!=mode or metadata.st_size>maximum:
                raise RuntimeError("authority file metadata is unsafe")
            chunks=[]; remaining=maximum+1
            while remaining:
                chunk=os.read(fd,min(65536,remaining))
                if not chunk: break
                chunks.append(chunk); remaining-=len(chunk)
            value=b"".join(chunks)
            if len(value)>maximum: raise RuntimeError("authority file is oversized")
            return value
        finally: os.close(fd)
    finally: os.close(parent)

def read_token(path: Path, expected_uid: int = 0) -> bytes:
    value = secure_read(path,expected_uid,0o400,4096).strip()
    if not 20 <= len(value) <= 4096 or any(byte < 33 or byte > 126 for byte in value):
        raise RuntimeError("control credential is invalid")
    return value

def validate_evidence(path: Path, revision: str, expected_uid: int = 0) -> None:
    lines=secure_read(path,expected_uid,0o400,65536).decode("utf-8").splitlines()
    if len(lines)!=3 or lines[0]!=f"revision={revision}" or lines[1]!="stage=canary" or not lines[2].startswith("smoke=passed ") or not lines[2].endswith(" cleanup=passed"):
        raise RuntimeError("canary evidence does not authorize this revision")

class API:
    def __init__(self, token: bytes, base: str = "https://api.cloudflare.com/client/v4"):
        self.token, self.base = token, base.rstrip("/")
    def request(self, method: str, path: str, body: Any = None) -> Any:
        data = None if body is None else canonical(body)
        request = urllib.request.Request(self.base + path, data=data, method=method)
        request.add_header("Authorization", "Bearer " + self.token.decode("ascii"))
        request.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                document = json.load(response)
        except (OSError, urllib.error.URLError, json.JSONDecodeError) as error:
            raise RuntimeError("Cloudflare control request failed") from error
        if not isinstance(document, dict) or document.get("success") is not True:
            raise RuntimeError("Cloudflare control request was rejected")
        return document.get("result")

def ingress_config(api: API, account: str, tunnel: str) -> dict[str, Any]:
    result = api.request("GET", f"/accounts/{account}/cfd_tunnel/{tunnel}/configurations")
    if not isinstance(result, dict) or not isinstance(result.get("config"), dict):
        raise RuntimeError("tunnel configuration response is invalid")
    return result["config"]

def set_config(api: API, account: str, tunnel: str, config: dict[str, Any], expected: dict[str,Any]|None=None) -> None:
    current=ingress_config(api,account,tunnel)
    if expected is not None and digest(current)!=digest(expected):
        raise RuntimeError("concurrent tunnel configuration drift")
    api.request("PUT", f"/accounts/{account}/cfd_tunnel/{tunnel}/configurations", {"config": config})
    if digest(ingress_config(api, account, tunnel)) != digest(config):
        raise RuntimeError("tunnel configuration did not converge")

def route(config: dict[str, Any], hosts: tuple[str, ...], service: str) -> dict[str, Any]:
    result = json.loads(canonical(config))
    if set(result)!={"ingress"}:
        raise RuntimeError("tunnel is not a dedicated exact ingress authority")
    ingress = result.get("ingress")
    if not isinstance(ingress, list) or not ingress or ingress[-1].get("service") != "http_status:404":
        raise RuntimeError("tunnel catch-all is not exact")
    filtered = [rule for rule in ingress[:-1] if rule.get("hostname") not in hosts]
    filtered.extend({"hostname": host, "service": service} for host in hosts)
    filtered.append({"service": "http_status:404"})
    result["ingress"] = filtered
    return result

def checkpoint(path:Path,state:dict[str,Any],phase:str)->None:
    state["phase"]=phase; write_state(path,state)

def dns_records(api: API, zone: str) -> list[dict[str, Any]]:
    records=[]
    for host in PRODUCTION_HOSTS:
        result=api.request("GET", f"/zones/{zone}/dns_records?type=CNAME&name={host}")
        if not isinstance(result, list) or len(result) != 1: raise RuntimeError("production DNS authority is ambiguous")
        record=result[0]
        if record.get("name") != host or record.get("type") != "CNAME" or record.get("proxied") is not True:
            raise RuntimeError("production DNS record is not exact")
        records.append(record)
    return records

def switch_dns(api: API, zone: str, records: list[dict[str, Any]], expected: str, target: str) -> None:
    current=dns_records(api,zone)
    authority=lambda values:[(item.get("id"),item.get("name"),item.get("type"),item.get("content"),item.get("proxied")) for item in values]
    if authority(current)!=authority(records):
        raise RuntimeError("concurrent production DNS drift")
    records=current
    if any(record.get("content") != expected for record in records):
        raise RuntimeError("production DNS CAS conflict")
    patches=[{"id":r["id"], "type":"CNAME", "name":r["name"], "content":target, "proxied":True, "ttl":1} for r in records]
    api.request("POST", f"/zones/{zone}/dns_records/batch", {"patches":patches})
    if any(record.get("content") != target for record in dns_records(api, zone)):
        raise RuntimeError("atomic DNS batch did not converge")

def write_state(path: Path, state: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.geteuid()==0:
        os.chown(path.parent,0,0); os.chmod(path.parent,0o700)
        validate_parent_chain(path.parent,0)
    parent=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    temporary=f".promotion.{os.getpid()}.{os.urandom(8).hex()}"
    fd=-1
    try:
        fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=parent)
        payload=canonical(state)+b"\n"; offset=0
        while offset<len(payload): offset+=os.write(fd,payload[offset:])
        os.fsync(fd); os.fchmod(fd,0o400); os.close(fd); fd=-1
        os.replace(temporary,path.name,src_dir_fd=parent,dst_dir_fd=parent); os.fsync(parent)
    finally:
        if fd >= 0: os.close(fd)
        try: os.unlink(temporary,dir_fd=parent)
        except FileNotFoundError: pass
        os.close(parent)

def read_state(path: Path, expected_uid: int = 0) -> dict[str, Any]:
    value=json.loads(secure_read(path,expected_uid,0o400,1024*1024))
    if not isinstance(value,dict): raise RuntimeError("promotion journal is invalid")
    return value

def verify_public(revision: str) -> None:
    for attempt in range(12):
        try:
            request=urllib.request.Request(f"https://clustr-api.atlanteanz.com/health/ready?promotion={revision}-{attempt}",headers={"Cache-Control":"no-cache"})
            with urllib.request.urlopen(request,timeout=10) as response:
                ready=json.load(response); header=response.headers.get("X-Clixor-Revision")
            request=urllib.request.Request(f"https://clixor.atlanteanz.com/.well-known/apple-app-site-association?promotion={revision}-{attempt}",headers={"Cache-Control":"no-cache"})
            with urllib.request.urlopen(request,timeout=10) as response:
                association=json.load(response); association_revision=response.headers.get("X-Clixor-Revision")
            if ready=={"status":"ready","revision":revision} and header==revision and association==ASSOCIATION and association_revision==revision:
                return
        except (OSError,urllib.error.URLError,json.JSONDecodeError): pass
        if attempt < 11: time.sleep(5)
    raise RuntimeError("public API and association did not converge to the exact revision")

def promote(api: API, args: argparse.Namespace) -> None:
    validate_evidence(args.evidence,args.revision)
    if not isinstance(args.change_window,str) or not args.change_window.startswith("FROZEN-"):
        raise RuntimeError("externally frozen Cloudflare change window is not attested")
    if args.state.exists() or args.state.is_symlink():
        state=read_state(args.state)
        reconcile(api,args,state); return
    old=ingress_config(api,args.account,args.old_tunnel)
    candidate=ingress_config(api,args.account,args.candidate_tunnel)
    if digest(old) != args.old_config_sha or digest(candidate) != args.candidate_config_sha:
        raise RuntimeError("tunnel configuration CAS conflict")
    if not any(r.get("hostname")==CANARY_HOST and r.get("service")==ORIGIN for r in candidate.get("ingress",[])):
        raise RuntimeError("candidate canary origin is not exact")
    records=dns_records(api,args.zone)
    state={"schema":1,"phase":"fencing","change_window":args.change_window,"account":args.account,"zone":args.zone,"revision":args.revision,"old_revision":args.old_revision,"old_tunnel":args.old_tunnel,"candidate_tunnel":args.candidate_tunnel,"old_target":args.old_target,"candidate_target":args.candidate_target,"old_config":old,"candidate_config":candidate}
    write_state(args.state,state)
    old_fenced=route(old,PRODUCTION_HOSTS,FENCE); candidate_fenced=route(candidate,PRODUCTION_HOSTS,FENCE)
    try:
        checkpoint(args.state,state,"before-old-fence")
        set_config(api,args.account,args.old_tunnel,old_fenced,old)
        checkpoint(args.state,state,"after-old-fence")
        checkpoint(args.state,state,"before-candidate-fence")
        set_config(api,args.account,args.candidate_tunnel,candidate_fenced,candidate)
        checkpoint(args.state,state,"after-candidate-fence")
        checkpoint(args.state,state,"before-dns-candidate")
        switch_dns(api,args.zone,records,args.old_target,args.candidate_target)
        checkpoint(args.state,state,"after-dns-candidate")
        candidate_live=route(candidate,PRODUCTION_HOSTS,ORIGIN)
        checkpoint(args.state,state,"before-candidate-unfence")
        set_config(api,args.account,args.candidate_tunnel,candidate_live,candidate_fenced)
        checkpoint(args.state,state,"after-candidate-unfence")
        verify_public(args.revision)
        state.update(phase="promoted",candidate_live_config=candidate_live)
        write_state(args.state,state)
    except Exception:
        # Best-effort fence both authorities. Never unfreeze on ambiguity.
        for tunnel, config in ((args.old_tunnel,old_fenced),(args.candidate_tunnel,candidate_fenced)):
            try:
                current=ingress_config(api,args.account,tunnel)
                allowed=(old,old_fenced) if tunnel==args.old_tunnel else (candidate,candidate_fenced,route(candidate,PRODUCTION_HOSTS,ORIGIN))
                if any(digest(current)==digest(item) for item in allowed): set_config(api,args.account,tunnel,config,current)
            except Exception: pass
        try:
            current=dns_records(api,args.zone)
            targets={record.get("content") for record in current}
            if targets == {args.candidate_target}:
                switch_dns(api,args.zone,current,args.candidate_target,args.old_target)
                set_config(api,args.account,args.old_tunnel,old)
                verify_public(args.old_revision)
                state["phase"]="automatically-rolled-back"
            elif targets == {args.old_target}:
                set_config(api,args.account,args.old_tunnel,old)
                state["phase"]="aborted-before-switch"
            else:
                state["phase"]="ambiguous-fenced"
        except Exception:
            state["phase"]="ambiguous-fenced"
        write_state(args.state,state); raise

def reconcile(api:API,args:argparse.Namespace,state:dict[str,Any])->None:
    authority={"account":args.account,"zone":args.zone,"old_tunnel":args.old_tunnel,"candidate_tunnel":args.candidate_tunnel,"old_target":args.old_target,"candidate_target":args.candidate_target,"revision":args.revision}
    if any(state.get(key)!=value for key,value in authority.items()): raise RuntimeError("existing journal authority mismatch")
    old=state["old_config"]; candidate=state["candidate_config"]
    old_fenced=route(old,PRODUCTION_HOSTS,FENCE); candidate_fenced=route(candidate,PRODUCTION_HOSTS,FENCE); candidate_live=route(candidate,PRODUCTION_HOSTS,ORIGIN)
    old_current=ingress_config(api,args.account,args.old_tunnel); candidate_current=ingress_config(api,args.account,args.candidate_tunnel); records=dns_records(api,args.zone); targets={r["content"] for r in records}
    known_old=(old,old_fenced); known_candidate=(candidate,candidate_fenced,candidate_live)
    if not any(digest(old_current)==digest(x) for x in known_old) or not any(digest(candidate_current)==digest(x) for x in known_candidate):
        checkpoint(args.state,state,"ambiguous-concurrent-drift"); raise RuntimeError("remote drift requires operator-fenced resolution")
    if targets not in ({args.old_target},{args.candidate_target}):
        checkpoint(args.state,state,"reconcile-before-ambiguity-fence")
        if digest(old_current)!=digest(old_fenced): set_config(api,args.account,args.old_tunnel,old_fenced,old_current)
        if digest(candidate_current)!=digest(candidate_fenced): set_config(api,args.account,args.candidate_tunnel,candidate_fenced,candidate_current)
        checkpoint(args.state,state,"ambiguous-fenced"); raise RuntimeError("mixed DNS propagation remains write-fenced")
    if targets=={args.candidate_target}:
        if digest(old_current)!=digest(old_fenced):
            checkpoint(args.state,state,"reconcile-before-old-fence")
            set_config(api,args.account,args.old_tunnel,old_fenced,old_current)
        if digest(candidate_current)==digest(candidate_fenced):
            checkpoint(args.state,state,"before-candidate-unfence")
            set_config(api,args.account,args.candidate_tunnel,candidate_live,candidate_fenced)
            checkpoint(args.state,state,"after-candidate-unfence")
        elif digest(candidate_current)!=digest(candidate_live):
            set_config(api,args.account,args.candidate_tunnel,candidate_fenced,candidate_current); checkpoint(args.state,state,"ambiguous-fenced"); raise RuntimeError("candidate authority was not safely resumable")
        verify_public(args.revision); state["candidate_live_config"]=candidate_live; checkpoint(args.state,state,"promoted"); return
    # DNS still selects old. Resume only through exact known phases.
    if digest(old_current)==digest(old):
        checkpoint(args.state,state,"reconcile-before-old-fence"); set_config(api,args.account,args.old_tunnel,old_fenced,old); checkpoint(args.state,state,"after-old-fence")
    if digest(candidate_current)==digest(candidate):
        checkpoint(args.state,state,"reconcile-before-candidate-fence"); set_config(api,args.account,args.candidate_tunnel,candidate_fenced,candidate); checkpoint(args.state,state,"after-candidate-fence")
    elif digest(candidate_current)==digest(candidate_live):
        checkpoint(args.state,state,"reconcile-before-candidate-refence"); set_config(api,args.account,args.candidate_tunnel,candidate_fenced,candidate_live); checkpoint(args.state,state,"candidate-refenced")
    checkpoint(args.state,state,"reconcile-before-dns-candidate"); switch_dns(api,args.zone,dns_records(api,args.zone),args.old_target,args.candidate_target); checkpoint(args.state,state,"after-dns-candidate")
    checkpoint(args.state,state,"reconcile-before-candidate-unfence"); set_config(api,args.account,args.candidate_tunnel,candidate_live,candidate_fenced); checkpoint(args.state,state,"after-candidate-unfence")
    verify_public(args.revision); state["candidate_live_config"]=candidate_live; checkpoint(args.state,state,"promoted")

def rollback(api: API, args: argparse.Namespace) -> None:
    state=read_state(args.state)
    if state.get("revision") != args.revision:
        raise RuntimeError("rollback state is not an exact promoted candidate")
    expected={"old_tunnel":args.old_tunnel,"candidate_tunnel":args.candidate_tunnel,"old_target":args.old_target,"candidate_target":args.candidate_target}
    if any(state.get(key)!=value for key,value in expected.items()):
        raise RuntimeError("rollback authority does not match the promotion journal")
    candidate_live=state["candidate_live_config"]
    candidate_fenced=route(state["candidate_config"],PRODUCTION_HOSTS,FENCE)
    old_fenced=route(state["old_config"],PRODUCTION_HOSTS,FENCE)
    candidate_current=ingress_config(api,args.account,args.candidate_tunnel)
    old_current=ingress_config(api,args.account,args.old_tunnel)
    if digest(candidate_current) not in (digest(candidate_live),digest(candidate_fenced)) or digest(old_current) not in (digest(state["old_config"]),digest(old_fenced)):
        checkpoint(args.state,state,"rollback-ambiguous-drift"); raise RuntimeError("rollback authority changed; writes remain fenced")
    records=dns_records(api,args.zone)
    targets={record["content"] for record in records}
    if targets not in ({args.old_target},{args.candidate_target}):
        if digest(candidate_current)!=digest(candidate_fenced): set_config(api,args.account,args.candidate_tunnel,candidate_fenced,candidate_current)
        if digest(old_current)!=digest(old_fenced): set_config(api,args.account,args.old_tunnel,old_fenced,old_current)
        checkpoint(args.state,state,"rollback-ambiguous-fenced"); raise RuntimeError("rollback DNS is mixed; writes remain fenced")
    if digest(candidate_current)!=digest(candidate_fenced):
        checkpoint(args.state,state,"rollback-before-candidate-fence")
        set_config(api,args.account,args.candidate_tunnel,candidate_fenced,candidate_current)
        checkpoint(args.state,state,"rollback-after-candidate-fence")
    if targets=={args.candidate_target}:
        checkpoint(args.state,state,"rollback-before-dns-old")
        switch_dns(api,args.zone,dns_records(api,args.zone),args.candidate_target,args.old_target)
        checkpoint(args.state,state,"rollback-after-dns-old")
    old_current=ingress_config(api,args.account,args.old_tunnel)
    if digest(old_current)!=digest(state["old_config"]):
        checkpoint(args.state,state,"rollback-before-old-unfence")
        set_config(api,args.account,args.old_tunnel,state["old_config"],old_current)
        checkpoint(args.state,state,"rollback-after-old-unfence")
    verify_public(state["old_revision"])
    state["phase"]="rolled-back"; write_state(args.state,state)

def main() -> int:
    if len(sys.argv)>1 and sys.argv[1]=="execute":
        parser=argparse.ArgumentParser(); parser.add_argument("mode",choices=("execute",)); parser.add_argument("--request-file",type=Path,default=Path("/run/credentials/clixor-cloudflare-promote.service/promotion-request")); parser.add_argument("--token-file",type=Path,default=Path("/run/credentials/clixor-cloudflare-promote.service/cloudflare-control-token")); parser.add_argument("--state",type=Path,default=Path("/var/lib/clixor/cloudflare-promotion.json")); parsed=parser.parse_args()
        request=json.loads(secure_read(parsed.request_file,0,0o400,65536))
        expected={"mode","change_window","account","zone","old_tunnel","candidate_tunnel","old_target","candidate_target","revision","old_revision","old_config_sha","candidate_config_sha","evidence"}
        if not isinstance(request,dict) or set(request)!=expected: parser.error("promotion request inventory is not exact")
        if request.get("mode") not in ("promote","rollback"): parser.error("promotion request mode is invalid")
        args=argparse.Namespace(**request,token_file=parsed.token_file,state=parsed.state)
        args.evidence=Path(args.evidence)
    else:
        parser=argparse.ArgumentParser(); parser.add_argument("mode",choices=("promote","rollback"))
        for name in ("account","zone","old-tunnel","candidate-tunnel","old-target","candidate-target","revision"): parser.add_argument("--"+name,required=True)
        parser.add_argument("--old-config-sha"); parser.add_argument("--candidate-config-sha")
        parser.add_argument("--old-revision")
        parser.add_argument("--change-window",required=True)
        parser.add_argument("--evidence",type=Path)
        parser.add_argument("--token-file",type=Path,default=Path("/run/credentials/clixor-cloudflare-promotion.service/cloudflare-control-token")); parser.add_argument("--state",type=Path,default=Path("/var/lib/clixor/cloudflare-promotion.json"))
        args=parser.parse_args()
    if HEX_ID.fullmatch(args.account) is None or HEX_ID.fullmatch(args.zone) is None: parser.error("account and zone must be exact lowercase IDs")
    if UUID.fullmatch(args.old_tunnel) is None or UUID.fullmatch(args.candidate_tunnel) is None or args.old_tunnel==args.candidate_tunnel: parser.error("tunnel IDs must be distinct exact UUIDs")
    if args.old_target != f"{args.old_tunnel}.cfargotunnel.com" or args.candidate_target != f"{args.candidate_tunnel}.cfargotunnel.com": parser.error("DNS targets must bind the exact tunnel IDs")
    if REVISION.fullmatch(args.revision) is None: parser.error("revision must be an exact Git SHA")
    if args.mode=="promote" and (not args.old_config_sha or not args.candidate_config_sha): parser.error("promotion requires both config CAS digests")
    if args.mode=="promote" and not args.old_revision: parser.error("promotion requires --old-revision for verified rollback")
    if args.mode=="promote" and args.evidence is None: parser.error("promotion requires exact canary evidence")
    try:
        args.state.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
        if os.geteuid()==0:
            os.chown(args.state.parent,0,0); os.chmod(args.state.parent,0o700); validate_parent_chain(args.state.parent,0)
        lock=os.open(str(args.state)+".lock",os.O_WRONLY|os.O_CREAT|os.O_NOFOLLOW,0o600)
        try:
            fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            api=API(read_token(args.token_file)); (promote if args.mode=="promote" else rollback)(api,args)
        finally: os.close(lock)
    except Exception as error:
        print(f"promotion=failed reason={error}",file=sys.stderr); return 1
    print(f"promotion={args.mode}-complete revision={args.revision}"); return 0
if __name__=="__main__": raise SystemExit(main())
