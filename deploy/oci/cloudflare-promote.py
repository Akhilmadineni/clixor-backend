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

def read_token(path: Path, expected_uid: int = 0) -> bytes:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise RuntimeError("control credential is not a regular file")
    if metadata.st_uid != expected_uid or stat.S_IMODE(metadata.st_mode) != 0o400:
        raise RuntimeError("control credential ownership or mode is unsafe")
    value = path.read_bytes().strip()
    if not 20 <= len(value) <= 4096 or any(byte < 33 or byte > 126 for byte in value):
        raise RuntimeError("control credential is invalid")
    return value

def validate_evidence(path: Path, revision: str, expected_uid: int = 0) -> None:
    metadata=path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or metadata.st_uid != expected_uid or stat.S_IMODE(metadata.st_mode) != 0o400:
        raise RuntimeError("canary evidence is unsafe")
    lines=path.read_text().splitlines()
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

def set_config(api: API, account: str, tunnel: str, config: dict[str, Any]) -> None:
    api.request("PUT", f"/accounts/{account}/cfd_tunnel/{tunnel}/configurations", {"config": config})
    if digest(ingress_config(api, account, tunnel)) != digest(config):
        raise RuntimeError("tunnel configuration did not converge")

def route(config: dict[str, Any], hosts: tuple[str, ...], service: str) -> dict[str, Any]:
    result = json.loads(canonical(config))
    ingress = result.get("ingress")
    if not isinstance(ingress, list) or not ingress or ingress[-1].get("service") != "http_status:404":
        raise RuntimeError("tunnel catch-all is not exact")
    filtered = [rule for rule in ingress[:-1] if rule.get("hostname") not in hosts]
    filtered.extend({"hostname": host, "service": service} for host in hosts)
    filtered.append({"service": "http_status:404"})
    result["ingress"] = filtered
    return result

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
    if any(record.get("content") != expected for record in records):
        raise RuntimeError("production DNS CAS conflict")
    patches=[{"id":r["id"], "type":"CNAME", "name":r["name"], "content":target, "proxied":True, "ttl":1} for r in records]
    api.request("POST", f"/zones/{zone}/dns_records/batch", {"patches":patches})
    if any(record.get("content") != target for record in dns_records(api, zone)):
        raise RuntimeError("atomic DNS batch did not converge")

def write_state(path: Path, state: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary=tempfile.mkstemp(prefix=".promotion.", dir=path.parent)
    try:
        os.write(fd, canonical(state)+b"\n"); os.fsync(fd); os.close(fd); fd=-1
        os.chmod(temporary, 0o400); os.replace(temporary, path)
    finally:
        if fd >= 0: os.close(fd)
        try: os.unlink(temporary)
        except FileNotFoundError: pass

def read_state(path: Path, expected_uid: int = 0) -> dict[str, Any]:
    metadata=path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or metadata.st_uid != expected_uid or stat.S_IMODE(metadata.st_mode) != 0o400 or metadata.st_size > 1024*1024:
        raise RuntimeError("promotion journal is unsafe")
    value=json.loads(path.read_bytes())
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
    if args.state.exists() or args.state.is_symlink():
        raise RuntimeError("promotion journal already exists; archive it under change control")
    old=ingress_config(api,args.account,args.old_tunnel)
    candidate=ingress_config(api,args.account,args.candidate_tunnel)
    if digest(old) != args.old_config_sha or digest(candidate) != args.candidate_config_sha:
        raise RuntimeError("tunnel configuration CAS conflict")
    if not any(r.get("hostname")==CANARY_HOST and r.get("service")==ORIGIN for r in candidate.get("ingress",[])):
        raise RuntimeError("candidate canary origin is not exact")
    records=dns_records(api,args.zone)
    state={"schema":1,"phase":"fencing","revision":args.revision,"old_revision":args.old_revision,"old_tunnel":args.old_tunnel,"candidate_tunnel":args.candidate_tunnel,"old_target":args.old_target,"candidate_target":args.candidate_target,"old_config":old,"candidate_config":candidate}
    write_state(args.state,state)
    old_fenced=route(old,PRODUCTION_HOSTS,FENCE); candidate_fenced=route(candidate,PRODUCTION_HOSTS,FENCE)
    try:
        set_config(api,args.account,args.old_tunnel,old_fenced)
        set_config(api,args.account,args.candidate_tunnel,candidate_fenced)
        switch_dns(api,args.zone,records,args.old_target,args.candidate_target)
        candidate_live=route(candidate,PRODUCTION_HOSTS,ORIGIN)
        set_config(api,args.account,args.candidate_tunnel,candidate_live)
        verify_public(args.revision)
        state.update(phase="promoted",candidate_live_config=candidate_live)
        write_state(args.state,state)
    except Exception:
        # Best-effort fence both authorities. Never unfreeze on ambiguity.
        for tunnel, config in ((args.old_tunnel,old_fenced),(args.candidate_tunnel,candidate_fenced)):
            try: set_config(api,args.account,tunnel,config)
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

def rollback(api: API, args: argparse.Namespace) -> None:
    state=read_state(args.state)
    if state.get("phase") != "promoted" or state.get("revision") != args.revision:
        raise RuntimeError("rollback state is not an exact promoted candidate")
    expected={"old_tunnel":args.old_tunnel,"candidate_tunnel":args.candidate_tunnel,"old_target":args.old_target,"candidate_target":args.candidate_target}
    if any(state.get(key)!=value for key,value in expected.items()):
        raise RuntimeError("rollback authority does not match the promotion journal")
    candidate_live=state["candidate_live_config"]
    if digest(ingress_config(api,args.account,args.candidate_tunnel)) != digest(candidate_live):
        raise RuntimeError("candidate configuration changed; writes remain fenced")
    records=dns_records(api,args.zone)
    candidate_fenced=route(state["candidate_config"],PRODUCTION_HOSTS,FENCE)
    set_config(api,args.account,args.candidate_tunnel,candidate_fenced)
    switch_dns(api,args.zone,records,args.candidate_target,args.old_target)
    set_config(api,args.account,args.old_tunnel,state["old_config"])
    verify_public(state["old_revision"])
    state["phase"]="rolled-back"; write_state(args.state,state)

def main() -> int:
    parser=argparse.ArgumentParser(); parser.add_argument("mode",choices=("promote","rollback"))
    for name in ("account","zone","old-tunnel","candidate-tunnel","old-target","candidate-target","revision"): parser.add_argument("--"+name,required=True)
    parser.add_argument("--old-config-sha"); parser.add_argument("--candidate-config-sha")
    parser.add_argument("--old-revision")
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
        lock=os.open(str(args.state)+".lock",os.O_WRONLY|os.O_CREAT|os.O_NOFOLLOW,0o600)
        try:
            fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            api=API(read_token(args.token_file)); (promote if args.mode=="promote" else rollback)(api,args)
        finally: os.close(lock)
    except Exception as error:
        print(f"promotion=failed reason={error}",file=sys.stderr); return 1
    print(f"promotion={args.mode}-complete revision={args.revision}"); return 0
if __name__=="__main__": raise SystemExit(main())
