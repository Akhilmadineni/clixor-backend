#!/usr/bin/env python3
"""Crash-recoverable, independently fenced Cloudflare ownership promotion."""
from __future__ import annotations
import argparse,fcntl,hashlib,ipaddress,json,os,re,stat,sys,time,urllib.error,urllib.request
from pathlib import Path
from typing import Any
PRODUCTION_HOSTS=("clustr-api.atlanteanz.com","clixor.atlanteanz.com"); CANARY_HOST="clixor-oci-canary.atlanteanz.com"; ORIGIN="unix:/run/clixor-origin/gateway.sock"
HEX_ID=re.compile(r"[0-9a-f]{32}"); UUID=re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"); REVISION=re.compile(r"[0-9a-f]{40}"); SHA=re.compile(r"[0-9a-f]{64}")
ASSOCIATION={"applinks":{"apps":[],"details":[{"appIDs":["H9S3BAQ9U8.com.Clustr.Clustr.Clustr"],"components":[{"/":"/join","comment":"Matches only the fixed Clixor invite landing path."}]}]}}
def canonical(v:Any)->bytes:return json.dumps(v,sort_keys=True,separators=(",",":")).encode()
def digest(v:Any)->str:return hashlib.sha256(canonical(v)).hexdigest()
def validate_parent_chain(directory:Path,uid:int)->None:
    if not directory.is_absolute():raise RuntimeError("authority path is invalid")
    p=Path("/")
    for part in directory.parts[1:]:
        p/=part;s=p.lstat()
        if stat.S_ISLNK(s.st_mode) or not stat.S_ISDIR(s.st_mode) or s.st_uid!=uid or stat.S_IMODE(s.st_mode)&0o022:raise RuntimeError("authority parent chain is unsafe")
def secure_read(path:Path,uid:int,mode:int,maximum:int)->bytes:
    if not path.is_absolute() or path.name in ("",".",".."):raise RuntimeError("authority path is invalid")
    if uid==0:validate_parent_chain(path.parent,uid)
    d=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        f=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=d)
        try:
            s=os.fstat(f)
            if not stat.S_ISREG(s.st_mode) or s.st_uid!=uid or stat.S_IMODE(s.st_mode)!=mode or s.st_size>maximum:raise RuntimeError("authority file metadata is unsafe")
            out=b""
            while len(out)<=maximum:
                b=os.read(f,min(65536,maximum+1-len(out)))
                if not b:break
                out+=b
            if len(out)>maximum:raise RuntimeError("authority file is oversized")
            return out
        finally:os.close(f)
    finally:os.close(d)
def read_token(path:Path,expected_uid:int=0)->bytes:
    v=secure_read(path,expected_uid,0o400,4096).strip()
    if not 20<=len(v)<=4096 or any(c<33 or c>126 for c in v):raise RuntimeError("control credential is invalid")
    return v
def evidence_digest(path:Path,revision:str,expected_uid:int=0)->str:
    raw=secure_read(path,expected_uid,0o400,65536);lines=raw.decode().splitlines()
    if len(lines)!=3 or lines[0]!=f"revision={revision}" or lines[1]!="stage=canary" or not lines[2].startswith("smoke=passed ") or not lines[2].endswith(" cleanup=passed"):raise RuntimeError("canary evidence does not authorize this revision")
    return hashlib.sha256(raw).hexdigest()
def validate_evidence(path:Path,revision:str,expected_uid:int=0)->None:evidence_digest(path,revision,expected_uid)
class API:
    def __init__(self,token:bytes,base="https://api.cloudflare.com/client/v4"):self.token,self.base=token,base.rstrip("/")
    def request(self,method,path,body=None):
        q=urllib.request.Request(self.base+path,data=None if body is None else canonical(body),method=method,headers={"Authorization":"Bearer "+self.token.decode(),"Content-Type":"application/json"})
        try:
            with urllib.request.urlopen(q,timeout=20) as r:doc=json.load(r)
        except (OSError,urllib.error.URLError,json.JSONDecodeError) as e:raise RuntimeError("Cloudflare control request failed") from e
        if not isinstance(doc,dict) or doc.get("success") is not True:raise RuntimeError("Cloudflare control request was rejected")
        return doc.get("result")
def ingress_config(api,account,tunnel):
    r=api.request("GET",f"/accounts/{account}/cfd_tunnel/{tunnel}/configurations")
    if not isinstance(r,dict) or not isinstance(r.get("config"),dict):raise RuntimeError("tunnel configuration response is invalid")
    return r["config"]
def exact_config(config,kind):
    if kind=="candidate":expected=[{"hostname":CANARY_HOST,"service":ORIGIN},{"service":"http_status:404"}]
    else:
        ingress=config.get("ingress") if isinstance(config,dict) else None
        if not isinstance(ingress,list) or len(ingress)!=3 or ingress[-1]!={"service":"http_status:404"}:raise RuntimeError("old tunnel allowlist is not exact")
        rules=ingress[:-1]
        if {r.get("hostname") for r in rules}!=set(PRODUCTION_HOSTS) or any(set(r)!={"hostname","service"} or not isinstance(r["service"],str) or not r["service"] for r in rules):raise RuntimeError("old tunnel allowlist is not exact")
        expected=ingress
    if set(config)!={"ingress"} or config.get("ingress")!=expected:raise RuntimeError(f"{kind} tunnel allowlist is not exact")
def candidate_live(config):
    exact_config(config,"candidate");return {"ingress":[{"hostname":CANARY_HOST,"service":ORIGIN}]+[{"hostname":h,"service":ORIGIN} for h in PRODUCTION_HOSTS]+[{"service":"http_status:404"}]}
def set_config(api,account,tunnel,new,expected):
    if digest(ingress_config(api,account,tunnel))!=digest(expected):raise RuntimeError("concurrent tunnel configuration drift")
    api.request("PUT",f"/accounts/{account}/cfd_tunnel/{tunnel}/configurations",{"config":new})
    if digest(ingress_config(api,account,tunnel))!=digest(new):raise RuntimeError("tunnel configuration did not converge")
def dns_records(api,zone):
    out=[]
    for h in PRODUCTION_HOSTS:
        r=api.request("GET",f"/zones/{zone}/dns_records?type=CNAME&name={h}")
        if not isinstance(r,list) or len(r)!=1:raise RuntimeError("production DNS authority is ambiguous")
        out.append(r[0])
    return out
def dns_tuple(r):return {k:r.get(k) for k in ("id","name","type","content","proxied","ttl")}
def check_dns(actual,bound,target):
    if [dns_tuple(x) for x in actual]!=bound:raise RuntimeError("production DNS record identity drift")
    if any(x["content"]!=target for x in bound):raise RuntimeError("production DNS target conflict")
def switch_dns(api,zone,bound,expected,target):
    check_dns(dns_records(api,zone),bound,expected);patches=[dict(r,id=r["id"],content=target) for r in bound]
    api.request("POST",f"/zones/{zone}/dns_records/batch",{"patches":patches});wanted=[dict(r,content=target) for r in bound];check_dns(dns_records(api,zone),wanted,target)
def rule_path(a):return f"/zones/{a.zone}/rulesets/{a.maintenance_ruleset}/rules/{a.maintenance_rule}"
def ruleset_path(a):return f"/zones/{a.zone}/rulesets/{a.maintenance_ruleset}"
def validate_ruleset(api,a):
    r=api.request("GET",ruleset_path(a))
    rules=r.get("rules") if isinstance(r,dict) else None
    if not isinstance(rules,list) or not rules or any(not isinstance(x,dict) or not isinstance(x.get("id"),str) for x in rules):raise RuntimeError("maintenance ruleset order is unknown")
    selected={"id":r.get("id"),"kind":r.get("kind"),"phase":r.get("phase"),"rule_order":[x["id"] for x in rules]}
    if selected["id"]!=a.maintenance_ruleset or selected["kind"]!="zone" or selected["phase"]!="http_request_firewall_custom" or selected["rule_order"][0]!=a.maintenance_rule or selected["rule_order"].count(a.maintenance_rule)!=1 or digest(selected)!=a.maintenance_ruleset_sha:raise RuntimeError("maintenance ruleset authority is unknown")
def expected_rule(a,enabled):
    probe=ipaddress.ip_address(a.probe_source_ip)
    if probe.version!=4 or str(probe)!=a.probe_source_ip:raise RuntimeError("probe source must be an exact IPv4 /32")
    expr=f'(http.host in {{"{PRODUCTION_HOSTS[0]}" "{PRODUCTION_HOSTS[1]}"}} and ip.src ne {probe})'
    return {"id":a.maintenance_rule,"action":"block","expression":expr,"description":"clixor-production-change-window","ref":"clixor-production-change-window","enabled":enabled}
def get_rule(api,a):
    r=api.request("GET",rule_path(a))
    if not isinstance(r,dict):raise RuntimeError("maintenance fence response is invalid")
    allowed={"id","version","action","expression","description","last_updated","ref","enabled"}
    if not set(r)<=allowed:raise RuntimeError("maintenance fence contains unreviewed behavior")
    return {k:r.get(k) for k in ("id","action","expression","description","ref","enabled")}
def set_rule(api,a,enabled,expected):
    if get_rule(api,a)!=expected:raise RuntimeError("maintenance fence authority is unknown")
    wanted=expected_rule(a,enabled);body={k:v for k,v in wanted.items() if k!="id"};api.request("PATCH",rule_path(a),body)
    if get_rule(api,a)!=wanted:raise RuntimeError("maintenance fence did not converge")
def write_state(path,state):
    path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    if os.geteuid()==0:os.chown(path.parent,0,0);os.chmod(path.parent,0o700);validate_parent_chain(path.parent,0)
    d=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);name=f".promotion.{os.getpid()}.{os.urandom(8).hex()}"
    try:
        f=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=d)
        try:
            raw=canonical(state)+b"\n";offset=0
            while offset<len(raw):offset+=os.write(f,raw[offset:])
            os.fchmod(f,0o400);os.fsync(f)
        finally:os.close(f)
        os.replace(name,path.name,src_dir_fd=d,dst_dir_fd=d);os.fsync(d)
    finally:
        try:os.unlink(name,dir_fd=d)
        except FileNotFoundError:pass
        os.close(d)
def read_state(path,expected_uid=0):
    v=json.loads(secure_read(path,expected_uid,0o400,1024*1024))
    if not isinstance(v,dict):raise RuntimeError("promotion journal is invalid")
    return v
def checkpoint(path,state,phase,direction=None):
    state["phase"]=phase
    if direction is not None:state["direction"]=direction
    write_state(path,state)
def mutate(path,state,before,after,fn,direction):checkpoint(path,state,before,direction);fn();checkpoint(path,state,after,direction)
def verify_public(revision):
    for n in range(12):
        try:
            q=f"?promotion={revision}-{n}";req=urllib.request.Request("https://clustr-api.atlanteanz.com/health/ready"+q,headers={"Cache-Control":"no-cache"})
            with urllib.request.urlopen(req,timeout=10) as r:ready=json.load(r);rh=r.headers.get("X-Clixor-Revision")
            req=urllib.request.Request("https://clixor.atlanteanz.com/.well-known/apple-app-site-association"+q,headers={"Cache-Control":"no-cache"})
            with urllib.request.urlopen(req,timeout=10) as r:assoc=json.load(r);ah=r.headers.get("X-Clixor-Revision")
            if ready=={"status":"ready","revision":revision} and rh==revision and assoc==ASSOCIATION and ah==revision:return
        except Exception:pass
        if n<11:time.sleep(5)
    raise RuntimeError("public exact revision did not converge")
AUTH_KEYS=("account","zone","change_window","revision","old_revision","old_tunnel","candidate_tunnel","old_target","candidate_target","old_config_sha","candidate_config_sha","evidence_sha","maintenance_ruleset","maintenance_ruleset_sha","maintenance_rule","maintenance_rule_sha","probe_source_ip","dns")
def authority(a):return {k:getattr(a,k) for k in AUTH_KEYS}
def validate_bound(a,s):
    if s.get("authority")!=authority(a):raise RuntimeError("existing journal authority mismatch")
    if s.get("schema")!=2 or s.get("direction") not in ("forward","rollback","terminal"):raise RuntimeError("existing journal state is invalid")
    old=s.get("old_config");candidate=s.get("candidate_config");live=s.get("candidate_live_config")
    exact_config(old,"old");exact_config(candidate,"candidate")
    if digest(old)!=a.old_config_sha or digest(candidate)!=a.candidate_config_sha or live!=candidate_live(candidate):raise RuntimeError("existing journal configuration binding mismatch")
def promote(api,a):
    if evidence_digest(a.evidence,a.revision)!=a.evidence_sha:raise RuntimeError("evidence digest mismatch")
    validate_ruleset(api,a)
    if a.state.exists() or a.state.is_symlink():
        s=read_state(a.state);validate_bound(a,s)
        return rollback_state(api,a,s) if s.get("direction")=="rollback" else forward(api,a,s)
    old=ingress_config(api,a.account,a.old_tunnel);candidate=ingress_config(api,a.account,a.candidate_tunnel);exact_config(old,"old");exact_config(candidate,"candidate")
    if digest(old)!=a.old_config_sha or digest(candidate)!=a.candidate_config_sha:raise RuntimeError("tunnel configuration digest conflict")
    check_dns(dns_records(api,a.zone),a.dns,a.old_target);disabled=expected_rule(a,False)
    if digest(disabled)!=a.maintenance_rule_sha or get_rule(api,a)!=disabled:raise RuntimeError("maintenance fence authority is unknown")
    s={"schema":2,"direction":"forward","phase":"prepared","authority":authority(a),"old_config":old,"candidate_config":candidate,"candidate_live_config":candidate_live(candidate)};write_state(a.state,s);return forward(api,a,s)
def forward(api,a,s):
    validate_ruleset(api,a)
    if s.get("direction")=="terminal":return verify_terminal(api,a,s)
    disabled,enabled=expected_rule(a,False),expected_rule(a,True);rule=get_rule(api,a)
    if rule==disabled:mutate(a.state,s,"before-maintenance-enable","after-maintenance-enable",lambda:set_rule(api,a,True,disabled),"forward")
    elif rule!=enabled:checkpoint(a.state,s,"unknown-maintenance-fence","forward");raise RuntimeError("maintenance fence authority is unknown")
    old,candidate,live=s["old_config"],s["candidate_config"],s["candidate_live_config"];oc=ingress_config(api,a.account,a.old_tunnel);cc=ingress_config(api,a.account,a.candidate_tunnel)
    if digest(oc)!=digest(old) or digest(cc) not in (digest(candidate),digest(live)):checkpoint(a.state,s,"ambiguous-tunnel-drift","forward");raise RuntimeError("tunnel authority drift; maintenance fence retained")
    records=dns_records(api,a.zone);targets={r.get("content") for r in records}
    if targets=={a.old_target}:mutate(a.state,s,"before-dns-candidate","after-dns-candidate",lambda:switch_dns(api,a.zone,a.dns,a.old_target,a.candidate_target),"forward")
    elif targets=={a.candidate_target}:check_dns(records,[dict(x,content=a.candidate_target) for x in a.dns],a.candidate_target)
    else:checkpoint(a.state,s,"ambiguous-dns","forward");raise RuntimeError("DNS is ambiguous; maintenance fence retained")
    cc=ingress_config(api,a.account,a.candidate_tunnel)
    if digest(cc)==digest(candidate):mutate(a.state,s,"before-candidate-live","after-candidate-live",lambda:set_config(api,a.account,a.candidate_tunnel,live,candidate),"forward")
    elif digest(cc)!=digest(live):checkpoint(a.state,s,"ambiguous-candidate","forward");raise RuntimeError("candidate drift; maintenance fence retained")
    checkpoint(a.state,s,"before-public-validation","forward");verify_public(a.revision);checkpoint(a.state,s,"after-public-validation","forward")
    if get_rule(api,a)!=enabled:checkpoint(a.state,s,"unknown-maintenance-fence","forward");raise RuntimeError("maintenance fence changed")
    mutate(a.state,s,"before-maintenance-disable","after-maintenance-disable",lambda:set_rule(api,a,False,enabled),"forward");checkpoint(a.state,s,"promoted","terminal")
def rollback(api,a):
    s=read_state(a.state);validate_bound(a,s);checkpoint(a.state,s,"rollback-requested","rollback");return rollback_state(api,a,s)
def rollback_state(api,a,s):
    validate_ruleset(api,a)
    if s.get("direction")=="terminal":return verify_terminal(api,a,s)
    disabled,enabled=expected_rule(a,False),expected_rule(a,True);rule=get_rule(api,a)
    if rule==disabled:mutate(a.state,s,"rollback-before-maintenance-enable","rollback-after-maintenance-enable",lambda:set_rule(api,a,True,disabled),"rollback")
    elif rule!=enabled:checkpoint(a.state,s,"rollback-unknown-maintenance-fence","rollback");raise RuntimeError("maintenance fence authority is unknown")
    old,candidate,live=s["old_config"],s["candidate_config"],s["candidate_live_config"]
    if digest(ingress_config(api,a.account,a.old_tunnel))!=digest(old):checkpoint(a.state,s,"rollback-ambiguous-old","rollback");raise RuntimeError("old tunnel drift; maintenance fence retained")
    cc=ingress_config(api,a.account,a.candidate_tunnel)
    if digest(cc)==digest(live):mutate(a.state,s,"rollback-before-candidate-canary","rollback-after-candidate-canary",lambda:set_config(api,a.account,a.candidate_tunnel,candidate,live),"rollback")
    elif digest(cc)!=digest(candidate):checkpoint(a.state,s,"rollback-ambiguous-candidate","rollback");raise RuntimeError("candidate drift; maintenance fence retained")
    records=dns_records(api,a.zone);targets={r.get("content") for r in records};candidate_dns=[dict(x,content=a.candidate_target) for x in a.dns]
    if targets=={a.candidate_target}:mutate(a.state,s,"rollback-before-dns-old","rollback-after-dns-old",lambda:switch_dns(api,a.zone,candidate_dns,a.candidate_target,a.old_target),"rollback")
    elif targets=={a.old_target}:check_dns(records,a.dns,a.old_target)
    else:checkpoint(a.state,s,"rollback-ambiguous-dns","rollback");raise RuntimeError("DNS drift; maintenance fence retained")
    checkpoint(a.state,s,"rollback-before-public-validation","rollback");verify_public(a.old_revision);checkpoint(a.state,s,"rollback-after-public-validation","rollback")
    if get_rule(api,a)!=enabled:checkpoint(a.state,s,"rollback-unknown-maintenance-fence","rollback");raise RuntimeError("maintenance fence changed")
    mutate(a.state,s,"rollback-before-maintenance-disable","rollback-after-maintenance-disable",lambda:set_rule(api,a,False,enabled),"rollback");checkpoint(a.state,s,"rolled-back","terminal")
def verify_terminal(api,a,s):
    if get_rule(api,a)!=expected_rule(a,False):raise RuntimeError("terminal maintenance fence authority drift")
    old,candidate,live=s["old_config"],s["candidate_config"],s["candidate_live_config"]
    if digest(ingress_config(api,a.account,a.old_tunnel))!=digest(old):raise RuntimeError("terminal old tunnel authority drift")
    phase=s.get("phase")
    if phase=="promoted":
        if digest(ingress_config(api,a.account,a.candidate_tunnel))!=digest(live):raise RuntimeError("terminal candidate authority drift")
        check_dns(dns_records(api,a.zone),[dict(x,content=a.candidate_target) for x in a.dns],a.candidate_target);verify_public(a.revision)
    elif phase=="rolled-back":
        if digest(ingress_config(api,a.account,a.candidate_tunnel))!=digest(candidate):raise RuntimeError("terminal candidate authority drift")
        check_dns(dns_records(api,a.zone),a.dns,a.old_target);verify_public(a.old_revision)
    else:raise RuntimeError("terminal journal phase is invalid")
def archive_terminal(api,a):
    s=read_state(a.state);validate_bound(a,s);validate_ruleset(api,a);verify_terminal(api,a,s)
    archive=a.state.parent/"cloudflare-promotion-archive"/(a.revision+"-"+hashlib.sha256(a.change_window.encode()).hexdigest()[:12]+".json")
    write_state(archive,s)
    d=os.open(a.state.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.unlink(a.state.name,dir_fd=d);os.fsync(d)
    finally:os.close(d)
def main():
    p=argparse.ArgumentParser();p.add_argument("mode",choices=("execute",));p.add_argument("--request-file",type=Path,default=Path("/run/credentials/clixor-cloudflare-promote.service/promotion-request"));p.add_argument("--token-file",type=Path,default=Path("/run/credentials/clixor-cloudflare-promote.service/cloudflare-control-token"));p.add_argument("--state",type=Path,default=Path("/var/lib/clixor/cloudflare-promotion.json"));x=p.parse_args()
    try:
        q=json.loads(secure_read(x.request_file,0,0o400,131072));required={"mode","evidence",*AUTH_KEYS}
        if not isinstance(q,dict) or set(q)!=required or q["mode"] not in ("promote","rollback","archive"):raise RuntimeError("promotion request inventory is not exact")
        a=argparse.Namespace(**q,state=x.state,token_file=x.token_file);a.evidence=Path(a.evidence)
        if any(HEX_ID.fullmatch(getattr(a,k)) is None for k in ("account","zone","maintenance_ruleset","maintenance_rule")):raise RuntimeError("Cloudflare IDs are invalid")
        if UUID.fullmatch(a.old_tunnel) is None or UUID.fullmatch(a.candidate_tunnel) is None or a.old_tunnel==a.candidate_tunnel:raise RuntimeError("tunnel IDs are invalid")
        if REVISION.fullmatch(a.revision) is None or REVISION.fullmatch(a.old_revision) is None:raise RuntimeError("revision is not an exact Git SHA")
        if any(SHA.fullmatch(getattr(a,k)) is None for k in ("old_config_sha","candidate_config_sha","evidence_sha","maintenance_ruleset_sha","maintenance_rule_sha")):raise RuntimeError("authority digest is invalid")
        if not isinstance(a.change_window,str) or re.fullmatch(r"FROZEN-[A-Z0-9._-]+",a.change_window) is None:raise RuntimeError("change window is not frozen")
        if a.old_target!=f"{a.old_tunnel}.cfargotunnel.com" or a.candidate_target!=f"{a.candidate_tunnel}.cfargotunnel.com":raise RuntimeError("DNS target does not bind tunnel")
        if not isinstance(a.dns,list) or len(a.dns)!=2:raise RuntimeError("DNS authority is invalid")
        x.state.parent.mkdir(parents=True,exist_ok=True,mode=0o700);lock=os.open(str(x.state)+".lock",os.O_WRONLY|os.O_CREAT|os.O_NOFOLLOW,0o600)
        try:
            fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB);api=API(read_token(x.token_file))
            (promote if a.mode=="promote" else rollback if a.mode=="rollback" else archive_terminal)(api,a)
        finally:os.close(lock)
    except Exception as e:print(f"promotion=failed reason={e}",file=sys.stderr);return 1
    print(f"promotion={a.mode}-complete revision={a.revision}");return 0
if __name__=="__main__":raise SystemExit(main())
