#!/usr/bin/env python3
"""One-way, crash-recoverable Cloudflare route ownership transfer to OCI.

The controller deliberately prefers a fenced outage to two writable origins. It
has no NAS rollback path: once the old route is retired, every retry rolls the
same reviewed transfer forward.
"""
from __future__ import annotations

import argparse
import copy
import fcntl
import hashlib
import http.client
import ipaddress
import json
import os
import re
import socket
import stat
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

PRODUCTION_HOSTS = ("clustr-api.atlanteanz.com", "clixor.atlanteanz.com")
CANARY_HOST = "clixor-oci-canary.atlanteanz.com"
ORIGIN = "unix:/run/clixor-origin/gateway.sock"
GATE_MARKER = "public-open"
GATE_CLOSED_BODY = b"clixor-origin-gate-closed\n"
ROOT_UID = 0
HEX_ID = re.compile(r"[0-9a-f]{32}")
UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
REVISION = re.compile(r"[0-9a-f]{40}")
SHA = re.compile(r"[0-9a-f]{64}")
ASSOCIATION = {"applinks":{"apps":[],"details":[{"appIDs":["H9S3BAQ9U8.com.Clustr.Clustr.Clustr"],"components":[{"/":"/join","comment":"Matches only the fixed Clixor invite landing path."}]}]}}

def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()

def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()

def validate_parent_chain(directory: Path, uid: int) -> None:
    if not directory.is_absolute():
        raise RuntimeError("authority path is invalid")
    current = Path("/")
    for part in directory.parts[1:]:
        current /= part
        metadata = current.lstat()
        if (stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid != uid or stat.S_IMODE(metadata.st_mode) & 0o022):
            raise RuntimeError("authority parent chain is unsafe")

def secure_read(path: Path, uid: int, mode: int, maximum: int) -> bytes:
    if not path.is_absolute() or path.name in ("", ".", ".."):
        raise RuntimeError("authority path is invalid")
    if uid == ROOT_UID:
        validate_parent_chain(path.parent, uid)
    directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        file_fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory_fd)
        try:
            metadata = os.fstat(file_fd)
            if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != uid
                    or stat.S_IMODE(metadata.st_mode) != mode or metadata.st_size > maximum):
                raise RuntimeError("authority file metadata is unsafe")
            result = b""
            while len(result) <= maximum:
                chunk = os.read(file_fd, min(65536, maximum + 1 - len(result)))
                if not chunk:
                    break
                result += chunk
            if len(result) > maximum:
                raise RuntimeError("authority file is oversized")
            return result
        finally:
            os.close(file_fd)
    finally:
        os.close(directory_fd)

def ensure_root_directory(path: Path, mode: int) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=mode)
    if os.geteuid() == 0:
        os.chown(path, ROOT_UID, ROOT_UID)
        os.chmod(path, mode)
        validate_parent_chain(path, ROOT_UID)

def atomic_write(path: Path, raw: bytes, mode: int, *, replace: bool = True) -> None:
    parent_mode = 0o755 if path.parent.name == "origin-gate-public" else 0o700
    ensure_root_directory(path.parent, parent_mode)
    directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    temporary = f".cloudflare-promote.{os.getpid()}.{os.urandom(8).hex()}"
    try:
        file_fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                          mode, dir_fd=directory_fd)
        try:
            offset = 0
            while offset < len(raw):
                offset += os.write(file_fd, raw[offset:])
            os.fchmod(file_fd, mode)
            if os.geteuid() == 0:
                os.fchown(file_fd, ROOT_UID, ROOT_UID)
            os.fsync(file_fd)
        finally:
            os.close(file_fd)
        if replace:
            os.replace(temporary, path.name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
        else:
            try:
                os.link(temporary, path.name, src_dir_fd=directory_fd,
                        dst_dir_fd=directory_fd, follow_symlinks=False)
            finally:
                os.unlink(temporary, dir_fd=directory_fd)
        os.fsync(directory_fd)
    finally:
        try:
            os.unlink(temporary, dir_fd=directory_fd)
        except FileNotFoundError:
            pass
        os.close(directory_fd)

def write_state(path: Path, state: dict[str, Any]) -> None:
    atomic_write(path, canonical(state) + b"\n", 0o400)

def read_state(path: Path, expected_uid: int | None = None) -> dict[str, Any]:
    if expected_uid is None:
        expected_uid = ROOT_UID
    value = json.loads(secure_read(path, expected_uid, 0o400, 1024 * 1024))
    if not isinstance(value, dict):
        raise RuntimeError("promotion journal is invalid")
    return value

def read_token(path: Path, expected_uid: int | None = None) -> bytes:
    if expected_uid is None:
        expected_uid = ROOT_UID
    value = secure_read(path, expected_uid, 0o400, 4096).strip()
    if not 20 <= len(value) <= 4096 or any(byte < 33 or byte > 126 for byte in value):
        raise RuntimeError("control credential is invalid")
    return value

def evidence_digest(path: Path, revision: str, expected_uid: int | None = None) -> str:
    if expected_uid is None:
        expected_uid = ROOT_UID
    raw = secure_read(path, expected_uid, 0o400, 65536)
    lines = raw.decode().splitlines()
    if (len(lines) != 3 or lines[0] != f"revision={revision}" or lines[1] != "stage=canary"
            or not lines[2].startswith("smoke=passed ")
            or not lines[2].endswith(" cleanup=passed")):
        raise RuntimeError("canary evidence does not authorize this revision")
    return hashlib.sha256(raw).hexdigest()

class API:
    def __init__(self, token: bytes, base: str = "https://api.cloudflare.com/client/v4"):
        self.token, self.base = token, base.rstrip("/")

    def request(self, method: str, path: str, body: Any = None) -> Any:
        request = urllib.request.Request(
            self.base + path, data=None if body is None else canonical(body), method=method,
            headers={"Authorization":"Bearer " + self.token.decode(), "Content-Type":"application/json"})
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

def production_rule(rule: Any, hostname: str) -> bool:
    return (isinstance(rule, dict) and rule.get("hostname") == hostname
            and set(rule) == {"hostname", "service"}
            and isinstance(rule.get("service"), str) and bool(rule["service"]))

def derive_retired_config(config: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(config, dict):
        raise RuntimeError("reviewed old tunnel configuration is invalid")
    ingress = config.get("ingress")
    if (not isinstance(ingress, list) or len(ingress) < 3
            or ingress[-1] != {"service":"http_status:404"}):
        raise RuntimeError("reviewed old tunnel catch-all is invalid")
    indexes: list[int] = []
    for hostname in PRODUCTION_HOSTS:
        matches = [i for i, rule in enumerate(ingress[:-1]) if production_rule(rule, hostname)]
        if len(matches) != 1:
            raise RuntimeError("reviewed old tunnel has ambiguous Clixor routes")
        indexes.extend(matches)
    for rule in ingress[:-1]:
        if not isinstance(rule, dict):
            raise RuntimeError("reviewed old tunnel contains an invalid route")
        hostname = rule.get("hostname")
        wildcard_covers_production = (
            isinstance(hostname, str)
            and hostname.startswith("*.")
            and any(production.endswith(hostname[1:]) for production in PRODUCTION_HOSTS)
        )
        if (not isinstance(hostname, str)
                or ((hostname in PRODUCTION_HOSTS or wildcard_covers_production)
                    and not any(production_rule(rule, host) for host in PRODUCTION_HOSTS))):
            raise RuntimeError("reviewed old tunnel has an ambiguous Clixor route")
    retired = copy.deepcopy(config)
    retired["ingress"] = [copy.deepcopy(rule) for i, rule in enumerate(ingress)
                          if i not in set(indexes)]
    return retired

def candidate_config() -> dict[str, Any]:
    return {"ingress":[{"hostname":CANARY_HOST,"service":ORIGIN},{"service":"http_status:404"}]}

def candidate_live_config() -> dict[str, Any]:
    return {"ingress":[{"hostname":CANARY_HOST,"service":ORIGIN},
                       *[{"hostname":host,"service":ORIGIN} for host in PRODUCTION_HOSTS],
                       {"service":"http_status:404"}]}

def set_config(api: API, account: str, tunnel: str, expected: dict[str, Any],
               wanted: dict[str, Any]) -> None:
    if ingress_config(api, account, tunnel) != expected:
        raise RuntimeError("concurrent tunnel configuration drift")
    api.request("PUT", f"/accounts/{account}/cfd_tunnel/{tunnel}/configurations",
                {"config":wanted})
    if ingress_config(api, account, tunnel) != wanted:
        raise RuntimeError("tunnel configuration did not converge")

def dns_records(api: API, zone: str) -> list[dict[str, Any]]:
    records = []
    for hostname in PRODUCTION_HOSTS:
        query = urllib.parse.urlencode({"type":"CNAME","name":hostname})
        result = api.request("GET", f"/zones/{zone}/dns_records?{query}")
        if not isinstance(result, list) or len(result) != 1:
            raise RuntimeError("production DNS authority is ambiguous")
        records.append(result[0])
    return records

def dns_tuple(record: dict[str, Any]) -> dict[str, Any]:
    return {key:record.get(key) for key in ("id","name","type","content","proxied","ttl")}

def validate_dns_authority(bound: Any, old_target: str) -> None:
    if not isinstance(bound, list) or len(bound) != len(PRODUCTION_HOSTS):
        raise RuntimeError("DNS authority is invalid")
    for index, (record, hostname) in enumerate(zip(bound, PRODUCTION_HOSTS)):
        if (not isinstance(record, dict) or set(record) != {"id","name","type","content","proxied","ttl"}
                or HEX_ID.fullmatch(str(record["id"])) is None or record["name"] != hostname
                or record["type"] != "CNAME" or record["content"] != old_target
                or record["proxied"] is not True or record["ttl"] != 1):
            raise RuntimeError(f"DNS authority record {index} is not exact and proxied")

def expected_dns(bound: list[dict[str, Any]], target: str) -> list[dict[str, Any]]:
    return [dict(record, content=target) for record in bound]

def check_dns(actual: list[dict[str, Any]], bound: list[dict[str, Any]], target: str) -> None:
    if [dns_tuple(record) for record in actual] != expected_dns(bound, target):
        raise RuntimeError("production DNS record identity or value drift")

def switch_dns(api: API, zone: str, bound: list[dict[str, Any]], expected_target: str,
               wanted_target: str) -> None:
    check_dns(dns_records(api, zone), bound, expected_target)
    patches = [dict(record, content=wanted_target) for record in bound]
    api.request("POST", f"/zones/{zone}/dns_records/batch", {"patches":patches})
    check_dns(dns_records(api, zone), bound, wanted_target)

def ruleset_path(options: argparse.Namespace) -> str:
    return f"/zones/{options.zone}/rulesets/{options.maintenance_ruleset}"

def rule_path(options: argparse.Namespace) -> str:
    return ruleset_path(options) + f"/rules/{options.maintenance_rule}"

def host_expression() -> str:
    return f'(http.host in {{"{PRODUCTION_HOSTS[0]}" "{PRODUCTION_HOSTS[1]}"}})'

def expected_rule(options: argparse.Namespace, state: str) -> dict[str, Any]:
    probe = ipaddress.ip_address(options.probe_source_ip)
    if probe.version != 4 or str(probe) != options.probe_source_ip:
        raise RuntimeError("probe source must be an exact IPv4 /32")
    expression, enabled = host_expression(), True
    if state in ("exception", "disabled"):
        expression = expression[:-1] + f" and ip.src ne {probe})"
    if state == "disabled":
        enabled = False
    if state not in ("block-all", "exception", "disabled"):
        raise RuntimeError("maintenance rule state is invalid")
    return {"id":options.maintenance_rule,"action":"block","expression":expression,
            "description":"clixor-production-change-window",
            "ref":"clixor-production-change-window","enabled":enabled}

RULE_DYNAMIC_FIELDS = {"version", "last_updated"}
RULE_ALLOWED_FIELDS = {"id","version","action","expression","description","last_updated","ref","enabled"}

def rule_projection(rule: Any) -> dict[str, Any]:
    if not isinstance(rule, dict) or not set(rule) <= RULE_ALLOWED_FIELDS:
        raise RuntimeError("maintenance rule response is invalid")
    return {key:rule.get(key) for key in ("id","action","expression","description","ref","enabled")}

def strip_dynamic(value: Any) -> Any:
    if isinstance(value, dict):
        return {key:strip_dynamic(item) for key, item in value.items()
                if key not in RULE_DYNAMIC_FIELDS}
    if isinstance(value, list):
        return [strip_dynamic(item) for item in value]
    return value

def validate_ruleset_document(document: Any, options: argparse.Namespace,
                              expected_state: str | None = None) -> tuple[dict[str, Any],dict[str, Any]]:
    if not isinstance(document, dict):
        raise RuntimeError("maintenance ruleset response is invalid")
    rules = document.get("rules")
    if (document.get("id") != options.maintenance_ruleset or document.get("kind") != "zone"
            or document.get("phase") != "http_request_firewall_custom" or not isinstance(rules, list)
            or not rules or any(not isinstance(rule, dict) or not isinstance(rule.get("id"), str)
                                for rule in rules)):
        raise RuntimeError("maintenance ruleset authority is unknown")
    rule_ids = [rule["id"] for rule in rules]
    if (len(set(rule_ids)) != len(rule_ids) or rule_ids[0] != options.maintenance_rule
            or rule_ids.count(options.maintenance_rule) != 1):
        raise RuntimeError("maintenance rule is not uniquely first")
    selected = rule_projection(rules[0])
    allowed = {state:expected_rule(options, state) for state in ("disabled","block-all","exception")}
    if expected_state is not None and selected != allowed[expected_state]:
        raise RuntimeError("maintenance rule state is unknown")
    if selected not in allowed.values():
        raise RuntimeError("maintenance rule behavior is unknown")
    baseline = strip_dynamic(copy.deepcopy(document))
    baseline["rules"][0] = allowed["disabled"]
    if digest(baseline) != options.maintenance_ruleset_sha:
        raise RuntimeError("maintenance ruleset authority or order is unknown")
    return selected, document

def read_ruleset(api: API, options: argparse.Namespace,
                 expected_state: str | None = None) -> tuple[dict[str,Any],dict[str,Any]]:
    # Cloudflare provides a full-ruleset GET, not an individual-rule GET.
    return validate_ruleset_document(api.request("GET", ruleset_path(options)), options, expected_state)

def set_rule_state(api: API, options: argparse.Namespace, before: str, after: str) -> None:
    read_ruleset(api, options, before)
    wanted = expected_rule(options, after)
    body = {key:value for key, value in wanted.items() if key != "id"}
    # PATCHing one rule returns the complete updated ruleset.
    response = api.request("PATCH", rule_path(options), body)
    validate_ruleset_document(response, options, after)
    read_ruleset(api, options, after)

def checkpoint(path: Path, state: dict[str,Any], phase: str, operation: str | None = None) -> None:
    state["phase"] = phase
    if operation is not None:
        state.setdefault("write_history", []).append(operation)
    write_state(path, state)

def mutate(path: Path, state: dict[str,Any], name: str, function: Any) -> None:
    checkpoint(path, state, f"before-{name}", f"before:{name}")
    function()
    checkpoint(path, state, f"after-{name}", f"after:{name}")

def reconcile_completed_mutation(path: Path, state: dict[str,Any], name: str) -> None:
    """Durably close a before-write record after exact remote/local reread."""
    history = state.get("write_history", [])
    if f"before:{name}" in history and f"after:{name}" not in history:
        checkpoint(path, state, f"after-{name}", f"after:{name}")

def marker_state(gate_directory: Path) -> str:
    marker = gate_directory / GATE_MARKER
    try:
        metadata = marker.lstat()
    except FileNotFoundError:
        return "closed"
    if (stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != ROOT_UID or stat.S_IMODE(metadata.st_mode) != 0o400
            or metadata.st_size != 0):
        raise RuntimeError("origin gate capability metadata is unsafe")
    return "open"

def validate_gate_directory(path: Path) -> None:
    metadata = path.lstat()
    if (stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != ROOT_UID or stat.S_IMODE(metadata.st_mode) != 0o755):
        raise RuntimeError("origin gate directory is unsafe")

def initialize_gate(gate_directory: Path, gate_state: Path) -> None:
    ensure_root_directory(gate_directory, 0o755)
    validate_gate_directory(gate_directory)
    actual = marker_state(gate_directory)
    if gate_state.exists() or gate_state.is_symlink():
        journal = read_state(gate_state)
        if (journal.get("schema") != 1 or journal.get("transition") != "stable"
                or journal.get("state") != actual):
            raise RuntimeError("existing origin gate journal is inconsistent")
        return
    if actual != "closed":
        raise RuntimeError("unbound open origin gate is unsafe")
    write_state(gate_state, {"schema":1,"transition":"stable","state":"closed",
                             "authority_sha":"bootstrap"})

def validate_gate_journal(options: argparse.Namespace, wanted: str,
                          *, require_current_authority: bool) -> None:
    journal = read_state(options.gate_state)
    expected_authority = digest(authority(options))
    if (journal.get("schema") != 1 or journal.get("transition") != "stable"
            or journal.get("state") != wanted
            or (require_current_authority and journal.get("authority_sha") != expected_authority)):
        raise RuntimeError("origin gate journal is inconsistent with its capability")

def local_request(hostname: str, path: str) -> tuple[int,dict[str,str],bytes]:
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    connection.settimeout(5)
    connection.connect("/run/clixor-origin/gateway.sock")
    connection.sendall(f"GET {path} HTTP/1.1\r\nHost: {hostname}\r\nConnection: close\r\n\r\n".encode())
    response = http.client.HTTPResponse(connection)
    response.begin()
    body = response.read(1024 * 1024)
    headers = {key.lower():value for key, value in response.getheaders()}
    status = response.status
    connection.close()
    return status, headers, body

def verify_local_gate(options: argparse.Namespace, wanted: str) -> None:
    last: Exception | None = None
    for attempt in range(20):
        try:
            status, headers, body = local_request(PRODUCTION_HOSTS[0], "/health/ready")
            cs, ch, cb = local_request(CANARY_HOST, "/health/ready")
            expected = {"status":"ready","revision":options.revision}
            if cs != 200 or json.loads(cb) != expected or ch.get("x-clixor-revision") != options.revision:
                raise RuntimeError("canary was not usable through the local gate")
            if wanted == "closed":
                if status != 503 or body != GATE_CLOSED_BODY:
                    raise RuntimeError("production origin gate is not closed")
            elif (status != 200 or json.loads(body) != expected
                  or headers.get("x-clixor-revision") != options.revision):
                raise RuntimeError("production origin gate is not open on the exact revision")
            return
        except Exception as error:
            last = error
            if attempt < 19:
                time.sleep(0.25)
    raise RuntimeError(f"origin gate did not converge: {last}")

def set_gate(options: argparse.Namespace, wanted: str) -> None:
    if wanted not in ("closed", "open"):
        raise RuntimeError("origin gate state is invalid")
    validate_gate_directory(options.gate_directory)
    current = marker_state(options.gate_directory)
    authority_sha = digest(authority(options))
    if current != wanted:
        write_state(options.gate_state, {"schema":1,"transition":"opening" if wanted == "open" else "closing",
                                        "state":current,"wanted":wanted,"authority_sha":authority_sha})
        directory_fd = os.open(options.gate_directory,
                               os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            if wanted == "open":
                file_fd = os.open(GATE_MARKER, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                  0o400, dir_fd=directory_fd)
                try:
                    if os.geteuid() == 0:
                        os.fchown(file_fd, ROOT_UID, ROOT_UID)
                    os.fchmod(file_fd, 0o400)
                    os.fsync(file_fd)
                finally:
                    os.close(file_fd)
            else:
                os.unlink(GATE_MARKER, dir_fd=directory_fd)
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    verify_local_gate(options, wanted)
    write_state(options.gate_state, {"schema":1,"transition":"stable","state":wanted,
                                     "authority_sha":authority_sha})

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

def public_request(url: str) -> tuple[int,dict[str,str],bytes]:
    request = urllib.request.Request(url, headers={"Cache-Control":"no-cache"})
    try:
        response = urllib.request.build_opener(NoRedirect).open(request, timeout=10)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        return response.status, {key.lower():value for key,value in response.headers.items()}, response.read(1024*1024)

def require_cloudflare(headers: dict[str,str]) -> None:
    if "cloudflare" not in headers.get("server", "").lower() or not headers.get("cf-ray"):
        raise RuntimeError("public probe did not traverse Cloudflare")

def verify_edge_blocked(revision: str) -> None:
    for attempt in range(12):
        status, headers, _ = public_request(
            f"https://{PRODUCTION_HOSTS[0]}/health/ready?promotion={revision}-block-{attempt}")
        if status == 403:
            require_cloudflare(headers)
            return
        if attempt < 11:
            time.sleep(5)
    raise RuntimeError("Cloudflare block-all rule did not reach the OCI probe edge")

def verify_edge_reaches_closed_gate(revision: str) -> None:
    for attempt in range(12):
        status, headers, body = public_request(
            f"https://{PRODUCTION_HOSTS[0]}/health/ready?promotion={revision}-gate-{attempt}")
        if status == 503 and body == GATE_CLOSED_BODY:
            require_cloudflare(headers)
            return
        if attempt < 11:
            time.sleep(5)
    raise RuntimeError("Cloudflare OCI /32 exception did not reach the closed origin gate")

def verify_public(revision: str) -> None:
    for attempt in range(12):
        try:
            status, headers, body = public_request(
                f"https://{PRODUCTION_HOSTS[0]}/health/ready?promotion={revision}-ready-{attempt}")
            status_aasa, headers_aasa, body_aasa = public_request(
                f"https://{PRODUCTION_HOSTS[1]}/.well-known/apple-app-site-association?promotion={revision}-aasa-{attempt}")
            require_cloudflare(headers); require_cloudflare(headers_aasa)
            if (status == 200 and status_aasa == 200
                    and json.loads(body) == {"status":"ready","revision":revision}
                    and json.loads(body_aasa) == ASSOCIATION
                    and headers.get("x-clixor-revision") == revision
                    and headers_aasa.get("x-clixor-revision") == revision):
                return
        except Exception:
            pass
        if attempt < 11:
            time.sleep(5)
    raise RuntimeError("public exact revision did not converge without redirects")

AUTH_KEYS = ("account","zone","change_window","revision","old_tunnel","candidate_tunnel",
             "old_target","candidate_target","old_config","old_retired_config","candidate_config",
             "candidate_live_config","evidence_sha","maintenance_ruleset","maintenance_ruleset_sha",
             "maintenance_rule","maintenance_rule_sha","probe_source_ip","dns")

def authority(options: argparse.Namespace) -> dict[str,Any]:
    return {key:getattr(options, key) for key in AUTH_KEYS}

def validate_request(options: argparse.Namespace) -> None:
    if any(HEX_ID.fullmatch(getattr(options,key)) is None
           for key in ("account","zone","maintenance_ruleset","maintenance_rule")):
        raise RuntimeError("Cloudflare IDs are invalid")
    if (UUID.fullmatch(options.old_tunnel) is None or UUID.fullmatch(options.candidate_tunnel) is None
            or options.old_tunnel == options.candidate_tunnel):
        raise RuntimeError("tunnel IDs are invalid")
    if REVISION.fullmatch(options.revision) is None:
        raise RuntimeError("revision is not an exact Git SHA")
    if any(SHA.fullmatch(getattr(options,key)) is None
           for key in ("evidence_sha","maintenance_ruleset_sha","maintenance_rule_sha")):
        raise RuntimeError("authority digest is invalid")
    if (not isinstance(options.change_window, str)
            or re.fullmatch(r"FROZEN-[A-Z0-9._-]+", options.change_window) is None):
        raise RuntimeError("change window is not frozen")
    if (options.old_target != f"{options.old_tunnel}.cfargotunnel.com"
            or options.candidate_target != f"{options.candidate_tunnel}.cfargotunnel.com"):
        raise RuntimeError("DNS target does not bind its tunnel")
    if options.old_retired_config != derive_retired_config(options.old_config):
        raise RuntimeError("reviewed retired old tunnel does not preserve unrelated routes")
    if options.candidate_config != candidate_config() or options.candidate_live_config != candidate_live_config():
        raise RuntimeError("candidate tunnel configuration is not exact")
    validate_dns_authority(options.dns, options.old_target)
    if digest(expected_rule(options, "disabled")) != options.maintenance_rule_sha:
        raise RuntimeError("maintenance rule authority digest is invalid")

def validate_bound(options: argparse.Namespace, state: dict[str,Any]) -> None:
    if state.get("schema") != 3 or state.get("direction") != "forward-only":
        raise RuntimeError("existing journal state is invalid")
    if state.get("authority") != authority(options):
        raise RuntimeError("existing journal authority mismatch")
    history = state.get("write_history")
    if not isinstance(history, list) or any(not isinstance(item,str) for item in history):
        raise RuntimeError("existing journal write history is invalid")

def topology(api: API, options: argparse.Namespace) -> tuple[dict[str,Any],dict[str,Any],list[dict[str,Any]]]:
    return (ingress_config(api, options.account, options.old_tunnel),
            ingress_config(api, options.account, options.candidate_tunnel),
            dns_records(api, options.zone))

def validate_final_authority(api: API, options: argparse.Namespace, rule_state: str,
                             gate: str) -> None:
    read_ruleset(api, options, rule_state)
    old, candidate, records = topology(api, options)
    if old != options.old_retired_config:
        raise RuntimeError("old tunnel is not exactly retired")
    if candidate != options.candidate_live_config:
        raise RuntimeError("candidate tunnel is not exactly live")
    check_dns(records, options.dns, options.candidate_target)
    if marker_state(options.gate_directory) != gate:
        raise RuntimeError("local origin gate authority drift")
    validate_gate_journal(options, gate, require_current_authority=True)
    verify_local_gate(options, gate)

def prepare(api: API, options: argparse.Namespace) -> dict[str,Any]:
    rule, _ = read_ruleset(api, options, "disabled")
    if digest(rule) != options.maintenance_rule_sha:
        raise RuntimeError("maintenance rule authority is unknown")
    old, candidate, records = topology(api, options)
    if old != options.old_config:
        raise RuntimeError("live old tunnel differs from the reviewed configuration")
    if candidate != options.candidate_config:
        raise RuntimeError("live candidate tunnel differs from the reviewed configuration")
    check_dns(records, options.dns, options.old_target)
    validate_gate_directory(options.gate_directory)
    initial_gate = marker_state(options.gate_directory)
    validate_gate_journal(options, initial_gate, require_current_authority=False)
    state = {"schema":3,"direction":"forward-only","phase":"prepared",
             "authority":authority(options),"write_history":[]}
    write_state(options.state, state)
    return state

def finish_after_unfreeze(api: API, options: argparse.Namespace, state: dict[str,Any]) -> None:
    validate_final_authority(api, options, "disabled", "open")
    verify_public(options.revision)
    reconcile_completed_mutation(options.state, state, "waf-disable")
    if state.get("phase") != "after-waf-disable":
        checkpoint(options.state, state, "after-waf-disable")
    checkpoint(options.state, state, "promoted", "terminal:promoted")

def forward(api: API, options: argparse.Namespace, state: dict[str,Any]) -> None:
    validate_bound(options, state)
    if state.get("phase") == "promoted":
        validate_final_authority(api, options, "disabled", "open")
        verify_public(options.revision)
        return
    rule, _ = read_ruleset(api, options)
    if rule == expected_rule(options, "disabled"):
        if state.get("phase") in ("before-waf-disable", "after-waf-disable"):
            finish_after_unfreeze(api, options, state)
            return
        if state.get("phase") not in ("prepared", "before-waf-block-all"):
            if marker_state(options.gate_directory) == "open":
                set_gate(options, "closed")
            raise RuntimeError("maintenance fence was disabled before final unfreeze")
        mutate(options.state, state, "waf-block-all",
               lambda:set_rule_state(api, options, "disabled", "block-all"))
        rule = expected_rule(options, "block-all")
    late_open_phases = {
        "before-origin-gate-open", "after-origin-gate-open",
        "before-public-validation", "after-public-validation",
        "before-waf-disable",
    }
    gate_open_resume = (
        rule == expected_rule(options, "exception")
        and marker_state(options.gate_directory) == "open"
        and state.get("phase") in late_open_phases
    )
    if gate_open_resume:
        # A SIGKILL can leave the capability durable while its independent
        # journal still says "opening". Reconcile that local transition only;
        # no Cloudflare write or fresh close is permitted here.
        set_gate(options, "open")
        reconcile_completed_mutation(options.state, state, "origin-gate-open")
        validate_final_authority(api, options, "exception", "open")
    if marker_state(options.gate_directory) == "open" and not gate_open_resume \
            and rule != expected_rule(options, "block-all"):
        set_gate(options, "closed")
        raise RuntimeError("production origin gate opened before final authority was journaled")
    if rule == expected_rule(options, "block-all"):
        reconcile_completed_mutation(options.state, state, "waf-block-all")
        checkpoint(options.state, state, "before-block-all-probe")
        verify_edge_blocked(options.revision)
        checkpoint(options.state, state, "after-block-all-probe")
        if marker_state(options.gate_directory) != "closed":
            mutate(options.state, state, "origin-gate-close", lambda:set_gate(options, "closed"))
        else:
            set_gate(options, "closed")
            reconcile_completed_mutation(options.state, state, "origin-gate-close")
            if state.get("phase") != "after-origin-gate-close":
                checkpoint(options.state, state, "after-origin-gate-close")
    elif rule != expected_rule(options, "exception"):
        raise RuntimeError("maintenance fence behavior is unknown")
    if marker_state(options.gate_directory) != "closed" and not gate_open_resume:
        raise RuntimeError("production origin gate opened before topology transfer")
    old, candidate, records = topology(api, options)
    if old not in (options.old_config, options.old_retired_config):
        raise RuntimeError("old tunnel authority drift; origin gate retained")
    if old == options.old_config and candidate == options.candidate_live_config:
        raise RuntimeError("dual production tunnel authority is forbidden; origin gate retained")
    # There is intentionally a maintenance gap: retire old Clixor authority
    # before creating it on OCI. At no durable or remote-write boundary may
    # both tunnels serve the production hostnames.
    if old == options.old_config:
        mutate(options.state, state, "old-tunnel-retire",
               lambda:set_config(api, options.account, options.old_tunnel,
                                 options.old_config, options.old_retired_config))
    else:
        reconcile_completed_mutation(options.state, state, "old-tunnel-retire")
    if candidate == options.candidate_config:
        mutate(options.state, state, "candidate-live",
               lambda:set_config(api, options.account, options.candidate_tunnel,
                                 options.candidate_config, options.candidate_live_config))
    elif candidate != options.candidate_live_config:
        raise RuntimeError("candidate tunnel authority drift; origin gate retained")
    else:
        reconcile_completed_mutation(options.state, state, "candidate-live")
    targets = {record.get("content") for record in records}
    if targets == {options.old_target}:
        mutate(options.state, state, "dns-candidate",
               lambda:switch_dns(api, options.zone, options.dns,
                                 options.old_target, options.candidate_target))
    elif targets == {options.candidate_target}:
        check_dns(records, options.dns, options.candidate_target)
        reconcile_completed_mutation(options.state, state, "dns-candidate")
    else:
        raise RuntimeError("DNS is ambiguous; origin gate retained")
    rule, _ = read_ruleset(api, options)
    if rule == expected_rule(options, "block-all"):
        mutate(options.state, state, "waf-oci-exception",
               lambda:set_rule_state(api, options, "block-all", "exception"))
    elif rule != expected_rule(options, "exception"):
        raise RuntimeError("maintenance fence changed during transfer")
    else:
        reconcile_completed_mutation(options.state, state, "waf-oci-exception")
    if not gate_open_resume:
        checkpoint(options.state, state, "before-closed-edge-probe")
        verify_edge_reaches_closed_gate(options.revision)
        checkpoint(options.state, state, "after-closed-edge-probe")
        validate_final_authority(api, options, "exception", "closed")
        mutate(options.state, state, "origin-gate-open", lambda:set_gate(options, "open"))
    else:
        validate_final_authority(api, options, "exception", "open")
    checkpoint(options.state, state, "before-public-validation")
    verify_public(options.revision)
    checkpoint(options.state, state, "after-public-validation")
    # Exact final rule/order, both tunnels, both DNS tuples and local capability immediately before unfreeze.
    validate_final_authority(api, options, "exception", "open")
    mutate(options.state, state, "waf-disable",
           lambda:set_rule_state(api, options, "exception", "disabled"))
    checkpoint(options.state, state, "promoted", "terminal:promoted")

def promote(api: API, options: argparse.Namespace) -> None:
    if evidence_digest(options.evidence, options.revision) != options.evidence_sha:
        raise RuntimeError("evidence digest mismatch")
    validate_request(options)
    if options.state.exists() or options.state.is_symlink():
        state = read_state(options.state); validate_bound(options, state)
    else:
        state = prepare(api, options)
    try:
        forward(api, options, state)
    except BaseException:
        # Before the durable unfreeze checkpoint, an unknown late control-plane
        # read must not leave OCI locally serving production. The special
        # before-waf-disable phase may mean the disable already committed; never
        # close or re-enable there, because that would manufacture a new outage.
        if (state.get("phase") not in ("before-waf-disable", "after-waf-disable", "promoted")
                and marker_state(options.gate_directory) == "open"):
            try:
                set_gate(options, "closed")
            except Exception:
                # Marker removal is fsynced before local validation; preserve the
                # original exception while remaining fail-closed.
                pass
        raise

def archive_path(options: argparse.Namespace) -> Path:
    return (options.state.parent / "cloudflare-promotion-archive"
            / f"{options.revision}-{digest(authority(options))}.json")

def archive_terminal(api: API, options: argparse.Namespace) -> None:
    if evidence_digest(options.evidence, options.revision) != options.evidence_sha:
        raise RuntimeError("evidence digest mismatch")
    path = archive_path(options)
    if options.state.exists() or options.state.is_symlink():
        state = read_state(options.state); validate_bound(options, state)
        if state.get("phase") != "promoted":
            raise RuntimeError("only a terminal transfer can be archived")
        validate_final_authority(api, options, "disabled", "open"); verify_public(options.revision)
        raw = canonical(state) + b"\n"
        try:
            atomic_write(path, raw, 0o400, replace=False)
        except FileExistsError:
            if secure_read(path, ROOT_UID, 0o400, 1024*1024) != raw:
                raise RuntimeError("archive collision does not match terminal authority")
        directory_fd = os.open(options.state.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.unlink(options.state.name, dir_fd=directory_fd); os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        return
    state = read_state(path); validate_bound(options, state)
    if state.get("phase") != "promoted":
        raise RuntimeError("archive is not terminal")
    validate_final_authority(api, options, "disabled", "open"); verify_public(options.revision)

def parse_request(request_file: Path, token_file: Path, state: Path,
                  gate_directory: Path, gate_state: Path) -> tuple[argparse.Namespace,API]:
    request = json.loads(secure_read(request_file, ROOT_UID, 0o400, 512*1024))
    required = {"mode","evidence",*AUTH_KEYS}
    if (not isinstance(request, dict) or set(request) != required
            or request["mode"] not in ("promote","archive")):
        raise RuntimeError("promotion request inventory is not exact")
    options = argparse.Namespace(**request, state=state, token_file=token_file,
                                 gate_directory=gate_directory, gate_state=gate_state)
    options.evidence = Path(options.evidence)
    validate_request(options)
    return options, API(read_token(token_file))

def acquire_lock(path: Path) -> int:
    ensure_root_directory(path.parent, 0o700)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except Exception:
        os.close(descriptor); raise
    return descriptor

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("execute","initialize-gate"))
    parser.add_argument("--request-file", type=Path,
                        default=Path("/run/credentials/clixor-cloudflare-promote.service/promotion-request"))
    parser.add_argument("--token-file", type=Path,
                        default=Path("/run/credentials/clixor-cloudflare-promote.service/cloudflare-control-token"))
    parser.add_argument("--state", type=Path, default=Path("/var/lib/clixor/cloudflare-promotion.json"))
    parser.add_argument("--gate-directory", type=Path,
                        default=Path("/var/lib/clixor/origin-gate-public"))
    parser.add_argument("--gate-state", type=Path,
                        default=Path("/var/lib/clixor/cloudflare-origin-gate.json"))
    arguments = parser.parse_args()
    try:
        if os.geteuid() != 0:
            raise RuntimeError("promotion controller must run as root")
        if arguments.mode == "initialize-gate":
            initialize_gate(arguments.gate_directory, arguments.gate_state)
            print("origin-gate=initialized"); return 0
        options, api = parse_request(arguments.request_file, arguments.token_file,
                                     arguments.state, arguments.gate_directory, arguments.gate_state)
        lock = acquire_lock(Path(str(arguments.state) + ".lock"))
        try:
            (promote if options.mode == "promote" else archive_terminal)(api, options)
        finally:
            os.close(lock)
    except Exception as error:
        print(f"promotion=failed reason={error}", file=sys.stderr); return 1
    print(f"promotion={options.mode}-complete revision={options.revision}"); return 0

if __name__ == "__main__":
    raise SystemExit(main())
