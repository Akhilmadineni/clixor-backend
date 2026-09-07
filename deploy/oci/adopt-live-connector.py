#!/usr/bin/env python3
"""Operator-only, source-authenticated adoption of existing live OCI ingress.

Never changes a Cloudflare resource, service state, application data, or secrets.
Publishes a release-bound recovery extension and backward-compatible stable
controller files. Interrupted runs retain the original immutable bundle and can
resume using the exact same source revision. The watchdog must remain paused
until validation and the subsequent ordinary deployment have completed.
"""
from __future__ import annotations

import argparse
import fcntl
import importlib.util
import json
import os
import stat
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

sys.dont_write_bytecode = True
import live_connector as live
import runtime_bundle

ROOT = Path('/srv/clixor')
STABLE = Path('/usr/local/libexec/clixor')


def run(*args):
    result = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, timeout=120, check=False)
    if result.returncode:
        raise RuntimeError('adoption prerequisite command failed: ' + args[0])
    return result.stdout


def atomic(path, raw, mode):
    fd, name = tempfile.mkstemp(prefix='.live-adopt-', dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, 'wb') as out:
            out.write(raw)
            out.flush()
            os.fsync(out.fileno())
        os.replace(name, path)
        fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        if os.path.exists(name):
            os.unlink(name)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        raise RuntimeError('public adoption proof must not redirect')


def public_proof(revision):
    opener = urllib.request.build_opener(NoRedirect())
    result = {}
    for host in (live.CANARY, *live.PRODUCTION_HOSTS):
        request = urllib.request.Request('https://' + host + '/health/ready',
                                        headers={'Cache-Control': 'no-cache'})
        with opener.open(request, timeout=15) as response:
            body = response.read(65537)
            if response.status != 200 or len(body) > 65536:
                raise RuntimeError('public adoption readiness failed')
            value = json.loads(body, object_pairs_hook=live._pairs)
            if value.get('status') != 'ready' or value.get('revision') != revision:
                raise RuntimeError('public hostname is not serving the selected revision')
            result[host] = live.digest(body)
    return result


def adopt(source, source_sha, git_dir, baseline, config_version, apply):
    if os.geteuid() != 0:
        raise RuntimeError('adoption must run as root')
    runtime_bundle.validate_approved_source(source, source_sha, git_dir)
    selected = ROOT / 'releases/current'
    if not selected.is_symlink() or selected.resolve() != baseline:
        raise RuntimeError('selected baseline changed')
    if baseline.parent != ROOT / 'releases' or baseline.is_symlink():
        raise RuntimeError('baseline is not an immediate immutable release')
    lock_path = ROOT / 'runtime/deploy.lock'
    info = lock_path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
            or stat.S_IMODE(info.st_mode) != 0o600):
        raise RuntimeError('deployment lock is unsafe')
    with lock_path.open('r+') as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        return adopt_locked(source, source_sha, baseline, config_version, apply)


def adopt_locked(source, source_sha, baseline, config_version, apply):
    for path in (Path('/var/lib/clixor/cloudflare-promotion.json'),
                 ROOT / 'runtime/deploy-transaction.json',
                 Path('/var/lib/clixor/cloudflare-topology-authority.json')):
        if path.exists() or path.is_symlink():
            raise RuntimeError('an existing deployment or topology authority requires its own recovery')
    if run('/usr/bin/systemctl', 'is-active', 'cloudflared.service').strip() != b'active':
        raise RuntimeError('cannot adopt an inactive connector')
    watchdog = subprocess.run(['/usr/bin/systemctl', 'is-active', '--quiet',
                               'clixor-runtime-watchdog.timer'], check=False)
    if watchdog.returncode == 0:
        raise RuntimeError('pause the watchdog before the operator adoption')
    # Validate current baseline using the already installed controller as well
    # as the candidate validator. No release file is changed by either check.
    run('/usr/bin/python3', str(STABLE / 'runtime-reconciler.py'), 'validate-release',
        '--release', str(baseline))
    manifest = runtime_bundle.validate_runtime_bundle(baseline)
    if live.read(baseline / 'secret-mode') != b'staging\n':
        raise RuntimeError('adoption is restricted to an existing staging pilot')
    if manifest['state']['cloudflared'] != {'enabled': True, 'active': True}:
        raise RuntimeError('baseline does not own an enabled connector')
    if live.read(live.GATE, mode=0o600) != b'':
        raise RuntimeError('production gate must already be open')
    revision = manifest['source_sha']
    for replica in ('clixor-oci-api-a', 'clixor-oci-api-b'):
        image = run('/usr/bin/docker', 'inspect', replica, '--format', '{{.Image}}').strip().decode()
        if image != manifest['image']['id']:
            raise RuntimeError('live replica differs from selected immutable image')
    spec = importlib.util.spec_from_file_location('adoption_credential', source / 'deploy/oci/cloudflare-canary-credential.py')
    credential = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(credential)
    old = credential.validate_metadata(live.document(baseline / 'runtime-bundle/cloudflare-canary-connector.json'))
    metadata = credential._metadata_document(old['account_id'], old['tunnel_id'],
        old['secret']['ocid'], old['secret']['version'], config_version, mode='adopted-live')
    credential.verify_remote_config(metadata, attempts=1)
    # Compare current systemd credential against the exact, existing Vault
    # version; only hashes enter evidence. The token never leaves the VM.
    token = credential.fetch_exact_secret(old['secret']['ocid'], old['secret']['version'])
    token = credential.validate_tunnel_token(token, old['account_id'], old['tunnel_id'])
    selected_token = live.read(Path('/run/credentials/cloudflared.service/cloudflare-token'), mode=0o440)
    import hmac
    if not hmac.compare_digest(token.strip(), selected_token.strip()):
        raise RuntimeError('live connector does not use the recorded Vault secret version')
    evidence = {'revision': revision, 'metadata': metadata, 'public': public_proof(revision)}
    record = {'schema': 1, 'state': 'adopted-live', 'baseline': baseline.name,
              'baseline_manifest_sha256': live.digest(live.read(baseline / 'runtime-bundle/manifest.json')),
              'controller_sha': source_sha, 'metadata': metadata,
              'evidence_sha256': live.digest(live.canonical(evidence))}
    raw = live.canonical(record)
    if live.AUTHORITY.exists() or live.AUTHORITY.is_symlink():
        if live.read(live.AUTHORITY) != raw:
            raise RuntimeError('existing adoption differs; refusing to overwrite authority')
    extension = baseline / live.EXTENSION
    helper_names = ('cloudflare-canary-credential.py', 'live_connector.py')
    extension_record = {'schema': 1, 'release': baseline.name,
        'base_manifest_sha256': record['baseline_manifest_sha256'],
        'controller_sha': source_sha, 'authority_sha256': live.digest(raw),
        'files': {name: live.digest((source / 'deploy/oci' / name).read_bytes()) for name in helper_names}}
    if extension.exists() or extension.is_symlink():
        live.extension(baseline)
        if live.document(extension / 'manifest.json') != extension_record:
            raise RuntimeError('existing baseline extension differs')
    # Repeat route/version proof immediately before any authority publication.
    credential.verify_remote_config(metadata, attempts=1)
    public_proof(revision)
    if not apply:
        print('adoption=checked revision=' + revision + ' routes=unchanged')
        return
    audit = Path('/var/lib/clixor/live-connector-adoption-evidence.json')
    if audit.exists() and live.read(audit) != live.canonical(evidence):
        raise RuntimeError('adoption evidence differs from previous attempt')
    atomic(audit, live.canonical(evidence), 0o400)
    # These stable files are backward compatible before extension publication.
    # Install the shared module first; do not restart any service here.
    for name in ('live_connector.py', 'runtime_bundle.py', 'runtime-reconciler.py'):
        atomic(STABLE / name, (source / 'deploy/oci' / name).read_bytes(), 0o500)
    for name in ('clixor-runtime-reconcile.service', 'clixor-runtime-watchdog.service'):
        atomic(Path('/etc/systemd/system') / name, (source / 'deploy/oci' / name).read_bytes(), 0o644)
    run('/usr/bin/systemctl', 'daemon-reload')
    if not live.AUTHORITY.exists():
        atomic(live.AUTHORITY, raw, 0o400)
    if not extension.exists():
        temporary = Path(tempfile.mkdtemp(prefix='.live-extension-', dir=baseline))
        for name in helper_names:
            atomic(temporary / name, (source / 'deploy/oci' / name).read_bytes(), 0o500)
        atomic(temporary / 'manifest.json', live.canonical(extension_record), 0o400)
        os.rename(temporary, extension)
        fd = os.open(baseline, os.O_RDONLY | os.O_DIRECTORY)
        os.fsync(fd)
        os.close(fd)
    live.extension(baseline)
    runtime_bundle.validate_runtime_bundle(baseline)
    # Align only the local journal with the already-open capability. This is
    # not an ingress transition and never creates or removes public-open.
    atomic(Path('/var/lib/clixor/cloudflare-origin-gate.json'),
           live.canonical({'schema': 1, 'transition': 'stable', 'state': 'open',
                           'authority_sha': live.digest(raw)}), 0o400)
    credential.prepare(baseline)
    credential.verify(baseline)
    credential.verify_remote_config(metadata, attempts=1)
    public_proof(revision)
    print('adoption=passed revision=' + revision + ' routes=unchanged data=unchanged')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--source-sha', required=True)
    parser.add_argument('--git-dir', required=True, type=Path)
    parser.add_argument('--baseline', required=True, type=Path)
    parser.add_argument('--config-version', required=True, type=int)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    try:
        adopt(args.source, args.source_sha, args.git_dir, args.baseline, args.config_version, args.apply)
    except Exception as error:
        print('Live adoption refused: ' + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
