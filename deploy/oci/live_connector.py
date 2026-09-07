"""Strict, root-owned authority for adopting an already-live pilot connector.

This is not route promotion: it cannot create a gate, change DNS, or grant a
different tunnel authority. The operator installer supplies observed evidence.
"""
from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path

AUTHORITY = Path('/var/lib/clixor/live-connector-adoption.json')
EXTENSION = 'live-connector-extension-v1'
PRODUCTION_HOSTS = ('clustr-api.atlanteanz.com', 'clixor.atlanteanz.com')
CANARY = 'clixor-oci-canary.atlanteanz.com'
ORIGIN = 'unix:/run/clixor-origin/gateway.sock'
GATE = Path('/var/lib/clixor/origin-gate-public/public-open')


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode() + b'\n'


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate live authority field')
        result[key] = value
    return result


def read(path: Path, mode=0o400, uid=0):
    # Check every ancestor; a safe leaf beneath an attacker-owned directory is
    # not authority. Tests use a temporary directory with their own UID.
    for parent in (path.parent, *path.parents):
        info = parent.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise ValueError('unsafe live authority parent')
        if uid == 0 and (info.st_uid != 0 or info.st_mode & 0o022):
            raise ValueError('untrusted live authority parent')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != uid
                or stat.S_IMODE(info.st_mode) not in (mode if isinstance(mode, tuple) else (mode,))
                or info.st_size > 1048576):
            raise ValueError('unsafe live authority file')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            return stream.read(1048577)
    finally:
        os.close(fd)


def document(path: Path, uid=0):
    result = json.loads(read(path, uid=uid), object_pairs_hook=_pairs)
    if not isinstance(result, dict):
        raise ValueError('live authority must be an object')
    return result


def ingress():
    return ([{'hostname': host, 'service': ORIGIN}
             for host in (CANARY, *PRODUCTION_HOSTS)] + [{'service': 'http_status:404'}])


def authority(uid=0):
    result = document(AUTHORITY, uid)
    if set(result) != {'schema', 'state', 'baseline', 'baseline_manifest_sha256',
                       'controller_sha', 'metadata', 'evidence_sha256'}:
        raise ValueError('live adoption fields are invalid')
    import re
    if (type(result['schema']) is not int or result['schema'] != 1 or result['state'] != 'adopted-live'
            or not re.fullmatch(r'oci-[0-9a-f]{12}-[A-Za-z0-9._-]+', str(result['baseline']))
            or not re.fullmatch(r'[0-9a-f]{40}', str(result['controller_sha']))
            or any(not re.fullmatch(r'[0-9a-f]{64}', str(result[key]))
                   for key in ('baseline_manifest_sha256', 'evidence_sha256'))):
        raise ValueError('live adoption identity is invalid')
    meta = result['metadata']
    if not isinstance(meta, dict) or meta.get('mode') != 'adopted-live':
        raise ValueError('live adoption connector mode is invalid')
    # The credential controller validates the complete metadata grammar. This
    # module also checks the route boundary independently of that executable.
    if meta.get('remote_config', {}).get('ingress') != ingress():
        raise ValueError('live adoption routes differ from the approved hostnames')
    return result


def require_open_gate(uid=0):
    # tmpfiles canonicalizes this existing capability to 0400. Accept the
    # historical root-only 0600 marker during adoption, never broader modes.
    if read(GATE, mode=(0o400, 0o600), uid=uid) != b'':
        raise ValueError('live origin capability must be empty')


def require_live(metadata, uid=0):
    selected = authority(uid)
    if metadata != selected['metadata']:
        raise ValueError('connector differs from adopted live authority')
    require_open_gate(uid)
    return selected


def extension(release: Path, uid=0):
    root = release / EXTENSION
    if not root.exists() and not root.is_symlink():
        return None
    info = root.lstat()
    if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or info.st_uid != uid or stat.S_IMODE(info.st_mode) != 0o700):
        raise ValueError('unsafe live connector extension')
    record = document(root / 'manifest.json', uid)
    if (set(record) != {'schema', 'release', 'base_manifest_sha256', 'controller_sha',
                       'authority_sha256', 'files'} or type(record['schema']) is not int
            or record['schema'] != 1 or not isinstance(record['files'], dict)):
        raise ValueError('invalid live extension manifest')
    selected = authority(uid)
    if (record['release'] != release.name or selected['baseline'] != release.name
            or record['controller_sha'] != selected['controller_sha']
            or record['authority_sha256'] != digest(read(AUTHORITY, uid=uid))
            or record['base_manifest_sha256'] != selected['baseline_manifest_sha256']
            or digest(read(release / 'runtime-bundle/manifest.json', uid=uid))
            != record['base_manifest_sha256']):
        raise ValueError('live extension is not bound to this baseline')
    required = {'cloudflare-canary-credential.py', 'live_connector.py'}
    if set(record['files']) != required or {p.name for p in root.iterdir()} != required | {'manifest.json'}:
        raise ValueError('live extension inventory is invalid')
    for name in required:
        if digest(read(root / name, mode=0o500, uid=uid)) != record['files'][name]:
            raise ValueError('live extension executable changed')
    return root


def metadata_for_baseline(release: Path):
    if extension(release) is None:
        return None
    return authority()['metadata']
