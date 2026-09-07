from __future__ import annotations

import copy
import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import live_connector as live
from test_cloudflare_canary_credential import CREDENTIAL, ACCOUNT, TUNNEL, SECRET_OCID, FakeResponse
from test_runtime_reconciler import RECONCILER

SPEC = importlib.util.spec_from_file_location('adopt_live', Path(__file__).parent / 'adopt-live-connector.py')
ADOPT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ADOPT)


class LiveConnectorTests(unittest.TestCase):
    def setUp(self):
        temp_parent = Path.home() if os.getuid() == 0 else Path(tempfile.gettempdir()).resolve()
        self.temp = tempfile.TemporaryDirectory(dir=temp_parent)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.uid = os.getuid()
        self.release = self.root / ('oci-' + 'a' * 12 + '-baseline')
        (self.release / 'runtime-bundle').mkdir(parents=True)
        self.base = b'{"baseline":"immutable"}\n'
        self.write(self.release / 'runtime-bundle/manifest.json', self.base)
        self.meta = CREDENTIAL._metadata_document(ACCOUNT, TUNNEL, SECRET_OCID, 1, 2, 'adopted-live')
        self.auth = {'schema': 1, 'state': 'adopted-live', 'baseline': self.release.name,
                     'baseline_manifest_sha256': live.digest(self.base),
                     'controller_sha': 'b' * 40, 'metadata': self.meta,
                     'evidence_sha256': 'c' * 64}
        self.authority = self.root / 'authority.json'
        self.gate = self.root / 'public-open'
        self.write(self.authority, live.canonical(self.auth))
        self.write(self.gate, b'', 0o600)
        for name, value in [('AUTHORITY', self.authority), ('GATE', self.gate)]:
            patcher = mock.patch.object(live, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def write(self, path, content, mode=0o400):
        if path.exists():
            path.unlink()
        path.write_bytes(content)
        path.chmod(mode)

    def make_extension(self):
        root = self.release / live.EXTENSION
        root.mkdir(mode=0o700)
        files = {}
        for name in ('cloudflare-canary-credential.py', 'live_connector.py'):
            self.write(root / name, b'# reviewed code\n', 0o500)
            files[name] = live.digest(b'# reviewed code\n')
        record = {'schema': 1, 'release': self.release.name,
                  'base_manifest_sha256': live.digest(self.base),
                  'controller_sha': 'b' * 40,
                  'authority_sha256': live.digest(live.canonical(self.auth)), 'files': files}
        self.write(root / 'manifest.json', live.canonical(record))
        return root

    def test_requires_exact_authority_and_preexisting_gate(self):
        self.assertEqual(live.require_live(self.meta, self.uid), self.auth)
        self.gate.unlink()
        with self.assertRaises(OSError):
            live.require_live(self.meta, self.uid)

    def test_rejects_route_secret_and_config_drift(self):
        for path, value in [('tunnel_id', 'd' * 32), ('remote_config', {}), ('secret', {})]:
            changed = copy.deepcopy(self.meta)
            changed[path] = value
            with self.assertRaises(ValueError):
                live.require_live(changed, self.uid)

    def test_tmpfiles_gate_mode_and_legacy_mode_are_accepted(self):
        for mode in (0o400, 0o600):
            self.gate.chmod(mode)
            self.assertEqual(live.require_live(self.meta, self.uid), self.auth)

    def test_gate_rejects_other_modes_and_nonempty_content(self):
        for mode in (0o000, 0o440, 0o640, 0o644, 0o666, 0o700):
            self.gate.chmod(mode)
            with self.assertRaises((ValueError, OSError)):
                live.require_live(self.meta, self.uid)
        self.write(self.gate, b'not-a-capability', 0o400)
        with self.assertRaises(ValueError):
            live.require_live(self.meta, self.uid)

    def test_baseline_rollback_uses_stable_compatibility_controller(self):
        helper = RECONCILER.HOST_TOOL_ROOT / 'live-connector-credential.py'
        with mock.patch.object(live, 'extension', return_value=self.release / live.EXTENSION), \
             mock.patch.object(live, 'read', return_value=b'reviewed') as read:
            runner = mock.Mock()
            RECONCILER._prepare_connector_credential(self.release, self.root, runner)
            read.assert_called_once_with(helper, mode=0o500)
            runner.run.assert_called_once_with([
                '/usr/bin/python3', str(helper), 'prepare', '--release', str(self.release),
                '--project-root', str(self.root)])

    def test_rollback_never_falls_back_when_extension_or_controller_is_unsafe(self):
        for method in ('extension', 'read'):
            with mock.patch.object(live, 'extension', return_value=self.release / live.EXTENSION), \
                 mock.patch.object(live, method, side_effect=ValueError('tampered')):
                with self.assertRaises(RECONCILER.ReconcileError):
                    RECONCILER._connector_credential_controller(self.release)

    def test_deploy_rollback_uses_validating_resolver(self):
        script = (Path(__file__).parent / 'deploy.sh').read_text()
        rollback = script.split('restore_previous_connector_credential() {', 1)[1].split('\nrestore_cloudflared()', 1)[0]
        self.assertIn('connector-helper --release "${previous_release}"', rollback)
        self.assertNotIn('${previous_release}/runtime-bundle/host-tools/bin/', rollback)

    def test_controller_repair_preserves_authority_and_rejects_drift(self):
        with mock.patch.object(live, 'authority', return_value=self.auth), \
             mock.patch.object(live, 'extension', return_value=self.release / live.EXTENSION):
            newer = dict(self.auth, controller_sha='d' * 40)
            self.assertEqual(ADOPT.preserved_repair_authority(newer, self.release), self.auth)
            for key in ('baseline', 'baseline_manifest_sha256', 'metadata', 'evidence_sha256'):
                with self.assertRaises(RuntimeError):
                    ADOPT.preserved_repair_authority(dict(newer, **{key: 'changed'}), self.release)
        with mock.patch.object(live, 'authority', return_value=self.auth), \
             mock.patch.object(live, 'extension', return_value=None):
            with self.assertRaises(RuntimeError):
                ADOPT.preserved_repair_authority(self.auth, self.release)

    def test_live_metadata_is_narrow_not_arbitrary_ingress(self):
        CREDENTIAL.validate_metadata(self.meta)
        changed = copy.deepcopy(self.meta)
        changed['remote_config']['ingress'][1]['hostname'] = 'attacker.example'
        with self.assertRaises(CREDENTIAL.CredentialError):
            CREDENTIAL.validate_metadata(changed)

    def test_extension_is_bound_to_original_bundle(self):
        root = self.make_extension()
        self.assertEqual(live.extension(self.release, self.uid), root)
        self.write(self.release / 'runtime-bundle/manifest.json', b'{"changed":true}\n')
        with self.assertRaises(ValueError):
            live.extension(self.release, self.uid)

    def test_extension_rejects_code_tampering(self):
        root = self.make_extension()
        self.write(root / 'live_connector.py', b'changed\n', 0o500)
        with self.assertRaises(ValueError):
            live.extension(self.release, self.uid)

    def test_extension_rejects_extra_files(self):
        root = self.make_extension()
        self.write(root / 'extra.py', b'changed\n', 0o500)
        with self.assertRaises(ValueError):
            live.extension(self.release, self.uid)

    def test_rejects_symlink_gate(self):
        self.gate.unlink()
        self.gate.symlink_to(self.authority)
        with self.assertRaises(OSError):
            live.require_live(self.meta, self.uid)

    def test_rejects_duplicate_authority_fields(self):
        self.write(self.authority, b'{"schema":1,"schema":1}')
        with self.assertRaises(ValueError):
            live.authority(self.uid)

    def test_remote_proof_rejects_unreviewed_options(self):
        config = {'version': 2, 'config': {
            'ingress': [dict(hostname=r.get('hostname', ''), path=None, service=r['service'],
                             Handlers=None, originRequest=CREDENTIAL.DEFAULT_ORIGIN_REQUEST)
                        for r in live.ingress()],
            'warp-routing': {}, 'originRequest': CREDENTIAL.DEFAULT_ORIGIN_REQUEST}}
        with mock.patch.object(CREDENTIAL.urllib.request, 'urlopen',
                               return_value=FakeResponse(json.dumps(config).encode())):
            CREDENTIAL.verify_remote_config(self.meta, attempts=1)
        config['config']['ingress'][1]['path'] = '/only-this'
        with mock.patch.object(CREDENTIAL.urllib.request, 'urlopen',
                               return_value=FakeResponse(json.dumps(config).encode())):
            with self.assertRaises(CREDENTIAL.CredentialError):
                CREDENTIAL.verify_remote_config(self.meta, attempts=1)

    def test_preflight_refuses_unadopted_live_gate(self):
        script = (Path(__file__).parent / 'deploy.sh').read_text()
        guard = script.index('live production gate has no verified ownership')
        self.assertLess(guard, script.index('stage_release_boot_tooling\n'))
        self.assertIn('live_connector_enabled', script)

    def test_source_authentication_precedes_any_host_change(self):
        with mock.patch.object(ADOPT.os, 'geteuid', return_value=0), \
             mock.patch.object(ADOPT.runtime_bundle, 'validate_approved_source', side_effect=RuntimeError('untrusted')), \
             mock.patch.object(ADOPT, 'atomic') as write, \
             mock.patch.object(ADOPT, 'run') as command:
            with self.assertRaisesRegex(RuntimeError, 'untrusted'):
                ADOPT.adopt(self.root, 'a' * 40, self.root, self.release, 2, True)
            write.assert_not_called()
            command.assert_not_called()

    def test_public_proof_requires_all_fixed_hosts_and_exact_revision(self):
        response = FakeResponse(json.dumps({'status': 'ready', 'revision': 'a' * 40}).encode())
        response.status = 200
        opener = mock.Mock()
        opener.open.return_value = response
        with mock.patch.object(ADOPT.urllib.request, 'build_opener', return_value=opener):
            proof = ADOPT.public_proof('a' * 40)
            self.assertEqual(set(proof), {live.CANARY, *live.PRODUCTION_HOSTS})
            self.assertEqual(opener.open.call_count, 3)
            with self.assertRaisesRegex(RuntimeError, 'selected revision'):
                ADOPT.public_proof('b' * 40)

    def test_public_proof_refuses_redirects(self):
        with self.assertRaises(RuntimeError):
            ADOPT.NoRedirect().redirect_request(None, None, 302, '', {}, 'https://elsewhere')


if __name__ == '__main__':
    unittest.main()
