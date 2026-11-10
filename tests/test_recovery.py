"""CPU protocol evidence: actual SQLite/private files, simulated remote API only."""
import json
import unittest
import urllib.parse
import uuid
from unittest.mock import patch

from nodus_dc.errors import Error
from nodus_dc.handback import SCOPES
from nodus_dc.recovery import RECOVERY_SCOPES
from tests import test_handback


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.f = test_handback.HandbackTests()
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.keys = {}
        self.audit_events = []
        self.calls = []
        self.deleted_node = False
        self.lose_node = False
        self.lose_keys = set()
        self.mutate = lambda method, path, result: result
        self.add_key(self.f.token_path, 'host-retirement', self.f.key_uid, SCOPES)
        self.f.h.transport = self.transport

    def add_key(self, path, name, uid, scopes):
        self.keys[path.read_text().strip()] = {'uid': uid, 'name': name, 'scopes': sorted(scopes), 'projects': [], 'revoked': False}

    def recovery_key(self, name='recovery-one'):
        path = self.f.path / (name + '.token')
        path.write_text('synthetic-recovery-token-' + name + '-1234567890')
        path.chmod(0o600)
        self.add_key(path, name, str(uuid.uuid4()), RECOVERY_SCOPES)
        return {'recovery_token_file': str(path), 'recovery_api_key_name': name}

    def transport(self, method, url, token, body):
        path = url.removeprefix('https://api.invalid')
        self.calls.append((method, path, body))
        actor = self.keys.get(token)
        if not actor or actor['revoked']:
            result = (401, {'reason': 'Unauthorized'})
        elif path == '/auth/whoami':
            result = (200, {'kind': 'APIKey', 'credentialUID': actor['uid'], 'org': self.f.org,
                            'scopes': actor['scopes'], 'projects': []})
        elif '/apikeys/' in path:
            name = urllib.parse.unquote(path.rsplit('/', 1)[1])
            target = next((item for item in self.keys.values() if item['name'] == name), None)
            if not target or target['revoked']:
                result = (404, {'reason': 'NotFound'})
            elif method == 'GET':
                result = (200, test_handback.api_key_object(target['uid'], target['name'], target['scopes'], target['projects']))
            else:
                self.assertTrue(self.deleted_node)
                target['revoked'] = True
                self.audit_events.append({'uid': str(uuid.uuid4()), 'time': '2026-11-10T00:00:00Z',
                    'action': 'apikeys.delete', 'result': 'Success',
                    'target': {'kind': 'APIKey', 'uid': target['uid'], 'name': target['name']}})
                if name in self.lose_keys:
                    self.lose_keys.remove(name)
                    raise Error('retirement_unavailable', 'simulated committed DELETE with lost response')
                result = (204, None)
        elif '/auditevents?' in path:
            result = (200, {'items': self.audit_events, 'metadata': {}})
        elif '/retirement?' in path:
            result = (200, {'apiVersion': 'nodus.dev/v1', 'kind': 'NodeRetirement', 'node': self.f.node,
                'uid': self.f.node_uid, 'organizationUID': self.f.org, 'credentialGeneration': 4,
                'nodeIdentityRevokedTime': '2026-11-10T00:00:00Z', 'retired': True}) if self.deleted_node else (409, {})
        elif '/sharing?' in path:
            result = (200, {'accepting': False, 'nodes': [self.f.node], 'generation': 2,
                'consent': {'id': self.f.record['consent_id'], 'termsDigest': 'a'*64, 'revokedTime': '2026-11-10T00:00:00Z'}})
        elif method == 'GET':
            result = (404, {}) if self.deleted_node else (200, {'metadata': {'name': self.f.node, 'uid': self.f.node_uid, 'resourceVersion': '456'}})
        else:
            self.assertEqual(body['preconditions'], {'uid': self.f.node_uid, 'resourceVersion': '456'})
            self.deleted_node = True
            if self.lose_node:
                self.lose_node = False
                raise Error('retirement_unavailable', 'simulated committed Node DELETE with lost response')
            result = (200, {'kind': 'Status', 'status': 'Success', 'details': {'name': self.f.node,
                'uid': self.f.node_uid, 'kind': 'nodes', 'group': 'nodus.dev'}})
        return self.mutate(method, path, result)

    def run_return(self, **kwargs):
        return self.f.run_handback(**kwargs)

    def pending_key(self):
        self.lose_keys.add('host-retirement')
        with self.assertRaises(Error):
            self.run_return()
        self.assertEqual('key_delete_pending', self.f.h._load()['stage'])

    def test_node_ack_loss_recovers_only_from_exact_proof(self):
        self.lose_node = True
        with self.assertRaises(Error):
            self.run_return()
        self.assertEqual('node_delete_pending', self.f.h._load()['stage'])
        self.assertTrue(self.run_return(recover=True)['native_access_ready'])
        self.assertIn('node_retirement_proof', self.f.h._load()['evidence'])
        self.assertEqual(1, sum(method == 'DELETE' and '/nodes/' in path for method, path, _ in self.calls))

    def test_pending_before_node_write_retries_exact_live_uid_and_fresh_rv(self):
        save = self.f.h._save
        def crash(journal, stage, **evidence):
            out = save(journal, stage, **evidence)
            if stage == 'node_delete_pending':
                raise SystemExit('interrupted before DELETE')
            return out
        with patch.object(self.f.h, '_save', side_effect=crash), self.assertRaises(SystemExit):
            self.run_return()
        self.assertFalse(self.deleted_node)
        self.assertTrue(self.run_return(recover=True)['native_access_ready'])

    def test_lost_key_ack_uses_exact_audit_and_retires_recovery_key(self):
        self.pending_key()
        extra = self.recovery_key()
        self.assertTrue(self.run_return(recover=True, **extra)['native_access_ready'])
        journal = self.f.h._load()
        self.assertEqual(self.f.key_uid, journal['evidence']['key_delete']['target']['uid'])
        self.assertTrue(all(item['revoked'] for item in self.keys.values()))
        self.assertTrue(all(item['state'] == 'rejected' for item in journal['recovery_keys']))
        self.assertTrue(all(not __import__('pathlib').Path(item['path']).exists() for item in journal['files']))
        self.assertGreaterEqual(sum(self.f.waits), 31)

    def test_recovery_api_key_envelope_failure_keeps_introduced_obligation(self):
        self.pending_key()
        extra = self.recovery_key()
        actor = next(item for item in self.keys.values() if item['name'] == 'recovery-one')
        value = test_handback.api_key_object(actor['uid'], actor['name'], actor['scopes'])
        for name, invalid in test_handback.invalid_api_key_objects(value):
            with self.subTest(case=name):
                self.mutate = lambda method, path, result: (200, invalid) if method == 'GET' and path.endswith('/apikeys/recovery-one') else result
                with self.assertRaises(Error):
                    self.run_return(recover=True, **extra)
                with self.assertRaises(Error):
                    self.run_return()
                self.assertEqual('identity_pending', self.f.h._load()['recovery_keys'][0]['state'])
                self.assertFalse(actor['revoked'])
                self.assertEqual(0, self.f.agent.stops)
                self.assertNotIn('synthetic-unexpected-token-never-retained', json.dumps(self.f.h._load()))
        self.mutate = lambda method, path, result: result
        self.assertTrue(self.run_return(recover=True, **extra)['native_access_ready'])
        self.assertTrue(actor['revoked'])

    def test_lost_recovery_key_ack_remains_obligation_and_second_key_reconciles(self):
        self.pending_key()
        first = self.recovery_key()
        self.lose_keys.add('recovery-one')
        with self.assertRaises(Error):
            self.run_return(recover=True, **first)
        self.assertEqual('delete_pending', self.f.h._load()['recovery_keys'][0]['state'])
        with self.assertRaises(Error):
            self.run_return()  # No silent happy-path bypass of an introduced credential.
        second = self.recovery_key('recovery-two')
        self.assertTrue(self.run_return(recover=True, **second)['native_access_ready'])
        self.assertEqual(2, len(self.f.h._load()['recovery_keys']))

    def test_missing_or_wrong_audit_is_not_revocation(self):
        self.pending_key()
        extra = self.recovery_key()
        for events in ([], [{**self.audit_events[0], 'target': {'kind': 'APIKey', 'name': 'host-retirement', 'uid': str(uuid.uuid4())}}]):
            with self.subTest(events=events):
                self.mutate = lambda method, path, result: (200, {'items': events, 'metadata': {}}) if '/auditevents?' in path else result
                with self.assertRaises(Error):
                    self.run_return(recover=True, **extra)
                self.assertEqual(0, self.f.agent.stops)
        self.mutate = lambda method, path, result: result
        self.assertTrue(self.run_return(recover=True, **extra)['native_access_ready'])

    def test_foreign_or_malformed_node_proof_and_404_fail_closed(self):
        self.lose_node = True
        with self.assertRaises(Error):
            self.run_return()
        for code, fields in [(404, {}), (200, {'organizationUID': str(uuid.uuid4())}),
                (200, {'uid': 'bnod_wrong'}), (200, {'credentialGeneration': True}), (200, {'retired': False})]:
            with self.subTest(fields=fields):
                self.mutate = lambda method, path, result: (code, {**result[1], **fields}) if '/retirement?' in path else result
                with self.assertRaises(Error):
                    self.run_return(recover=True)
                self.assertEqual('node_delete_pending', self.f.h._load()['stage'])
        self.mutate = lambda method, path, result: result
        self.assertTrue(self.run_return(recover=True)['native_access_ready'])

    def test_tracked_key_crash_is_durable_and_rotation_is_rejected(self):
        self.pending_key()
        extra = self.recovery_key()
        save = self.f.h._save
        def crash(journal, stage, **evidence):
            out = save(journal, stage, **evidence)
            if evidence.get('recovery_credentials_tracked'):
                raise SystemExit('interrupted after obligation commit')
            return out
        with patch.object(self.f.h, '_save', side_effect=crash), self.assertRaises(SystemExit):
            self.run_return(recover=True, **extra)
        self.assertEqual('identity_pending', self.f.h._load()['recovery_keys'][0]['state'])
        from pathlib import Path
        file = Path(extra['recovery_token_file'])
        original = file.read_text()
        file.write_text('different-potentially-live-token')
        with self.assertRaises(Error):
            self.run_return(recover=True, **extra)
        file.write_text(original)
        self.assertTrue(self.run_return(recover=True, **extra)['native_access_ready'])

    def test_recovery_requires_existing_journal_and_no_late_key_introduction(self):
        with self.assertRaises(Error):
            self.run_return(recover=True)
        self.assertIsNone(self.f.h._load())
        self.assertTrue(self.run_return()['native_access_ready'])
        before = json.dumps(self.f.h._load(), sort_keys=True)
        with self.assertRaises(Error):
            self.run_return(recover=True, **self.recovery_key())
        self.assertEqual(before, json.dumps(self.f.h._load(), sort_keys=True))

    def test_audit_scan_and_credential_chain_are_bounded(self):
        self.pending_key()
        self.mutate = lambda method, path, result: (200, {'items': [], 'metadata': {'continue': str(len(self.calls))}}) if '/auditevents?' in path else result
        for number in range(4):
            before = len(self.calls)
            with self.assertRaises(Error):
                self.run_return(recover=True, **self.recovery_key('recovery-' + str(number)))
            self.assertEqual(20, sum('/auditevents?' in path for _, path, _ in self.calls[before:]))
        before = len(self.calls)
        with self.assertRaises(Error) as exc:
            self.run_return(recover=True, **self.recovery_key('one-too-many'))
        self.assertEqual('recovery_key_limit', exc.exception.code)
        self.assertEqual(before, len(self.calls))
        self.assertEqual(4, len(self.f.h._load()['recovery_keys']))
        self.assertEqual(0, self.f.agent.stops)

    def test_crash_before_recovery_delete_keeps_exact_obligation(self):
        self.pending_key()
        extra = self.recovery_key()
        save = self.f.h._save
        def crash(journal, stage, **evidence):
            out = save(journal, stage, **evidence)
            if any(item['state'] == 'delete_pending' for item in out.get('recovery_keys', [])):
                raise SystemExit('interrupted before temporary key DELETE')
            return out
        with patch.object(self.f.h, '_save', side_effect=crash), self.assertRaises(SystemExit):
            self.run_return(recover=True, **extra)
        # A fresh actor resolves a pending credential; the pending credential cannot
        # authorize its own uncertain reconciliation, even when actually still live.
        second = self.recovery_key('recovery-two')
        self.assertTrue(self.run_return(recover=True, **second)['native_access_ready'])
        self.assertTrue(all(item['revoked'] for item in self.keys.values()))

    def test_recovery_restart_repeats_wait_and_every_key_must_reject(self):
        self.pending_key()
        extra = self.recovery_key()
        self.mutate = lambda method, path, result: (403, {}) if path == '/auth/whoami' and result[0] == 401 else result
        with self.assertRaises(Error):
            self.run_return(recover=True, **extra)
        self.assertEqual(31, sum(self.f.waits))
        self.assertEqual(0, self.f.agent.stops)
        self.f.tick = 900000
        self.mutate = lambda method, path, result: result
        self.assertTrue(self.run_return(recover=True, **extra)['native_access_ready'])
        self.assertEqual(62, sum(self.f.waits))

    def test_recovery_resumes_local_stages_and_completed_replay_without_new_key(self):
        self.pending_key()
        extra = self.recovery_key()
        self.f.service.backend.clean = False
        with self.assertRaises(Error):
            self.run_return(recover=True, **extra)
        self.assertEqual('credentials_removed', self.f.h._load()['stage'])
        self.f.service.backend.clean = True
        result = self.run_return(recover=True)
        self.assertTrue(result['native_access_ready'])
        before = len(self.calls)
        self.assertEqual(result, self.run_return(recover=True))
        self.assertEqual(before, len(self.calls))

    def test_crash_during_first_authenticated_read_cannot_forget_introduced_key(self):
        for location in ('whoami', 'metadata'):
            with self.subTest(location=location):
                fixture = RecoveryTests()
                fixture.setUp()
                try:
                    save = fixture.f.h._save
                    def before_remote(journal, stage, **evidence):
                        out = save(journal, stage, **evidence)
                        if stage == 'prepared':
                            raise SystemExit('prepared baseline')
                        return out
                    with patch.object(fixture.f.h, '_save', side_effect=before_remote), self.assertRaises(SystemExit):
                        fixture.run_return()
                    extra = fixture.recovery_key()
                    token = __import__('pathlib').Path(extra['recovery_token_file']).read_text()
                    original = fixture.transport
                    def crash(method, url, presented, body):
                        if presented == token and ((location == 'whoami' and url.endswith('/auth/whoami')) or
                                (location == 'metadata' and url.endswith('/apikeys/recovery-one'))):
                            raise SystemExit('crash during introduced credential read')
                        return original(method, url, presented, body)
                    fixture.f.h.transport = crash
                    with self.assertRaises(SystemExit):
                        fixture.run_return(recover=True, **extra)
                    held = fixture.f.h._load()
                    self.assertEqual('identity_pending', held['recovery_keys'][0]['state'])
                    self.assertIn(held['recovery_keys'][0]['file'], held['files'])
                    fixture.f.h.transport = original
                    with self.assertRaises(Error) as exc:
                        fixture.run_return()
                    self.assertEqual('recovery_required', exc.exception.code)
                    self.assertFalse(fixture.deleted_node)
                    self.assertFalse(fixture.keys[token]['revoked'])
                    self.assertTrue(fixture.run_return(recover=True, **extra)['native_access_ready'])
                    self.assertTrue(fixture.keys[token]['revoked'])
                finally:
                    fixture.doCleanups()
