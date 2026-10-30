"""Public Tianhe profiles contain no credentials and fail closed on identity errors."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import yun_tianhe_password as session
import yun_tianhe_vault as vault

PROFILE = dict(target='tianhe-ln5', host='hpc.example.invalid', port=22,
               username='example_user', host_key_type='ssh-ed25519',
               host_fingerprint='SHA256:' + 'A' * 43,
               trust_source='independent_fingerprint_confirmation',
               trust_evidence='synthetic independent confirmation')

class PublicProfileTests(unittest.TestCase):
    def load(self, data):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'profile.json'
            path.write_text(json.dumps(data), encoding='utf8')
            return session.load_profile(path)

    def test_valid_profile_is_read_without_a_network_connection(self):
        with patch.object(session.socket, 'create_connection', side_effect=AssertionError('no network')):
            self.assertEqual(self.load(PROFILE), PROFILE)

    def test_invalid_or_missing_account_host_port_and_pin_fail_closed(self):
        for changed in ({'username': ''}, {'username': 'bad/name'}, {'host': 'bad host'},
                        {'port': 0}, {'port': True}, {'host_fingerprint': 'SHA256:placeholder'},
                        {'trust_source': 'not_confirmed'}, {'trust_evidence': ''}):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                self.load({**PROFILE, **changed})
        missing = dict(PROFILE); missing.pop('username')
        with self.assertRaises(ValueError): self.load(missing)

    def test_credential_identity_and_vault_path_are_account_specific(self):
        other = {**PROFILE, 'username': 'another_user'}
        self.assertNotEqual(vault.identity(PROFILE), vault.identity(other))
        self.assertNotEqual(vault.vault_path(PROFILE), vault.vault_path(other))
        with self.assertRaises(ValueError): vault.save(PROFILE, 'another_user', 'synthetic-only')

if __name__ == '__main__': unittest.main()
