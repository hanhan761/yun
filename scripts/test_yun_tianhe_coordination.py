"""Non-secret coordination and two-stage interactive security regression tests."""
import contextlib,io,json,os,pathlib,subprocess,sys,tempfile,unittest
from unittest.mock import patch,MagicMock
import yun_tianhe_coordination as c
import yun_tianhe_password as s
import yun_tianhe_vault as v
PROFILE=dict(target='tianhe-ln5',username='synthetic',host='test-only.invalid',port=9999,host_key_type='ssh-ed25519',host_fingerprint='SHA256:synthetic')
class CoordinationTests(unittest.TestCase):
 def test_marker_binding_generation_source_and_time(self):
  with tempfile.TemporaryDirectory() as d:
   marker=pathlib.Path(d)/'marker.json';blob=pathlib.Path(d)/'synthetic';blob.write_bytes(b'not-a-credential')
   with patch.object(c,'marker_path',return_value=marker),patch.object(v,'vault_path',return_value=blob):
    c.publish_success(PROFILE,'manual-card')
    good=c.recovery_signal(PROFILE,0,'observer');self.assertEqual(good['source'],'manual-card')
    self.assertIsNone(c.recovery_signal(PROFILE,good['succeeded_at_ns'],'observer'))
    self.assertIsNone(c.recovery_signal(PROFILE,0,'manual-card'))
    self.assertIsNone(c.recovery_signal(dict(PROFILE,host_fingerprint='SHA256:changed'),0,'observer'))
    blob.write_bytes(b'different-generation')
    self.assertIsNone(c.recovery_signal(PROFILE,0,'observer'))
 def test_interactive_second_pin_failure_never_sends_password(self):
  pm=MagicMock();pm.Transport.return_value.is_authenticated.return_value=True
  with patch.dict('sys.modules',{'paramiko':pm}),patch.object(s,'load_profile',return_value=PROFILE),patch.object(s.socket,'create_connection',return_value=MagicMock()),patch.object(s,'check_host',side_effect=[None,ValueError('synthetic pin mismatch')]) as pin,patch.object(s,'credentials_from_pipe',return_value=('synthetic','synthetic-only')),patch.object(c,'AuthenticationLock'),contextlib.redirect_stdout(io.StringIO()):
   self.assertEqual(s.main(['--profile','synthetic','--credentials-stdin']),2)
   self.assertEqual(pin.call_count,2);pm.Transport.return_value.auth_password.assert_not_called()
 def test_dpapi_failure_never_authenticates(self):
  pm=MagicMock()
  with patch.dict('sys.modules',{'paramiko':pm}),patch.object(s,'load_profile',return_value=PROFILE),patch.object(s.socket,'create_connection',return_value=MagicMock()),patch.object(s,'check_host'),patch.object(c,'AuthenticationLock'),patch.object(v,'load',side_effect=OSError('synthetic decrypt failure')),contextlib.redirect_stdout(io.StringIO()):
   self.assertEqual(s.main(['--profile','synthetic','--credentials-dpapi']),2);pm.Transport.return_value.auth_password.assert_not_called()
 @unittest.skipUnless(os.name=='nt','Windows locking')
 def test_cross_process_lock_and_release(self):
  code="import sys,json;import yun_tianhe_coordination as c;l=c.AuthenticationLock(json.loads(sys.argv[1]));l.acquire();print('locked',flush=True);sys.stdin.readline();l.release()"
  child=subprocess.Popen([sys.executable,'-X','utf8','-c',code,json.dumps(PROFILE)],cwd=str(pathlib.Path(__file__).parent),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,creationflags=subprocess.CREATE_NO_WINDOW)
  try:
   self.assertEqual(child.stdout.readline().strip(),'locked')
   lock=c.AuthenticationLock(PROFILE)
   with self.assertRaises(c.AuthenticationBusy):lock.acquire()
   child.communicate('release\n',timeout=5)
   lock.acquire();lock.release()
  finally:
   if child.poll() is None:child.kill();child.communicate()
if __name__=='__main__':unittest.main()
