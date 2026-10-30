import unittest,tempfile,json,sys
from pathlib import Path
from unittest.mock import patch,MagicMock
sys.path.insert(0,str(Path(__file__).resolve().parent))
import tianhe_access_diagnose as d
class Tests(unittest.TestCase):
 def test_proxy_presence_is_not_cause(self):
  summary=d.summarize({'allCategories':{'value':[{'diagnosisItems':[{'name':'代理','type':'manual_repair'}]}]}})
  self.assertFalse(summary['causal_conflict_proven'])
  self.assertEqual(d.assessment(summary,{'ssh':{'ssh_banner':True}}),'ssh_transport_reachable_warnings_not_causal_proof')
 def test_portal_ok_does_not_prove_ssh(self):
  self.assertEqual(d.assessment({}, {'portal':{'status':200},'ssh':{'state':'unreachable'}}),'ssh_access_unknown_check_atrust_session_then_pinned_login')
 def test_private_bypass(self):
  self.assertTrue(d.bypass_matches('203.0.113.11','localhost;203.0.113.*;<local>'))
  self.assertFalse(d.bypass_matches('203.0.113.11','localhost;10.*;<local>'))
 def test_utf16_report(self):
  with tempfile.TemporaryDirectory() as t:
   p=Path(t)/'diag.txt';p.write_bytes(json.dumps({'startDiagnoseTime':'test'}).encode('utf-16'))
   self.assertEqual(d.load_diagnostic(p)['startDiagnoseTime'],'test')
 def test_unknown_status_not_silently_ok(self):
  result=d.summarize({'allCategories':{'value':[{'diagnosisItems':[{'name':'x','type':'pending_repair'}]}]}})
  self.assertEqual(len(result['warnings']),1)
 def test_portal_direct_and_no_credentials(self):
  sock=MagicMock();sock.__enter__.return_value.recv.return_value=b'SSH-2.0-test\r\n'
  response=MagicMock();response.__enter__.return_value.status=200
  opener=MagicMock();opener.open.return_value=response
  with patch.object(d.socket,'create_connection',return_value=sock),patch.object(d.urllib.request,'ProxyHandler') as proxy,patch.object(d.urllib.request,'build_opener',return_value=opener):
   result=d.probe('203.0.113.11',22,'https://example.invalid/manifest')
   proxy.assert_called_once_with({});self.assertFalse(result['ssh']['authenticated']);self.assertFalse(result['ssh']['host_identity_verified'])
 def test_portal_is_optional_and_rejects_credentials(self):
  with patch.object(d.socket,'create_connection',side_effect=OSError('synthetic')):
   self.assertEqual(d.probe('203.0.113.11',22)['portal']['state'],'not_requested')
   with self.assertRaises(ValueError):d.probe('203.0.113.11',22,'https://example.invalid/?token=synthetic')
if __name__=='__main__':unittest.main()
