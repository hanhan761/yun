"""Read-only aTrust diagnostics. No authentication, proxy mutation, or VPN control."""
import argparse,fnmatch,ipaddress,json,os,socket,subprocess,urllib.request,urllib.parse
from pathlib import Path
def load_diagnostic(path):
 raw=Path(path).read_bytes()
 if len(raw)>4*1024*1024:raise ValueError('Diagnostic too large')
 encoding='utf-16' if raw[:2] in [b'\xff\xfe',b'\xfe\xff'] else 'utf-8-sig'
 return json.loads(raw.decode(encoding))
def summarize(doc):
 items=[i for c in doc.get('allCategories',{}).get('value',[]) for i in c.get('diagnosisItems',[])]
 warnings=[dict(name=i.get('name'),type=i.get('type'),available=i.get('available'),software=[r.get('name') for r in (i.get('tableData') or []) if r.get('name')]) for i in items if i.get('type') not in [None,'not_need_repair']]
 return dict(diagnosed_at=doc.get('startDiagnoseTime'),warnings=warnings,checked_items=len(items),causal_conflict_proven=False)
def bypass_matches(host,patterns):
 return any(fnmatch.fnmatchcase(host.lower(),p.strip().lower()) for p in patterns.split(';') if p.strip() and p.strip().lower()!='<local>')
def windows_context(host):
 if os.name!='nt':return dict(state='not_windows')
 import winreg
 with winreg.OpenKey(winreg.HKEY_CURRENT_USER,r'Software\Microsoft\Windows\CurrentVersion\Internet Settings') as key:
  def val(name,default=None):
   try:return winreg.QueryValueEx(key,name)[0]
   except OSError:return default
  proxy=dict(enabled=bool(val('ProxyEnable',0)),server_configured=bool(val('ProxyServer','')),ssh_host_bypassed=bypass_matches(host,val('ProxyOverride','')),pac_configured=bool(val('AutoConfigURL')))
 # Host is validated IPv4 from the pinned profile, never text from a diagnostic file.
 try:ipaddress.IPv4Address(host)
 except ValueError:return dict(proxy=proxy,route=dict(state='host_not_ipv4'),route_alone_proves_tunnel=False)
 command="[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; Find-NetRoute -RemoteIPAddress "+host+" | Select-Object InterfaceAlias,DestinationPrefix,NextHop | ConvertTo-Json -Compress"
 ps=Path(os.environ['SystemRoot'])/'System32/WindowsPowerShell/v1.0/powershell.exe'
 try:
  r=subprocess.run([str(ps),'-NoProfile','-NonInteractive','-WindowStyle','Hidden','-Command',command],capture_output=True,text=True,encoding='utf8',timeout=15,creationflags=subprocess.CREATE_NO_WINDOW)
  route=json.loads(r.stdout) if r.returncode==0 else dict(state='query_failed')
 except (OSError,ValueError,subprocess.TimeoutExpired):route=dict(state='unknown')
 return dict(proxy=proxy,route=route,route_alone_proves_tunnel=False)
def probe(host,port,portal_url=None):
 result={}
 # Paramiko/raw TCP does not use WinINet/HTTP_PROXY. System proxy warnings cannot
 # establish that SSH traversed Clash. Kernel/TUN interception remains possible.
 try:
  with socket.create_connection((host,port),timeout=8) as sock:
   sock.settimeout(8);banner=sock.recv(256)
   result['ssh']=dict(tcp_connected=True,ssh_banner=any(v.startswith(b'SSH-') for v in banner.splitlines()),authenticated=False,host_identity_verified=False)
 except OSError as e:result['ssh']=dict(state='unreachable',error_type=type(e).__name__,authenticated=False,host_identity_verified=False)
 if portal_url:
  target=urllib.parse.urlsplit(portal_url)
  if target.scheme!='https' or not target.hostname or target.username or target.password or target.query or target.fragment:
   raise ValueError('Portal must be an explicitly supplied HTTPS URL without credentials or query.')
  try:
   opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
   with opener.open(portal_url,timeout=8) as response:result['portal']=dict(status=response.status,proxy_mode='explicit_direct')
  except Exception as e:
   reason=getattr(e,'reason',e)
   result['portal']=dict(state='unreachable',error_type=type(e).__name__,reason_type=type(reason).__name__,certificate_verify_code=getattr(reason,'verify_code',None),proxy_mode='explicit_direct')
 else:result['portal']=dict(state='not_requested')
 return result
def assessment(summary,network):
 ssh=(network or {}).get('ssh',{})
 if ssh.get('ssh_banner'):return 'ssh_transport_reachable_warnings_not_causal_proof'
 if network:return 'ssh_access_unknown_check_atrust_session_then_pinned_login'
 return 'warnings_only_live_access_not_tested'
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--diagnostic',required=True);p.add_argument('--network',action='store_true');p.add_argument('--profile');p.add_argument('--portal-url');a=p.parse_args()
 result=summarize(load_diagnostic(a.diagnostic));network=None
 if a.network:
  if not a.profile:p.error('--network requires the existing pinned --profile')
  from yun_tianhe_password import load_profile
  profile=load_profile(a.profile);host=profile['host'];port=profile['port']
  result['windows']=windows_context(host);network=probe(host,port,a.portal_url);result['network']=network
 result['assessment']=assessment(result,network)
 result['mutation_performed']=False
 print(json.dumps(result,ensure_ascii=False,indent=2));return 0
if __name__=='__main__':raise SystemExit(main())
