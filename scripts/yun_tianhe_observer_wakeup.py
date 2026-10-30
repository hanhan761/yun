"""Explicitly registered, read-only observer launch on successful manual HPC query.
No SSH, job submission, task creation, remote commands, or background polling here.
"""
import contextlib,hashlib,json,os,subprocess,sys,time
from pathlib import Path

MANUAL_SOURCE='endnote-manual-query'
def registry_path():
 import yun_tianhe_password as s
 return s.local_appdata()/'yun'/'tianhe-coordination'/'query-observers.json'

def atomic(path,data):
 path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
 temp=path.with_name(path.name+'.'+str(os.getpid())+'.tmp')
 temp.write_text(json.dumps(data,ensure_ascii=False,indent=2),encoding='utf8');temp.replace(path)

@contextlib.contextmanager
def lock_available(path):
 import msvcrt
 path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
 with path.open('a+b') as stream:
  if os.fstat(stream.fileno()).st_size==0:stream.write(b'0');stream.flush()
  stream.seek(0)
  try:msvcrt.locking(stream.fileno(),msvcrt.LK_NBLCK,1)
  except OSError:yield False;return
  try:yield True
  finally:stream.seek(0);msvcrt.locking(stream.fileno(),msvcrt.LK_UNLCK,1)

def validate(record,now):
 if record.get('scope')!='read_only_observer' or not record.get('enabled'):return 'disabled_or_invalid_scope'
 contract=json.loads(Path(record['contract']).read_text(encoding='utf8'))
 receipt=json.loads(Path(record['receipt']).read_text(encoding='utf8'))
 if contract['job_id']!=record['job_id'] or receipt['job_id']!=record['job_id'] or receipt['remote_dir']!=record['remote_dir'] or receipt['state']!='submitted':return 'identity_mismatch'
 if not contract.get('read_only') or contract.get('submits_or_restarts_compute') is not False:return 'invalid_contract'
 if now>=contract['deadline_epoch']:return 'expired'
 if Path(record['python']).resolve()!=Path(sys.executable).resolve():return 'interpreter_mismatch'
 entry=Path(record['entrypoint'])
 if not entry.is_absolute() or not Path(record['cwd']).is_absolute() or str(entry) not in record['sources']:return 'invalid_launcher'
 for filename,expected in record['sources'].items():
  path=Path(filename)
  if not path.is_absolute() or path.stat().st_size>2*1024*1024 or hashlib.sha256(path.read_bytes()).hexdigest()!=expected:return 'source_changed'
 try:
  notification=json.loads(Path(record['notification_state']).read_text(encoding='utf8'))
  if notification.get('task_id')==record['task_id'] and notification.get('terminal_reported'):return 'terminal_already_reported'
 except (OSError,ValueError):pass
 return None

def wake_registered_observers(profile):
 from yun_tianhe_coordination import binding,marker_path
 now=time.time();results=[]
 try:
  signal=json.loads(marker_path().read_text(encoding='utf8'));current=binding(profile)
  age=now-signal['succeeded_at_ns']/1e9
  if signal.get('source')!=MANUAL_SOURCE or signal.get('binding')!=current or not -5<=age<=120:return []
  registry=json.loads(registry_path().read_text(encoding='utf8'))
  if registry.get('schema_version')!=1:return []
 except (OSError,ValueError,KeyError,TypeError):return []
 for record in registry.get('observers',[]):
  result=dict(job_id=record.get('job_id'),checked_at=now,query_success_at_ns=signal['succeeded_at_ns'])
  try:
   if record.get('binding')!=current:result['state']='binding_mismatch';results.append(result);continue
   issue=validate(record,now)
   if issue:result['state']=issue;results.append(result);continue
   launch_state=Path(record['launch_state'])
   with lock_available(launch_state.with_suffix('.lock')) as available:
    if not available:result['state']='launch_check_busy';results.append(result);continue
    with lock_available(record['observer_lock']) as observer_free:
     if not observer_free:result['state']='observer_running_signal_available';results.append(result);continue
    try:previous=json.loads(launch_state.read_text(encoding='utf8'))
    except (OSError,ValueError):previous={}
    if previous.get('state')=='launch_requested' and now-previous.get('checked_at',0)<20:
     result['state']='launch_pending';results.append(result);continue
    # Observer's own OS mutex is the final duplicate guard before any SSH call.
    with Path(record['stdout']).open('ab') as out,Path(record['stderr']).open('ab') as err:
     process=subprocess.Popen([record['python'],'-X','utf8','-u',record['entrypoint']],cwd=record['cwd'],stdin=subprocess.DEVNULL,stdout=out,stderr=err,creationflags=subprocess.CREATE_NO_WINDOW|subprocess.DETACHED_PROCESS,close_fds=True)
    result.update(state='launch_requested',pid=process.pid)
    atomic(launch_state,result)
  except (OSError,ValueError,KeyError,TypeError) as exc:result.update(state='recovery_unavailable',error_type=type(exc).__name__)
  results.append(result)
 try:atomic(registry_path().with_name('last-query-recovery.json'),dict(checked_at=now,results=results))
 except OSError:pass
 return results
