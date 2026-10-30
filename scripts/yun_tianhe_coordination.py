"""Local, non-secret authentication coordination. No authentication retries here."""
import hashlib,json,os,time
from pathlib import Path

class AuthenticationBusy(Exception):
    pass

class AuthenticationLock:
    def __init__(self, profile):
        import yun_tianhe_password as session
        identity=json.dumps([profile['host'],profile['port']],sort_keys=True).encode()
        directory=session.local_appdata()/'yun'/'tianhe-coordination'
        directory.mkdir(parents=True,exist_ok=True)
        self.path=directory/(hashlib.sha256(identity).hexdigest()[:24]+'.lock')
        self.stream=None
    def acquire(self):
        import msvcrt
        self.stream=self.path.open('a+b')
        try:
            if os.fstat(self.stream.fileno()).st_size==0:self.stream.write(b'0');self.stream.flush()
            self.stream.seek(0)
            msvcrt.locking(self.stream.fileno(),msvcrt.LK_NBLCK,1)
        except OSError:
            self.stream.close();self.stream=None
            raise AuthenticationBusy('Authentication lock held') from None
    def release(self):
        if self.stream is not None:
            self.stream.close();self.stream=None

def binding(profile):
    import yun_tianhe_vault as vault
    stat=vault.vault_path(profile).stat()
    return dict(target=profile['target'],host=profile['host'],port=profile['port'],username=profile['username'],
                host_key_type=profile['host_key_type'],host_fingerprint=profile['host_fingerprint'],
                credential_generation=dict(mtime_ns=stat.st_mtime_ns,size=stat.st_size))

def marker_path():
    import yun_tianhe_password as session
    return session.local_appdata()/'yun'/'tianhe-coordination'/'last-success.json'

def publish_success(profile,source):
    data=dict(binding=binding(profile),succeeded_at_ns=time.time_ns(),pid=os.getpid(),source=source)
    p=marker_path();p.parent.mkdir(parents=True,exist_ok=True)
    temporary=p.with_name(p.name+'.'+str(os.getpid())+'.tmp')
    temporary.write_text(json.dumps(data),encoding='utf8');temporary.replace(p)

def recovery_signal(profile,after_ns,observer_source):
    try:
        data=json.loads(marker_path().read_text(encoding='utf8'))
        if data['binding']!=binding(profile) or data['succeeded_at_ns']<=after_ns:return None
        if data['source']==observer_source:return None
        return data
    except (OSError,ValueError,KeyError,TypeError):return None

# Explicitly enrolled observers only; called by a successful manual machine query.
from yun_tianhe_observer_wakeup import wake_registered_observers
