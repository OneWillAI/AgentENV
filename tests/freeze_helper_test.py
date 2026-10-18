#!/usr/bin/env python3
"""Exercise the exact shell supervisor with mocked kernel calls and short clocks."""
import json, os, pathlib, subprocess, tempfile, time
SOURCE = pathlib.Path(__file__).resolve().parents[1] / 'src/sandbox/firecracker/disk-freeze.sh'

def until(check, seconds=12):
    end=time.monotonic()+seconds
    while time.monotonic()<end:
        if check(): return
        time.sleep(.05)
    raise AssertionError('condition timed out')

with tempfile.TemporaryDirectory(prefix='freeze-helper-') as tmp:
    root=pathlib.Path(tmp)
    tools=root/'bin'; tools.mkdir()
    (tools/'stat').write_text('#!/bin/sh\necho tmpfs\n')
    # Real guest regression: mkdir -p stalled on the frozen root before thaw
    # could signal its owner, even though the /run state directory existed.
    (tools/'mkdir').write_text("#!/bin/sh\nif test -e \"$CASE/frozen\" && test \"$1\" = -p; then exit 73; fi\nexec /bin/mkdir \"$@\"\n")
    (tools/'fsfreeze').write_text('''#!/usr/bin/python3
import fcntl,json,os,pathlib,sys,time
p=pathlib.Path(os.environ['CASE'])
freeze=sys.argv[1]=='--freeze'
if freeze: time.sleep(float(os.environ.get('FREEZE_DELAY','0')))
with (p/'kernel.lock').open('w') as lock:
 fcntl.flock(lock,fcntl.LOCK_EX)
 active=(p/'frozen').exists()
 with (p/'calls').open('a') as log: log.write(json.dumps([time.monotonic(),sys.argv[1],active])+'\\n')
 if freeze:
  if active: sys.exit(1)
  (p/'frozen').touch()
 else:
  if (os.environ.get('THAW_FAIL')=='1' and not (p/'allow-thaw').exists()) or not active: sys.exit(1)
  (p/'frozen').unlink()
''')
    for file in tools.iterdir(): file.chmod(0o755)
    def case(name, **extra):
        p=root/name; p.mkdir()
        text=SOURCE.read_text().replace('/run/agentenv-disk-freeze',str(p/'states')).replace('/run/agentenv-disk-branch',str(p/'lease'))
        text=text.replace('"$elapsed" -ge 10','"$elapsed" -ge 2').replace('"$elapsed" -ge 60','"$elapsed" -ge 5')
        script=p/'helper';script.write_text(text)
        env=dict(os.environ, PATH=str(tools)+':'+os.environ['PATH'], CASE=str(p), **extra)
        def start(action,token): return subprocess.Popen(['/bin/sh',str(script),action,token],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        def call(action,token): return start(action,token).wait(timeout=15)
        return p,start,call
    p,start,call=case('normal')
    assert call('freeze','one')==0
    assert (p/'frozen').exists()
    assert call('thaw','one')==0
    assert call('thaw','one')==0 # idempotent acknowledgement
    assert not (p/'frozen').exists()
    assert call('freeze','two')==0
    assert call('thaw','one')!=0
    assert (p/'frozen').exists()
    assert call('thaw','two')==0
    print('PASS normal thaw, repeat acknowledgement, stale token isolation',flush=True)
    p,start,call=case('late',FREEZE_DELAY='3')
    caller=start('freeze','one');time.sleep(.25);caller.kill();caller.wait()
    until(lambda:(p/'states/one/failed').exists())
    until(lambda:not (p/'lease.lease').exists())
    assert not (p/'frozen').exists()
    calls=[json.loads(line)[1] for line in (p/'calls').read_text().splitlines()]
    assert calls==['--unfreeze','--freeze','--unfreeze'],calls
    print('PASS killed caller, acquisition deadline and late-freeze cleanup',flush=True)
    p,start,call=case('expiry')
    assert call('freeze','one')==0
    until(lambda:(p/'states/one/failed').exists())
    assert not (p/'frozen').exists()
    assert call('thaw','one')!=0
    assert call('freeze','two')==0
    assert call('thaw','two')==0
    print('PASS lease expiry reports failure and permits a recovered successor',flush=True)
    p,start,call=case('cold')
    assert call('freeze-stop','one')==0
    time.sleep(6)
    assert (p/'frozen').exists() # cold capture must never auto-thaw
    assert call('thaw','one')==0
    print('PASS cold-stop remains frozen until explicit release',flush=True)
    p,start,call=case('failure',THAW_FAIL='1')
    assert call('freeze','one')==0
    assert call('thaw','one')!=0
    assert (p/'lease.lease').exists()
    assert (p/'states/one/recovery-failed').exists()
    assert call('freeze','two')!=0
    (p/'allow-thaw').touch()
    time.sleep(.1)
    assert call('thaw','one')==0
    assert not (p/'frozen').exists() and not (p/'lease.lease').exists()
    print('PASS failed thaw excludes new acquisition; explicit retry recovers',flush=True)
