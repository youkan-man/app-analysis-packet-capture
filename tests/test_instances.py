"""Process ownership tests, including cleanup while a command is still running."""
import os
from pathlib import Path
import secrets
import subprocess
import sys
import time
import pytest
from app.instances import CapacityError, Instances, MissingInstance


def test_capacity_rejection_and_ownership(tmp_path):
    pool=Instances(tmp_path,maximum=1)
    key=secrets.token_hex(32)
    try:
        instance=pool.allocate(key)
        with pytest.raises(CapacityError):
            pool.allocate(secrets.token_hex(32))
        with pytest.raises(MissingInstance):
            pool.get(instance.id,secrets.token_hex(32))
        assert pool.get(instance.id,key) is instance
        pool.remove(instance)
        assert not instance.root.exists()
    finally:
        pool.close()
    assert not list(tmp_path.iterdir())


@pytest.mark.skipif(os.name!='posix',reason='Docker uses POSIX process groups')
def test_close_stops_running_protocol_pipe_and_descendants(tmp_path,monkeypatch):
    # Substitute only the external process for a deterministic stalled service.
    # Instance queues, pipe I/O, group termination and file cleanup are all real.
    original=subprocess.Popen
    child_pid=tmp_path/'child.pid'
    script=("import subprocess,sys,time; "
            "child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)']); "
            f"open({str(child_pid)!r},'w').write(str(child.pid)); time.sleep(60)")
    monkeypatch.setattr('app.instances.subprocess.Popen',
        lambda command,**kwargs:original([sys.executable,'-c',script],**kwargs))
    pool=Instances(tmp_path)
    try:
        instance=pool.allocate(secrets.token_hex(32))
        instance.path.write_bytes(b'owned capture')
        instance.start('pcap')
        for _ in range(200):
            if child_pid.exists() and child_pid.read_text():break
            time.sleep(.01)
        assert child_pid.exists()
        job=instance.submit({'operation':'packets','payload':{}})
        for _ in range(100):
            if instance.result(job)['state']=='running':break
            time.sleep(.01)
        pool.remove(instance)
        assert instance.process.poll() is not None
        assert not instance.root.exists()
        # A killed orphan may be a zombie briefly until Docker's init reaps it.
        stat=Path('/proc')/child_pid.read_text().strip()/'stat'
        for _ in range(100):
            if not stat.exists() or stat.read_text().split()[2]=='Z':break
            time.sleep(.01)
        assert not stat.exists() or stat.read_text().split()[2]=='Z'
    finally:
        pool.close()
