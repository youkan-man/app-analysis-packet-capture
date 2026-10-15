"""Regress the reporting-mode option order that previously hid field metadata."""
import app.engine as engine


def test_reporting_option_first_and_offline_resolution_disabled(monkeypatch):
    commands=[]
    class Process:
        returncode=0
        def __init__(self,command,**kwargs):
            commands.append(command)
        def communicate(self,timeout):
            return b'ok',b''
    monkeypatch.setattr(engine.subprocess,'Popen',Process)
    assert engine.run_tshark(['-G','fields'])=='ok'
    assert commands[-1]==[engine.TSHARK,'-G','fields']
    engine.run_tshark(['-r','capture.pcap','-T','pdml'])
    assert commands[-1][1:3]==['-n','-r']
