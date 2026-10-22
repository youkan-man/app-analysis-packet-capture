"""CI-only loopback UDP traffic. No production interfaces or external hosts."""
import signal
import socket
import threading

stop = threading.Event()
for sig in (signal.SIGTERM, signal.SIGINT):
    signal.signal(sig, lambda *_: stop.set())
receivers = []
for port in (49321, 49322):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('127.0.0.1', port))
    sock.settimeout(.2)
    receivers.append(sock)
    def consume(sock=sock):
        while not stop.is_set():
            try:
                sock.recvfrom(2048)
            except socket.timeout:
                pass
    threading.Thread(target=consume, daemon=True).start()
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
    while not stop.wait(.05):
        for port in (49321, 49322):
            sender.sendto(f'pcana-live-fixture-{port}'.encode(), ('127.0.0.1', port))
for sock in receivers:
    sock.close()
