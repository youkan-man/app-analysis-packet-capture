# Packet Capture Workbench

Wireshark/TShark packet inspection and live capture in one application.

## Run

```sh
docker compose up --build -d
```

Open `http://127.0.0.1:8080`. The single service includes capture; no secondary
Compose file, helper service, socket volume or statically registered interfaces
are used. Available native networks are discovered when the capture dialog opens
and checked again on start. The default deployment uses the Linux host network.
The web application runs as UID 10001. Only the dumpcap executable has the
`cap_net_raw` file capability; the container's capability bounding set allows it.
Do not add `no-new-privileges` to this deployment: it prevents the nonroot capture
executable from acquiring its file capability. The application is bound to
loopback by default; expose it only to trusted operators through authenticated
HTTPS. Capturing a shared interface can observe other users' network traffic;
private result ownership does not make the network itself private.

## Capture

Select **キャプチャ**, choose a network and conditions, then **開始**.
A new PCAPNG file is created in browser storage immediately. The dialog closes,
the file opens in the existing viewer, and captured packets appear while capture
continues. **停止** in the toolbar finishes the same file; it does not import a
second copy. Automatic stop also finalizes that file. Closing the dialog does not
stop capture. Explicit discard removes only that new file.

Complete PCAPNG blocks are appended atomically to IndexedDB before their rows are
shown. One streaming TShark process per capture decodes bytes once. Live summaries
use an incremental row cursor; existing visible row nodes, selected record and
scroll position are retained. Filters continue to apply to arriving packets.
Details and relationship queries use immutable snapshots of the locally committed
prefix, never a partially written block. End-of-capture decoder draining finishes
before the final file is acknowledged. No progress percentage or elapsed counter
is invented.

The original file, filename and list belong to this browser profile's IndexedDB.
Pins, filters and layout preferences remain in localStorage. Captures have
independent, memory-only capability keys for state, incremental data, inspection,
stop and deletion. There is no public capture/session list. Other browsers do not
receive the file or keys. Tabs in the same profile/origin share browser storage;
this is not per-account authentication. Keep external originals: clearing or
evicting site data removes local files. Reloading during capture preserves the
last committed prefix but ends that tab's capture ownership. Interrupted cleanup
is bounded by lease expiry. Host administrators can access transient data.

## Keyboard and loading

Focus the packet list. **Up/Down** moves between records, **Page Up/Down** moves by
the visible region, and **Home/End** jumps within the current filtered list.
**Enter** inspects, **Space** toggles the selected pin, **Ctrl/Cmd+C** copies the
record (normal selected-text copying is preserved), and **Shift+F10** or the menu
key opens its context menu. Navigation crosses virtualized row boundaries.
Text selection alone never opens a popup. Double-click still pins a record.

Protocol, byte, comparison and relationship panes use skeleton placeholders.
Network discovery in the capture dialog also uses a skeleton. Error, cancellation
and stale-result ownership are preserved. Packet loading retains a spinner; no
elapsed-time element or timer is present.

## Verification

GitHub Actions builds and runs the actual single nonroot container, tests existing
file inspection, clipboard, filters, pins, resizing, private instances and restart
recovery, then captures generated loopback UDP using real dumpcap. Tests cover
file creation at start, automatic dialog dismissal, growing records before stop,
stable file identity/row focus, keyboard navigation, live filters, private access,
manual/automatic stop and IndexedDB persistence. Screenshot artifacts cover desktop,
mobile, live data and skeleton states. Fixtures contain no production traffic.

```sh
python -m pip install -r requirements.txt pytest httpx
pytest -q
node tests/live_worker_contract.js
```

Old deployments can update with `git pull --ff-only` and the single Compose command
above. Stop/remove the previously deployed helper container when upgrading; its
old socket volume is unused. No existing volume is deleted automatically. Original
browser files and saved settings are not migrated or cleared.
