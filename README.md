# Packet Capture Workbench

Docker-hosted Wireshark/TShark inspection with **browser-owned capture storage** and **private, transient background analysis instances**. The formal light UI, continuous list, screen-driven filters, pins, comparison, linked bytes and communication hierarchy remain available.

## Run / update

```sh
git pull --ff-only
docker compose up --build -d
```

Open `http://127.0.0.1:8080`. Compose binds to loopback by default. For LAN access use a trusted HTTPS reverse proxy: plain HTTP does not protect captures or capability headers from network observers.

## Live packet capture (Linux Docker host)

```sh
docker compose -f compose.yaml -f compose.capture.yaml up --build -d
```

Use **キャプチャ** to select a host interface, protocol, IP address/direction and port.
No Wireshark filter syntax is needed for these controls. An optional BPF capture
filter lives under **詳細条件**; it is different from a display filter. The dialog
also sets automatic stop limits (seconds, file size and packet count) and snapshot
length. **停止して保存** finalizes PCAPNG, stores the original in this browser's
IndexedDB, and opens it in the existing packet viewer. Reaching any limit does the
same automatically. While recording, the dialog can be closed to inspect another
file; the capture button retains the recording state. There is no elapsed-time
counter. This version inspects the new capture after it stops, not as live rows.

The capture sidecar alone gets `NET_RAW` and the host network namespace. The web
and TShark analysis container stays nonroot, without network capabilities. The
sidecar runs only the fixed dumpcap command (non-promiscuous mode) and a Unix-socket
API, with no published TCP port, shell arguments, remote capture URLs, pipes or
extcap selection. To restrict native interfaces, set `CAPTURE_INTERFACES=eth0,lo`
when starting Compose. Defaults: 60 seconds, 32 MiB, 100,000 packets; maximum
settings: 3,600 seconds, 64 MiB, 1,000,000 packets. A disconnected active session
expires after 120 seconds; stopped data expires after 15 minutes without requests.

Every capture session has a separate in-memory capability. Another browser cannot
list, stop, fetch or delete it. Start retries with the same capability do not
create duplicate capture processes. Download does not delete the temporary copy:
only a successful browser transaction acknowledges it. Storage errors leave it
available for **保存を再試行** until expiry. **破棄** stops without importing, after
confirmation. Leaving the page attempts cleanup and falls back to bounded expiry.

The default `compose.yaml` remains an offline viewer with capture disabled. The
optional configuration targets **Linux Docker Engine**: Docker Desktop's host
networking does not expose Windows/macOS physical interfaces at layer 2. The
capture source is the Docker host, never the browser user's device. The named
`capture_socket` volume contains only the Unix socket; packet bytes live in the
sidecar's tmpfs and the browser, not a shared disk capture library.

**Enable host capture only for trusted operators behind authenticated HTTPS.**
Session isolation protects stored results, not the shared network: an authorized
operator can capture traffic visible on an allowed interface, including other
users' network traffic. Capabilities are not a user-login or per-interface user
permission system. Host administrators can inspect transient data. Do not deploy
this feature on an anonymously accessible service.

Capture implementation references: Wireshark's `dumpcap(1)` manual
(`https://www.wireshark.org/docs/man-pages/dumpcap.html`) and Docker host networking
(`https://docs.docker.com/engine/network/drivers/host/`).

## Ownership and processing

1. Opening a file saves the original Blob and its metadata atomically in this browser profile's **IndexedDB**. Small view settings, pins and saved filters remain in localStorage. A storage failure stops the operation; it never falls back to a shared server store.
2. A dedicated browser Web Worker reads that local file and uploads its bytes, without its filename, to create a private analysis instance. Each instance has its own random capability and dedicated Python process/TShark children.
3. Packet, field, filter, comparison and relationship requests use asynchronous jobs on that same instance. HTTP accepts jobs with `202` and the browser worker polls results without blocking the UI. Results and process caches are temporary, not a shared persistent capture database.
4. **閉じる** ends the active analysis and retains the local original. Switching files releases the old instance. Deleting a file deletes this browser's original and its local view/pin state. It does not affect another browser.
5. Refresh, idle expiry or a server restart creates a new private instance from the browser's stored original. Page exit attempts cleanup; leases also expire after 900 seconds without requests. Closing/expiry stops the process group including TShark and removes the instance directory.

There is no server capture-list endpoint and no identifier-only access to results. Every instance and job operation checks that instance's capability. Capabilities are generated in the Web Worker, sent in Authorization headers, and never written to localStorage/IndexedDB, URL parameters, cookies or logs. Temporary data lives under `/tmp`, mounted as tmpfs by Compose; `/data` and the old shared capture volume are not used.

**Browser profile is the storage boundary, not a user account.** Different devices, profiles and private contexts do not share data merely because they visit the same URL. Tabs in the same profile and origin share IndexedDB; people sharing that profile can access its files. Browser-data clearing/eviction removes locally stored data, so keep an external original. Host administrators can access transient analysis data; per-instance processes are not a security sandbox against a compromised TShark decoder.

## Existing deployments

Old server-volume files are **not** automatically imported: the former shared catalog does not establish which browser owns a file. This update detaches the old `capture_data` volume but does not delete it. Keep it for manual recovery and reopen each user's originals in their own browser. Do not use `docker compose down -v` to update. This deliberately removes the former shared `/api/captures` API; old direct API clients must adopt private instances/jobs.

## UI

The file list shows browser-local captures. The data surface remains the main view; status/error messages and a compact close action describe actual operations without adding setup screens. Right-click visible values or selected text to filter; selection alone opens no popup. Double-click records to pin them. Inspect/compare pins, resize panes and columns, and adjust font size as before.

The byte pane copies only hexadecimal bytes, excluding offsets/ASCII. Field selections and byte ranges are linked; generated or unmapped data is not assigned fictitious offsets. Field context menus distinguish decoded values, display values, and raw hexadecimal. Communication relationships use TShark's explicit request/response/ACK references, not inferred causality from timing alone.

## Runtime and API

| Boundary | Owner |
| --- | --- |
| `static/app/storage.worker.js` | IndexedDB transactions, opaque runtime handles, uploads, asynchronous job polling |
| `static/app/storage.js` | UI/worker RPC and cancellation |
| `app/main.py` | HTTP validation and capability-only instance/job endpoints |
| `app/instances.py` | Instance lifetime, process/queue ownership, job results and expiry |
| `app/analysis_worker.py` | One file's TShark calls and bounded process-local caches |
| `app/engine.py`, `filters.py`, `inspection.py`, `relationships.py` | Existing dissection and pure projections |

Create an instance with `POST /api/instances`, an octet-stream request body, and `Authorization: Bearer <64 lowercase random hex characters>`. The returned ID is not an access key. Submit `{operation: "packets"|"detail"|"relations", payload: {...}}` to `POST /api/instances/{id}/jobs`, poll its job URL, then delete the result. DELETE on an instance stops its process and deletes transient state. Every request needs its capability; IDs from another instance cannot be substituted.

Cancelled queued jobs are removed. Work already executing may finish with its result discarded; closing the instance terminates it. Uploads interrupted before completion are removed. Abrupt browser exit is bounded by idle expiry; a capability lost with an upload response can only leave a transient lease, never a shared library item.

`ANALYSIS_IDLE_SECONDS` defaults to 900; `MAX_ANALYSIS_INSTANCES` defaults to 32; `ANALYSIS_RUNTIME_DIR` defaults to `/tmp`; `MAX_UPLOAD_BYTES` defaults to 256 MiB. Run one Uvicorn HTTP process as the Docker command does: instances belong to that process, not a shared multi-worker registry. The server is not an authenticated user/account product and must be placed behind access control before public exposure. Session capabilities isolate operations, not admission or denial-of-service risk. Existing TShark output limits still apply.

## Verification

GitHub Actions runs Python unit/contract tests, builds the nonroot Docker image, and drives the actual container using Chromium. Existing interaction/layout/clipboard/flow tests remain, plus two independent browser contexts, unauthorized cross-instance reads/deletes/jobs, IndexedDB persistence, a real Docker restart, and isolated close/delete operations. Screenshots and test summaries are retained as artifacts. No production captures or session secrets are included in the fixtures/evidence. Live-capture CI uses real dumpcap on the runner host loopback with generated UDP traffic restricted to fixture ports, verifies manual stop and packet-limit stop, browser persistence and cross-browser access denial, and retains actual UI screenshots.

```sh
python -m pip install -r requirements.txt pytest httpx
pytest -q
for file in static/app/*.js; do node --check "$file"; done
```
