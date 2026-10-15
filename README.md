# Packet Capture Workbench

Docker-hosted, Wireshark-compatible offline packet file viewer. A Wireshark TShark process dissects capture data server-side; the Web UI provides a three-pane packet explorer and an enhanced visual display-filter builder.

## Run

From the repository root, run:

    docker compose up --build -d

Then open http://127.0.0.1:8080 on the Docker host. Compose binds only to loopback by default. Change the port binding or place the app behind an authenticated reverse proxy for LAN access.

Drag/drop or upload a PCAP or PCAPNG capture. The application stores capture files in the named Docker volume (capture_data), preserving files across container restarts. The app does not connect to Wireshark.org or an external decoder.

## Capabilities

- Wireshark-compatible PCAP / PCAPNG offline file formats.
- Packet list with relative time, source, destination, protocol, length and Info.
- Selection-based protocol tree and raw hexadecimal / ASCII byte viewer.
- Unmodified Wireshark display-filter expressions passed to the installed TShark (-Y).
- Visual filter editor with nested AND/OR groups, NOT, exists, typed string/number/IP-MAC values, comparisons, contains and matches.
- Real installed TShark field lookup, quick protocol filter presets, saved filters, paging, keyboard shortcuts, drag and drop.
- Dense desktop and responsive mobile layout.

## Architecture

- app/filters.py: Pure validation and visual filter compilation; no subprocess or persistence.
- app/engine.py: TShark subprocess and protocol extraction. TShark reads only capture files, no live device capture.
- app/main.py: HTTP routes, file-id validation and persisted file metadata.
- static/app.js: User interaction and browser-local saved display filters; never executes raw HTML.
- static/style.css: UI layout.

The Docker container is nonroot, does not need network capture privileges, and drops Linux capabilities. Neither live packet capture nor privileged device access is implemented. Display-filter compatibility depends on the TShark version bundled by Debian. Unsupported dissectors or vendor-specific decoders are not silently implemented.

## Security and bounds

This service is NOT an authenticated multi-user product. Treat PCAP files as sensitive and host it on loopback or behind an authenticated reverse proxy; anyone able to access its HTTP interface can read and remove uploaded captures. Upload limit defaults to 256 MiB, expression length to 2048 characters, and TShark list-output limit to 32 MiB. Larger datasets require a streaming/indexed backend. Each filtered page currently re-processes the capture file in TShark.

## Validation

GitHub Actions workflow Build and verify runs:

1. Python unit and FastAPI tests, including deterministic PCAP and PCAPNG integration decoded using real TShark.
2. Frontend JavaScript syntax validation.
3. Docker image build, isolated nonroot container and health smoke test.
4. Real Chromium browser actions for upload, rule builder, Wireshark text filter and responsive layout.
5. Browser screenshots captured as Actions artifacts (packets-desktop.png, filter-builder-desktop.png, packets-mobile.png).

Local run (with Wireshark/TShark installed):

    python -m pip install -r requirements.txt pytest httpx
    pytest -q
    node --check static/app.js
    docker build -t packet-capture-workbench .

## Skill Server provenance

Local Transport Gateway was used to discover the Skill Server live catalog and mandatory application priority policy. Design applies approved design-code-boundaries and frontend-ui-constraints guidance; CI browser screenshots provide required visual review evidence, which must be inspected before declaring visual acceptance. The approval metadata is dynamic; do not cache it as execution authority. No credentials, relay tokens or fixed internal IP addresses are recorded in this repository.
