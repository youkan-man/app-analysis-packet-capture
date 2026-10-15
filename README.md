# Packet Capture Workbench

Docker-hosted offline PCAP/PCAPNG viewer backed by Wireshark TShark. The primary screen is a continuous packet list with protocol details and raw bytes; filtering stays available without taking over the data view.

## Run

```sh
docker compose up --build -d
```

Open `http://127.0.0.1:8080`. The default Compose binding is loopback-only. Captures are retained in the `capture_data` volume and are never sent to an external decoder.

## Packet inspection

- Continuous packet list: no page navigation. The browser virtualizes rows while the API returns one coherent filtered result.
- Wireshark-compatible PCAP and PCAPNG dissection through the installed TShark version.
- Packet summary, hierarchical protocol fields, and hexadecimal/ASCII bytes.
- Pin any record from the row button or context menu. Pins remain available while filtering.
- Compare two or more pinned records in a field-by-field table; optional “differences only” mode includes summary and decoded protocol values.

## Filtering without Wireshark syntax

Every value already visible on screen is a filter source:

- Right-click any packet-list value and choose “only this value,” “exclude,” “AND,” or “OR.”
- Select part of any text cell and filter by the selected substring.
- Right-click decoded protocol fields to create a validated native Wireshark-field rule.
- Open the compact filter drawer to edit column, operator, and value using normal controls. Active conditions stay visible as removable chips.
- When a filter is active, the context menu can show 1, 3, 5, or 10 records before and after each match. Nonmatching neighbours are translucent, so packet context remains visible without changing the match count.
- Named presets store the visual conditions, optional advanced expression, and neighbour setting.

The Wireshark expression textarea is kept under an **advanced** disclosure for users who already know display-filter syntax; normal filtering does not require it.

Visible-column rules (`No.`, `Time`, `Source`, `Destination`, `Protocol`, `Length`, `Info`) use one generic rule model. `Info` is not a separate UI or API feature. Protocol-tree rules are safely compiled behind the server boundary. Mixed OR-groups are evaluated as OR between groups and AND within each group.

## Architecture

| Boundary | Responsibility |
| --- | --- |
| `app/filters.py` | Typed generic column predicates, bounded rule schema, safe native-field compilation |
| `app/engine.py` | TShark execution, continuous row decoding, native-match sets, neighbour projection |
| `app/main.py` | Capture lifecycle and HTTP validation |
| `static/app.js` | Virtualized list, context actions, filter editor, pins, comparison, local view state |
| `static/style.css` | Dense data-first desktop/mobile layout |

TShark is invoked with `-r` only. The container does not capture live interfaces and needs no `NET_RAW`, `NET_ADMIN`, host networking, or privileged mode.

## Limits and security

The HTTP interface has no built-in multi-user authentication. Keep the default loopback binding or deploy behind an authenticated reverse proxy. Capture files may contain credentials and private payloads.

Default upload limit is 256 MiB. TShark row output is bounded to 32 MiB, advanced expressions to 2048 characters, visual filters to 8 OR-groups / 32 rules, and neighbour context to 50 records. Very large captures need a separate indexed/streaming backend.

## Validation

GitHub Actions performs:

1. Typed filter and injection-boundary unit tests.
2. Real TShark PCAP/PCAPNG integration, including mixed visual/native filters and neighbour projection.
3. JavaScript syntax, Docker image, nonroot container, and health checks.
4. Chromium journeys for continuous scrolling, right-click and selected-text filtering, filter drawer, translucent neighbours, pins, comparison, keyboard access, and mobile layout.
5. Screenshot artifacts for visual review.

```sh
python -m pip install -r requirements.txt pytest httpx
pytest -q
node --check static/app.js
docker build -t packet-capture-workbench .
```

## Skill guidance

The live Skill Server catalog is checked through Local Transport Gateway. The approved `design-code-boundaries` and `frontend-ui-constraints` Skills govern responsibility separation and mandatory real-screen screenshot review. No internal service address or credential is embedded in this repository.
