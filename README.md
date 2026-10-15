# Packet Capture Workbench

Docker-hosted PCAP/PCAPNG inspection using Wireshark TShark. Packet contents remain the main workspace; filters, comparison and communication analysis open alongside the data.

## Run / update

```sh
docker compose up --build -d
```

Open `http://127.0.0.1:8080`. After pulling a new revision, run the same command to rebuild. Captures remain in the `capture_data` volume. Processing is offline; no live network-interface privileges are required.

## Inspect and copy

The continuous packet list uses virtualized rows without page controls. Select a record to inspect its protocol tree and hex/ASCII bytes.

- Select a protocol field to highlight the corresponding bytes in both hex and ASCII. Click or drag bytes to select the most specific enclosing field; its ancestors open automatically. Shift-click and keyboard arrows extend the byte selection.
- **バイト列をコピー** copies the selection, or all captured bytes when nothing is selected. Output is space-separated hexadecimal text only: no offsets or ASCII column. The byte context menu also provides compact hexadecimal. Ctrl/Cmd+C and Ctrl/Cmd+A operate inside the byte pane.
- Protocol-element context menus distinguish **値をコピー** (decoded value), **表示値をコピー** (the full rendered field description), and **生値（16進）をコピー** (TShark's raw field representation where available).
- Repeated fields keep separate occurrence IDs. Byte offsets are linked only when TShark's unmasked raw field bytes agree with the captured-frame slice. Generated fields, unavailable bytes and unmapped reassembled/transformed data remain visible and copyable but are not assigned invented byte ranges.

## Layout

Default UI font is 12 px, with 11 px data text. The **文字** selector supports 10–16 px. Drag the dividers between files/data, list/inspectors, protocol details/bytes, and the right drawer. Comparison height and table-column widths are adjustable too. Focus a divider and use arrow keys (Shift for a larger step), or Home/double-click to reset. Geometry and font choice are saved in the current browser. On narrow screens the inspector divider becomes horizontal.

## Screen-driven filters, pins and comparison

Every displayed packet column uses the same filter mechanism; Info has no dedicated search feature. Right-click a value to include, exclude or combine it with AND/OR. Select part of a text value to filter by that substring. Protocol-tree fields can also become typed rules; Wireshark syntax is not needed for these operations. The optional raw expression remains under an advanced disclosure.

The filter context menu offers translucent records before and after each match. These rows do not count as matches. Pins remain available across filtering and are saved per capture in the browser. Two or more pins can be compared field-by-field, with a differences-only option.

## Send/receive hierarchy

Select **通信階層** or right-click a record and choose **送受信の階層を解析**. The selected record becomes the fixed analysis anchor. The panel shows its protocol stack, endpoints, TCP/UDP stream, direction counts, and related records. Clicking a record inspects its contents without replacing the anchor or clearing the active filter.

Relations come from two-pass TShark frame references: DNS/HTTP/ICMP request–response links, TCP acknowledgements, duplicate ACKs and reassembly references supported by the installed version. Labels expose their source field names and time differences. Reverse-direction traffic alone is not classified as an application response, and TCP ACKs are not HTTP/DNS responses. Encrypted or unsupported application protocols may show stream/direction only. Missing relationships are marked as unconfirmed, not guessed. This is capture-local evidence, not cross-host causal tracing or an inferred service call graph.

## Security / limits

There is no built-in multi-user authentication. Keep the default loopback port binding or use an authenticated reverse proxy. Anyone with access can read/remove captures; capture payloads can be sensitive. The container runs nonroot with capabilities dropped.

Upload limit defaults to 256 MiB. TShark result limits are 32 MiB for rows and 8 MiB for individual inspections; visual filters allow 8 groups / 32 rules, raw expressions 2048 characters, and neighbour context at most 50 records. Large captures are reprocessed for queries; this is not a disk-indexed multi-gigabyte capture engine. Analysis depends on the image's installed TShark dissectors.

## Verification

GitHub Actions runs Python schema/unit tests and real TShark capture integration, builds the Docker image, and drives that actual nonroot container with Chromium. The browser journeys check generic filters, pins/comparison, clipboard contents, byte/field selection, resize persistence, fonts and DNS/HTTP/ACK hierarchy. Synthetic fixtures and screenshot evidence are retained in the run artifacts along with the exact tested source.

```sh
python -m pip install -r requirements.txt pytest httpx
pytest -q
for file in static/app/*.js; do node --check "$file"; done
```
