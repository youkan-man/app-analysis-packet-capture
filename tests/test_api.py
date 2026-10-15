from io import BytesIO
import json
import shutil

from fastapi.testclient import TestClient
import pytest
import app.main as main

from tests.sample_capture import pcap, pcapng


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(main, "store", main.CaptureStore(tmp_path))
    with TestClient(main.app) as session:
        yield session


def upload(client, data, name="capture.pcap"):
    return client.post("/api/captures", files={"file": (name, BytesIO(data), "application/octet-stream")})


def view(*groups):
    return json.dumps({"groups": list(groups)})


def column(field, value, operator="equals"):
    return {"scope": "column", "field": field, "operator": operator, "value": value, "case_sensitive": False}


def native(field, value, kind="string", operator="equals"):
    return {"scope": "wireshark", "field": field, "operator": operator, "value": value, "kind": kind, "case_sensitive": False}


def test_health_upload_validation_and_delete(client):
    assert client.get("/healthz").json() == {"status": "ok"}
    assert upload(client, b"not a capture").status_code == 422
    capture = upload(client, pcap(), "../sample.pcap").json()
    assert capture["filename"] == "sample.pcap"
    assert client.delete("/api/captures/" + capture["id"]).status_code == 204
    assert client.get("/api/captures").json()["items"] == []


@pytest.mark.parametrize("data,fmt", [(pcap(), "pcap"), (pcapng(), "pcapng")])
def test_pcap_formats_accepted(client, data, fmt):
    result = upload(client, data).json()
    assert result["format"] == fmt


def test_filter_json_rejected_before_tshark(client):
    capture = upload(client, pcap()).json()
    base = f'/api/captures/{capture["id"]}/packets'
    assert client.get(base, params={"view": "{"}).status_code == 422
    assert client.get(base, params={"view": '{"groups":[[]]}'}).status_code == 422
    assert client.get(base, params={"context": 51}).status_code == 422


@pytest.mark.skipif(shutil.which("tshark") is None, reason="TShark is not installed")
def test_continuous_list_screen_filters_native_fields_and_neighbours(client):
    capture = upload(client, pcap()).json()
    base = f'/api/captures/{capture["id"]}/packets'

    all_rows = client.get(base)
    assert all_rows.status_code == 200, all_rows.text
    data = all_rows.json()
    assert data["total"] == data["matched"] == data["displayed"] == 7
    assert "page" not in data and "page_size" not in data
    assert [packet["number"] for packet in data["packets"]] == list(range(1, 8))

    source = client.get(base, params={"view": view([column("source", "192.0.2.10")])}).json()
    assert [packet["number"] for packet in source["packets"]] == [1, 5]
    assert source["matched"] == 2

    info = client.get(base, params={"view": view([column("info", "query", "contains")])}).json()
    assert [packet["number"] for packet in info["packets"]] == [1, 5]

    protocol = client.get(base, params={"view": view([column("protocol", "TCP")])}).json()
    assert [packet["number"] for packet in protocol["packets"]] == [2, 4, 6]

    union = client.get(base, params={"view": view(
        [column("source", "192.0.2.10")],
        [column("destination", "192.0.2.14")],
    )}).json()
    assert [packet["number"] for packet in union["packets"]] == [1, 5, 7]

    native_result = client.get(base, params={"view": view([native("ip.src", "203.0.113.3", "address")])}).json()
    assert [packet["number"] for packet in native_result["packets"]] == [6]

    combined = client.get(base, params={"raw": "tcp", "view": view([column("destination", "198.51.100.43")])}).json()
    assert [packet["number"] for packet in combined["packets"]] == [6]

    context = client.get(base, params={"view": view([column("number", "4")]), "context": 1}).json()
    assert [packet["number"] for packet in context["packets"]] == [3, 4, 5]
    assert [packet["is_match"] for packet in context["packets"]] == [False, True, False]
    assert [packet["context_distance"] for packet in context["packets"]] == [1, 0, 1]

    detail = client.get(base + "/1")
    assert detail.status_code == 200
    assert "frame" in detail.json()["layers"] and detail.json()["hex"].startswith("001122334455")
