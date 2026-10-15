from io import BytesIO
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


def test_health_invalid_capture_and_file_not_found(client):
    assert client.get("/healthz").json() == {"status": "ok"}
    assert upload(client, b"this is not a capture").status_code == 422
    assert client.get("/api/captures").json()["items"] == []
    assert client.get("/api/captures/" + "a" * 32 + "/packets").status_code == 404


@pytest.mark.parametrize("data,fmt", [(pcap(), "pcap"), (pcapng(), "pcapng")])
def test_pcap_and_pcapng_are_accepted(client, data, fmt):
    reply = upload(client, data, "../uploaded.pcapng")
    assert reply.status_code == 201, reply.text
    capture = reply.json()
    assert capture["format"] == fmt
    assert capture["filename"] == "uploaded.pcapng"
    assert len(client.get("/api/captures").json()["items"]) == 1
    assert client.delete("/api/captures/" + capture["id"]).status_code == 204
    assert client.get("/api/captures").json()["items"] == []


@pytest.mark.skipif(shutil.which("tshark") is None, reason="TShark is not installed")
def test_tshark_packets_filters_details_and_invalid_syntax(client):
    capture = upload(client, pcap()).json()
    base = "/api/captures/" + capture["id"] + "/packets"
    all_packets = client.get(base)
    assert all_packets.status_code == 200, all_packets.text
    assert all_packets.json()["total"] == 2
    assert all_packets.json()["packets"][0]["source"] == "192.0.2.10"

    dns = client.get(base, params={"filter": "dns"})
    assert dns.status_code == 200, dns.text
    assert dns.json()["total"] == 1
    assert dns.json()["packets"][0]["number"] == 1

    tcp = client.get(base, params={"filter": "tcp.port == 443"})
    assert tcp.status_code == 200, tcp.text
    assert tcp.json()["total"] == 1
    assert tcp.json()["packets"][0]["number"] == 2
    assert client.get(base, params={"page": 2, "limit": 1}).json()["packets"][0]["number"] == 2
    assert client.get(base, params={"filter": "tcp and ("}).status_code == 422

    detail = client.get(base + "/1")
    assert detail.status_code == 200, detail.text
    assert "frame" in detail.json()["layers"]
    assert "ip" in detail.json()["layers"]
    assert detail.json()["hex"].startswith("001122334455")


@pytest.mark.skipif(shutil.which("tshark") is None, reason="TShark is not installed")
def test_pcapng_dissected(client):
    capture = upload(client, pcapng()).json()
    reply = client.get("/api/captures/" + capture["id"] + "/packets")
    assert reply.status_code == 200, reply.text
    assert reply.json()["total"] == 2


def test_compiler_endpoint(client):
    node = {"type": "group", "join": "or", "children": [
        {"type": "rule", "field": "ip.addr", "operator": "==", "kind": "address", "value": "192.0.2.10"}
    ]}
    reply = client.post("/api/filters/compile", json={"node": node})
    assert reply.status_code == 200
    assert reply.json()["expression"] == "(ip.addr == 192.0.2.10)"
    bad = client.post("/api/filters/compile", json={"node": {"type": "rule", "field": "&&"}})
    assert bad.status_code == 422


def test_info_query_json_validation(client):
    upload_result = upload(client, pcap()).json()
    base = "/api/captures/" + upload_result["id"] + "/packets"
    assert client.get(base, params={"info": "broken{"}).status_code == 422
    assert client.get(base, params={"info": '{"groups":[[]]}'}).status_code == 422
    assert client.get(base, params={"info": '{"groups":[[{"operator":"contains","value":"x","case_sensitive":"true"}]]}'}).status_code == 422


@pytest.mark.skipif(shutil.which("tshark") is None, reason="TShark is not installed")
def test_info_filters_apply_before_pagination_and_combine_with_tshark(client):
    import json
    capture = upload(client, pcap()).json()
    base = "/api/captures/" + capture["id"] + "/packets"

    def info(*groups):
        return json.dumps({"groups": list(groups)})

    include = {"operator": "contains", "value": "query", "case_sensitive": False}
    exclude = {"operator": "not_contains", "value": "query", "case_sensitive": False}
    selected = client.get(base, params={"info": info([include]), "limit": 1})
    assert selected.status_code == 200, selected.text
    assert selected.json()["total"] == 1
    assert selected.json()["packets"][0]["number"] == 1
    assert selected.json()["packets"][0]["fields"]["ip.src"] == "192.0.2.10"

    other = client.get(base, params={"info": info([exclude])})
    assert other.json()["total"] == 1
    assert other.json()["packets"][0]["number"] == 2
    assert other.json()["packets"][0]["fields"]["tcp.dstport"] == "443"

    union = client.get(base, params={"info": info([include], [exclude])})
    assert union.json()["total"] == 2
    assert union.json()["packets"][1]["number"] == 2

    combined = client.get(base, params={"filter": "tcp", "info": info([include])})
    assert combined.status_code == 200
    assert combined.json()["total"] == 0

    both = client.get(base, params={"info": info([include, {
        "operator": "contains", "value": "example.com", "case_sensitive": False
    }])})
    assert both.json()["total"] == 1

    uppercase = client.get(base, params={"info": info([{
        "operator": "contains", "value": "QUERY", "case_sensitive": True
    }])})
    assert uppercase.json()["total"] == 0

    # The Info clause must match all packets before slicing the requested page.
    no_second = client.get(base, params={"info": info([include]), "page": 2, "limit": 1})
    assert no_second.json()["packets"] == []
    assert no_second.json()["total"] == 1
