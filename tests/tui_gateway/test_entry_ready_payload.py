import importlib


def test_gateway_ready_payload_includes_protocol_metadata(monkeypatch):
    entry = importlib.import_module("tui_gateway.entry")
    events = []
    monkeypatch.setattr(entry, "resolve_skin", lambda: {"theme": "test"})
    monkeypatch.setattr(entry, "write_json", lambda payload: events.append(payload) or False)
    monkeypatch.setattr(entry.sys, "exit", lambda code=0: (_ for _ in ()).throw(SystemExit(code)))

    try:
        entry.main()
    except SystemExit:
        pass

    assert events
    payload = events[0]["params"]["payload"]
    assert payload["protocol_version"] == entry.GATEWAY_PROTOCOL_VERSION
    assert payload["capabilities"]["lantern_agent_plane"]["ready_metadata"] is True
    assert "LANTERN_BRIDGE_TOKEN" in payload["capabilities"]["lantern_agent_plane"]["bridge_env"]
