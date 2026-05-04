import json
import urllib.error

from hermes_cli import lantern_audit


class _Response:
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False


def test_non_managed_mode_emits_nothing(monkeypatch):
    calls = []
    monkeypatch.delenv("HERMES_LANTERN_MANAGED", raising=False)
    monkeypatch.setenv("LANTERN_BRIDGE_TOKEN", "secret-token")
    monkeypatch.setenv("LANTERN_SECURITY_AUDIT_URL", "http://127.0.0.1:49152/security/events")
    monkeypatch.setattr("urllib.request.urlopen", lambda *args, **kwargs: calls.append(args))

    assert lantern_audit.emit_blocked_tool_event("terminal", {"command": "ls"}, "blocked") is False
    assert calls == []


def test_blocked_tool_event_posts_sanitized_payload(monkeypatch):
    captured = {}

    def fake_urlopen(request, timeout):
        captured["request"] = request
        captured["timeout"] = timeout
        captured["body"] = request.data
        return _Response()

    monkeypatch.setenv("HERMES_LANTERN_MANAGED", "1")
    monkeypatch.setenv("LANTERN_BRIDGE_TOKEN", "secret-token")
    monkeypatch.setenv("LANTERN_SECURITY_AUDIT_URL", "http://127.0.0.1:49152/security/events")
    monkeypatch.setenv("LANTERN_TERMINAL_ID", "terminal-1")
    monkeypatch.setenv("LANTERN_CONSOLE_SCOPE_KEY", "all_media")
    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    ok = lantern_audit.emit_blocked_tool_event(
        "terminal",
        {"command": "cd /Users/rajum/.ssh && cat id_rsa"},
        "blocked by managed runtime",
        task_id="task-1",
        session_id="session-1",
        active_skill="rogue-skill",
    )

    assert ok is True
    payload = json.loads(captured["body"].decode("utf-8"))
    assert payload["event_type"] == "tool_blocked"
    assert payload["requested_tool"] == "terminal"
    assert payload["terminal_id"] == "terminal-1"
    assert payload["scope_key"] == "all_media"
    assert payload["risk"] == "secret_access"
    assert payload["argument_hash"].startswith("sha256:")
    assert "/Users/rajum" not in json.dumps(payload)
    assert "secret-token" not in json.dumps(payload)
    assert "id_rsa" not in payload["argument_preview_redacted"]
    assert captured["request"].get_header("Authorization") == "Bearer secret-token"
    assert captured["timeout"] == 1.0


def test_audit_post_failure_is_non_blocking(monkeypatch):
    def fail_urlopen(*_args, **_kwargs):
        raise urllib.error.URLError("offline")

    monkeypatch.setenv("HERMES_LANTERN_MANAGED", "1")
    monkeypatch.setenv("LANTERN_BRIDGE_TOKEN", "secret-token")
    monkeypatch.setenv("LANTERN_SECURITY_AUDIT_URL", "http://127.0.0.1:49152/security/events")
    monkeypatch.setattr("urllib.request.urlopen", fail_urlopen)

    assert lantern_audit.emit_blocked_tool_event("file_read", {"path": "~/.env"}, "blocked") is False


def test_toolset_change_blocked_payload_uses_capability_escalation(monkeypatch):
    captured = {}

    def fake_urlopen(request, timeout):
        captured["body"] = request.data
        return _Response()

    monkeypatch.setenv("HERMES_LANTERN_MANAGED", "1")
    monkeypatch.setenv("LANTERN_BRIDGE_TOKEN", "secret-token")
    monkeypatch.setenv("LANTERN_SECURITY_AUDIT_URL", "http://127.0.0.1:49152/security/events")
    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    assert lantern_audit.emit_toolset_change_blocked(["terminal", "file"]) is True
    payload = json.loads(captured["body"].decode("utf-8"))
    assert payload["event_type"] == "toolset_change_blocked"
    assert payload["risk"] == "capability_escalation"
    assert payload["blocked_capability"] == "capability_escalation"
