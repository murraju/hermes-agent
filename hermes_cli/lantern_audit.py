"""Best-effort Lantern security audit emission for managed Hermes sessions."""

from __future__ import annotations

import hashlib
import json
import os
import re
import urllib.error
import urllib.request
from typing import Any, Iterable

MAX_PREVIEW_CHARS = 512


def is_lantern_managed() -> bool:
    return os.getenv("HERMES_LANTERN_MANAGED", "").strip() == "1"


def emit_blocked_tool_event(
    function_name: str,
    function_args: dict | None,
    block_message: str,
    *,
    task_id: str = "",
    session_id: str = "",
    active_skill: str | None = None,
) -> bool:
    """Report a managed-mode tool denial to Lantern without raw args."""
    tool_name = str(function_name or "unknown")
    args = function_args if isinstance(function_args, dict) else {}
    preview_source = _preview_args(tool_name, args)
    return emit_security_event(
        {
            "event_type": "tool_blocked",
            "source": "hermes-agent",
            "surface": "agent-console",
            "session_id": session_id or "",
            "task_id": task_id or "",
            "terminal_id": os.getenv("LANTERN_TERMINAL_ID", ""),
            "scope_key": os.getenv("LANTERN_CONSOLE_SCOPE_KEY", ""),
            "requested_tool": tool_name,
            "requested_toolset": _toolset_for_tool(tool_name),
            "blocked_capability": _blocked_capability_for_tool(tool_name),
            "risk": _risk_for_tool(tool_name, preview_source),
            "reason": str(block_message or "blocked by Hermes managed-mode policy"),
            "active_skill": active_skill or "",
            "argument_hash": _sha256_json(args),
            "argument_preview_redacted": sanitize_preview(preview_source),
            "path_class": _path_class(preview_source),
        }
    )


def emit_toolset_change_blocked(
    requested_toolsets: Iterable[str],
    *,
    platform: str = "cli",
    reason: str = "Lantern managed runtime only allows Lantern MCP toolsets",
) -> bool:
    requested = sorted({str(item) for item in requested_toolsets if str(item).strip()})
    if not requested:
        return False
    preview = ", ".join(requested)
    return emit_security_event(
        {
            "event_type": "toolset_change_blocked",
            "source": "hermes-agent",
            "surface": "agent-console",
            "terminal_id": os.getenv("LANTERN_TERMINAL_ID", ""),
            "scope_key": os.getenv("LANTERN_CONSOLE_SCOPE_KEY", ""),
            "requested_toolset": sanitize_identifier(preview),
            "blocked_capability": "capability_escalation",
            "risk": "capability_escalation",
            "reason": reason,
            "argument_hash": _sha256_json({"platform": platform, "toolsets": requested}),
            "argument_preview_redacted": sanitize_preview(preview),
            "path_class": "none",
        }
    )


def emit_security_event(payload: dict[str, Any]) -> bool:
    if not is_lantern_managed():
        return False
    endpoint = _security_endpoint()
    token = os.getenv("LANTERN_BRIDGE_TOKEN", "").strip()
    if not endpoint or not token:
        return False

    body = json.dumps(_sanitize_payload(payload), separators=(",", ":")).encode("utf-8")
    request = urllib.request.Request(
        endpoint,
        data=body,
        method="POST",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=1.0) as response:
            return 200 <= getattr(response, "status", 0) < 300
    except (OSError, urllib.error.URLError, urllib.error.HTTPError, TimeoutError):
        return False


def sanitize_preview(value: str) -> str:
    text = str(value or "")
    replacements = [
        (r"(?i)Bearer\s+[A-Za-z0-9._\-]+", "Bearer <redacted>"),
        (r"(?i)LANTERN_BRIDGE_TOKEN\s*=\s*[^\s,;]+", "LANTERN_BRIDGE_TOKEN=<redacted>"),
        (
            r"(?i)(OPENAI|ANTHROPIC|GEMINI|GOOGLE|AWS|HUGGINGFACE|HF|FAL|LANTERN)[A-Z0-9_]*(API[_-]?KEY|TOKEN|SECRET)\s*=\s*[^\s,;]+",
            "<SECRET_REF>=<redacted>",
        ),
        (r"(?i)/Users/[^/\s\"']+(?:/[^\s\"']*)?", "<HOME>"),
        (r"(?i)/home/[^/\s\"']+(?:/[^\s\"']*)?", "<HOME>"),
        (r"(?i)~/?[^\s\"']*", "<HOME>"),
        (r"(?i)/(private|etc|var|Volumes|Library)(?:/[^\s\"']*)?", "<PATH>"),
        (r"(?i)\.(ssh|aws|env|gnupg)(?:/[^\s\"']*)?", "<SECRET_REF>"),
        (r"(?i)(id_rsa|id_ed25519|known_hosts|keychain|credentials)", "<SECRET_REF>"),
    ]
    for pattern, repl in replacements:
        text = re.sub(pattern, repl, text)
    text = text.strip()
    return text[:MAX_PREVIEW_CHARS] + ("..." if len(text) > MAX_PREVIEW_CHARS else "")


def sanitize_identifier(value: str, default: str = "unknown") -> str:
    text = re.sub(r"[^A-Za-z0-9_.:/-]", "", str(value or ""))[:128]
    return text or default


def _security_endpoint() -> str:
    explicit = os.getenv("LANTERN_SECURITY_AUDIT_URL", "").strip()
    if explicit:
        return explicit
    port = os.getenv("LANTERN_BRIDGE_PORT", "").strip()
    if port.isdigit():
        return f"http://127.0.0.1:{port}/security/events"
    return ""


def _sanitize_payload(payload: dict[str, Any]) -> dict[str, Any]:
    safe: dict[str, Any] = {}
    for key, value in payload.items():
        if key == "argument_preview_redacted":
            safe[key] = sanitize_preview(str(value or ""))
        elif key == "argument_hash":
            safe[key] = _sanitize_hash(str(value or ""))
        elif isinstance(value, str):
            safe[key] = sanitize_identifier(value) if key.endswith("_id") else sanitize_preview(value)
        else:
            safe[key] = value
    return safe


def _sanitize_hash(value: str) -> str:
    raw = value[7:] if value.startswith("sha256:") else value
    return f"sha256:{raw}" if re.fullmatch(r"[a-fA-F0-9]{64}", raw or "") else ""


def _sha256_json(value: Any) -> str:
    body = json.dumps(value, sort_keys=True, default=str, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(body.encode("utf-8")).hexdigest()


def _preview_args(tool_name: str, args: dict[str, Any]) -> str:
    for key in ("command", "path", "file_path", "url", "query", "content"):
        value = args.get(key)
        if isinstance(value, str) and value:
            return value
    try:
        return json.dumps(args, sort_keys=True, default=str)
    except Exception:
        return tool_name


def _toolset_for_tool(tool_name: str) -> str:
    lower = tool_name.lower()
    if "terminal" in lower or lower in {"bash", "shell"}:
        return "terminal"
    if "file" in lower or "read" in lower or "write" in lower:
        return "file"
    if "browser" in lower or "web" in lower:
        return "browser"
    if "provider" in lower or "credential" in lower:
        return "provider"
    return "unknown"


def _blocked_capability_for_tool(tool_name: str) -> str:
    toolset = _toolset_for_tool(tool_name)
    if toolset == "terminal":
        return "local_shell"
    if toolset == "file":
        return "local_filesystem"
    if toolset == "browser":
        return "network_egress"
    if toolset == "provider":
        return "provider_credentials"
    return "private_tool_surface"


def _risk_for_tool(tool_name: str, preview: str) -> str:
    lower = f"{tool_name} {preview}".lower()
    if any(marker in lower for marker in (".ssh", ".aws", ".env", "id_rsa", "keychain", "credential")):
        return "secret_access"
    if any(marker in lower for marker in ("curl ", "wget ", "upload", "exfiltrate", "send to", "post to")):
        return "network_egress"
    if _toolset_for_tool(tool_name) == "terminal":
        return "filesystem_exfiltration"
    if _toolset_for_tool(tool_name) == "file":
        return "local_file_access"
    return "capability_escalation"


def _path_class(preview: str) -> str:
    lower = preview.lower()
    if any(marker in lower for marker in (".ssh", ".aws", ".env", "id_rsa", "keychain", "credential")):
        return "secret_reference"
    if any(marker in lower for marker in ("~/", "/users/", "/home/")):
        return "home_directory"
    if any(marker in lower for marker in ("/etc/", "/private/", "/var/", "/volumes/")):
        return "system_path"
    return "none"
