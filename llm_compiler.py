"""
Pluggable LLM Overview Compiler.
Supports any OpenAI-compatible provider (DeepSeek, OpenAI, Gemini, OneAPI, local LLM proxies).
Pure read-only presentation/explanation layer.
"""

import json
import urllib.request
import urllib.error
from pathlib import Path
from typing import Optional
from config import config
from db import get_db_connection


OVERVIEW_DOC_PATH = Path("/opt/server-agents-gateway/SERVER_AGENTS.md")
_MEMORY_CACHE: Optional[str] = None


def compile_overview_with_llm(reason: str = "scheduled or triggered rebuild") -> str:
    """
    Compiles an AI-augmented living overview using the configured OpenAI-compatible provider.
    """
    if not config.ai_provider_enabled:
        return _generate_fallback_overview()

    # Collect ground-truth facts
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT key, category, name, description, desired_state, observed_state, drift_status, lock_required FROM gateway_assets;")
        assets = [dict(r) for r in cursor.fetchall()]

        cursor.execute("SELECT timestamp, agent_id, action_type, target, intent_reason, status FROM gateway_audit_logs ORDER BY timestamp DESC LIMIT 5;")
        recent_logs = [dict(r) for r in cursor.fetchall()]

    prompt = f"""You are the Chief AI Architect for this Linux Server environment.
Compile an authoritative, clear, and beautiful Markdown document titled `SERVER_AGENTS.md`.

Context facts (100% verified ground truth):
- Registered Assets:
{json.dumps(assets, indent=2, ensure_ascii=False)}

- Recent Agent Operations:
{json.dumps(recent_logs, indent=2, ensure_ascii=False)}

Goal:
1. Explain the architectural role and relationships of these components.
2. Highlight which assets have mandatory lock protection (lock_required=1).
3. Warn about any drifted assets (if desired != observed).
4. Summarize recent agent activity.
5. Provide operational guidelines for incoming AI agents.

Make it clean, structured, and easy for any new Agent to understand in 30 seconds. Return only the Markdown text."""

    headers = {
        "Content-Type": "application/json",
    }
    if config.ai_provider_api_key:
        headers["Authorization"] = f"Bearer {config.ai_provider_api_key}"

    req_body = {
        "model": config.ai_provider_model,
        "messages": [
            {"role": "system", "content": "You are a concise, authoritative infrastructure architect."},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.3,
    }

    url = f"{config.ai_provider_base_url.rstrip('/')}/chat/completions"
    try:
        req = urllib.request.Request(url, data=json.dumps(req_body).encode("utf-8"), headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=config.ai_provider_timeout_seconds) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            content = data["choices"][0]["message"]["content"]
            _save_overview_document(content)
            return content
    except Exception as e:
        fallback = _generate_fallback_overview(error_note=f"LLM compilation failed ({str(e)}), generated deterministic view.")
        _save_overview_document(fallback)
        return fallback


def get_current_overview() -> str:
    global _MEMORY_CACHE
    if _MEMORY_CACHE:
        return _MEMORY_CACHE
    if OVERVIEW_DOC_PATH.exists():
        try:
            return OVERVIEW_DOC_PATH.read_text(encoding="utf-8")
        except Exception:
            pass
    return _generate_fallback_overview()


def _save_overview_document(text: str) -> None:
    global _MEMORY_CACHE
    _MEMORY_CACHE = text
    try:
        OVERVIEW_DOC_PATH.parent.mkdir(parents=True, exist_ok=True)
        OVERVIEW_DOC_PATH.write_text(text, encoding="utf-8")
    except Exception:
        pass


def _generate_fallback_overview(error_note: Optional[str] = None) -> str:
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT key, category, name, description, desired_state, observed_state, drift_status, lock_required FROM gateway_assets;")
        assets = cursor.fetchall()

    lines = ["# 🌐 Server Living Overview (SERVER_AGENTS.md)\n"]
    if error_note:
        lines.append(f"> ⚠️ Note: {error_note}\n")
    lines.append("## 📦 Registered Assets\n")
    lines.append("| Key | Category | Name | Desired | Observed | Drift | Lock Required | Description |")
    lines.append("| :--- | :--- | :--- | :--- | :--- | :--- | :---: | :--- |")
    for a in assets:
        lines.append(f"| `{a['key']}` | {a['category']} | {a['name']} | {a['desired_state']} | {a['observed_state']} | {a['drift_status']} | {'🔒 Yes' if a['lock_required'] else 'No'} | {a['description'] or ''} |")
    return "\n".join(lines)