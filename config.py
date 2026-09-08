"""
Configuration module for server-agents-gateway.
Supports environment variables and optional .env file.
"""

import os
from dataclasses import dataclass
from pathlib import Path


def _load_env_file(filepath: Path) -> None:
    if not filepath.exists():
        return
    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, val = line.split("=", 1)
            key = key.strip()
            val = val.strip().strip('"').strip("'")
            if key not in os.environ:
                os.environ[key] = val


# Load local .env if present
_env_path = Path(__file__).parent / ".env"
_load_env_file(_env_path)


@dataclass(frozen=True)
class Config:
    # Gateway Host & Network
    host: str = os.getenv("GATEWAY_HOST", "127.0.0.1")
    port: int = int(os.getenv("GATEWAY_PORT", "4180"))
    db_path: str = os.getenv("GATEWAY_DB_PATH", str(Path(__file__).parent / "data" / "gateway.db"))

    # Configurable Root Admin Identification (Only this Agent has token issuance/revocation authority)
    root_admin_agent_id: str = os.getenv("ROOT_ADMIN_AGENT_ID", "root:admin")

    # Configurable LLM Provider (OpenAI Compatible)
    ai_provider_enabled: bool = os.getenv("AI_PROVIDER_ENABLED", "true").lower() in ("true", "1", "yes")
    ai_provider_base_url: str = os.getenv("AI_PROVIDER_BASE_URL", "http://127.0.0.1:8080/v1")
    ai_provider_api_key: str = os.getenv("AI_PROVIDER_API_KEY", "")
    ai_provider_model: str = os.getenv("AI_PROVIDER_MODEL", "gemini-2.5-flash")
    ai_provider_timeout_seconds: int = int(os.getenv("AI_PROVIDER_TIMEOUT_SECONDS", "30"))

    # Concurrency & Lease defaults
    default_lease_ttl_seconds: int = int(os.getenv("DEFAULT_LEASE_TTL_SECONDS", "120"))

    # Periodic reconciliation interval (seconds)
    reconcile_interval_seconds: int = int(os.getenv("RECONCILE_INTERVAL_SECONDS", "60"))


config = Config()
