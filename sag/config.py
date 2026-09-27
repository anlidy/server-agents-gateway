"""
Configuration module for server-agents-gateway.
Supports environment variables and optional .env file.
"""

import os
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit


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


_PACKAGE_DIR = Path(__file__).resolve().parent
_GATEWAY_ROOT = _PACKAGE_DIR.parent
_load_env_file(_GATEWAY_ROOT / ".env")


def resolve_config_path(value: str, root: Path | None = None) -> Path:
    """Resolve a config path. Relative values are anchored at gateway root, not cwd."""
    base = Path(root) if root is not None else _GATEWAY_ROOT
    p = Path(value).expanduser()
    if not p.is_absolute():
        p = base / p
    return p.resolve()


def _default_shell_cwd() -> str:
    explicit = os.getenv("GATEWAY_SHELL_CWD", "").strip()
    if explicit:
        return str(resolve_config_path(explicit))
    home = os.getenv("HOME", "").strip()
    if home and Path(home).is_dir():
        return str(Path(home).expanduser().resolve())
    return "/"


_DEFAULT_OAUTH_REDIRECT_URIS = (
    "https://claude.ai/api/mcp/auth_callback,https://claude.com/api/mcp/auth_callback,loopback"
)


def _csv(value: str) -> tuple:
    return tuple(v.strip() for v in value.split(",") if v.strip())


@dataclass(frozen=True)
class Config:
    gateway_root: str = str(_GATEWAY_ROOT.resolve())
    host: str = os.getenv("GATEWAY_HOST", "127.0.0.1")
    port: int = int(os.getenv("GATEWAY_PORT", "4180"))
    db_path: str = str(
        resolve_config_path(os.getenv("GATEWAY_DB_PATH", str(_GATEWAY_ROOT / "data" / "gateway.db")))
    )
    overview_path: str = str(
        resolve_config_path(
            os.getenv("GATEWAY_OVERVIEW_PATH", str(_GATEWAY_ROOT / "SERVER_AGENTS.md"))
        )
    )
    root_admin_agent_id: str = os.getenv("ROOT_ADMIN_AGENT_ID", "root:admin")
    shell_cwd: str = _default_shell_cwd()
    shell_timeout_seconds: int = int(os.getenv("GATEWAY_SHELL_TIMEOUT_SECONDS", "120"))
    shell_timeout_max: int = int(os.getenv("GATEWAY_SHELL_TIMEOUT_MAX", "3600"))
    audit_body_max_bytes: int = int(os.getenv("GATEWAY_AUDIT_BODY_MAX_BYTES", str(2 * 1024 * 1024)))
    trash_retention_days: int = int(os.getenv("GATEWAY_TRASH_RETENTION_DAYS", "30"))
    reconcile_interval_seconds: int = int(os.getenv("RECONCILE_INTERVAL_SECONDS", "60"))
    # OAuth（claude.ai 连接器）。设了 GATEWAY_PUBLIC_URL 才启用，见 sag/oauth.py。
    public_url: str = os.getenv("GATEWAY_PUBLIC_URL", "").strip().rstrip("/")
    oauth_redirect_uris: tuple = _csv(os.getenv("GATEWAY_OAUTH_REDIRECT_URIS", _DEFAULT_OAUTH_REDIRECT_URIS))
    oauth_access_ttl_minutes: int = int(os.getenv("GATEWAY_OAUTH_ACCESS_TTL_MINUTES", "60"))
    oauth_refresh_ttl_days: int = int(os.getenv("GATEWAY_OAUTH_REFRESH_TTL_DAYS", "30"))
    oauth_pairing_ttl_minutes: int = int(os.getenv("GATEWAY_OAUTH_PAIRING_TTL_MINUTES", "10"))
    # 公网域名（默认就是 GATEWAY_PUBLIC_URL 的主机名）前面没有 CF Access，只收 OAuth 令牌，
    # 静态 sag_ token 在这些域名上一律 401：静态 token 泄露了也还得过 CF Access 那一关。
    oauth_only_hosts: tuple = _csv(
        os.getenv("GATEWAY_OAUTH_ONLY_HOSTS", urlsplit(os.getenv("GATEWAY_PUBLIC_URL", "")).hostname or "")
    )
    # Kept so existing .env files still load; unused in v2.
    ai_provider_enabled: bool = os.getenv("AI_PROVIDER_ENABLED", "true").lower() in ("true", "1", "yes")
    ai_provider_base_url: str = os.getenv("AI_PROVIDER_BASE_URL", "http://127.0.0.1:8080/v1")
    ai_provider_api_key: str = os.getenv("AI_PROVIDER_API_KEY", "")
    ai_provider_model: str = os.getenv("AI_PROVIDER_MODEL", "gemini-2.5-flash")
    ai_provider_timeout_seconds: int = int(os.getenv("AI_PROVIDER_TIMEOUT_SECONDS", "30"))
    default_lease_ttl_seconds: int = int(os.getenv("DEFAULT_LEASE_TTL_SECONDS", "120"))

    @property
    def wrappers_dir(self) -> Path:
        return (Path(self.gateway_root) / "wrappers").resolve()

    @property
    def data_dir(self) -> Path:
        return Path(self.db_path).resolve().parent


config = Config()
