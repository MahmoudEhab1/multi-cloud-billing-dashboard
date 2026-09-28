"""SQLite-backed provider registry for the billing dashboard.

Cloud secrets are encrypted at rest with Fernet. The encryption key is read
from PROVIDER_ENCRYPTION_KEY in the application's .env file.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from cryptography.fernet import Fernet, InvalidToken
from werkzeug.security import check_password_hash, generate_password_hash

APP_ROOT = Path(os.environ.get("APP_ROOT", Path(__file__).resolve().parent))
DB_PATH = Path(os.environ.get("PROVIDER_DATABASE", APP_ROOT / "data" / "providers.db"))
SLUG_RE = re.compile(r"^[a-z][a-z0-9-]{1,39}$")
PROVIDER_TYPES = {"aws", "oci_tenant", "portal", "hetzner"}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _json_load(value: str | None) -> dict[str, Any]:
    if not value:
        return {}
    try:
        result = json.loads(value)
        return result if isinstance(result, dict) else {}
    except (TypeError, ValueError):
        return {}


class ProviderStore:
    def __init__(self, db_path: str | os.PathLike[str] | None = None) -> None:
        self.db_path = Path(db_path or DB_PATH)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.init_db()

    @contextmanager
    def connect(self) -> Iterable[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path, timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def init_db(self) -> None:
        with self.connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS providers (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    slug TEXT NOT NULL UNIQUE,
                    name TEXT NOT NULL,
                    provider_type TEXT NOT NULL,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    telegram_enabled INTEGER NOT NULL DEFAULT 1,
                    display_order INTEGER NOT NULL DEFAULT 100,
                    icon TEXT NOT NULL DEFAULT '☁',
                    accent TEXT NOT NULL DEFAULT '#3B82F6',
                    currency TEXT NOT NULL DEFAULT 'USD',
                    region TEXT NOT NULL DEFAULT '',
                    config_json TEXT NOT NULL DEFAULT '{}',
                    access_key_id_enc TEXT,
                    secret_access_key_enc TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    deleted_at TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_providers_enabled_order
                    ON providers(enabled, display_order, id);

                CREATE TABLE IF NOT EXISTS provider_status (
                    provider_id INTEGER PRIMARY KEY,
                    last_test_at TEXT,
                    last_test_ok INTEGER,
                    last_success_at TEXT,
                    last_error TEXT,
                    FOREIGN KEY(provider_id) REFERENCES providers(id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS admin_audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    action TEXT NOT NULL,
                    provider_id INTEGER,
                    details TEXT,
                    remote_addr TEXT,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                """
            )

    def _fernet(self) -> Fernet:
        key = os.environ.get("PROVIDER_ENCRYPTION_KEY", "").strip()
        if not key:
            raise RuntimeError("PROVIDER_ENCRYPTION_KEY is missing from .env")
        try:
            return Fernet(key.encode("ascii"))
        except Exception as exc:
            raise RuntimeError("PROVIDER_ENCRYPTION_KEY is invalid") from exc

    def encrypt(self, value: str | None) -> str | None:
        if not value:
            return None
        return self._fernet().encrypt(value.encode("utf-8")).decode("ascii")

    def decrypt(self, value: str | None) -> str:
        if not value:
            return ""
        try:
            return self._fernet().decrypt(value.encode("ascii")).decode("utf-8")
        except InvalidToken as exc:
            raise RuntimeError("Unable to decrypt provider credentials") from exc

    @staticmethod
    def validate_slug(slug: str) -> str:
        slug = (slug or "").strip().lower()
        if not SLUG_RE.fullmatch(slug):
            raise ValueError("Slug must start with a letter and use only lowercase letters, digits, or hyphens")
        return slug

    @staticmethod
    def validate_type(provider_type: str) -> str:
        if provider_type not in PROVIDER_TYPES:
            raise ValueError("Unsupported provider type")
        return provider_type

    @staticmethod
    def _row_to_provider(row: sqlite3.Row, *, include_secrets: bool = False) -> dict[str, Any]:
        provider = dict(row)
        provider["enabled"] = bool(provider["enabled"])
        provider["telegram_enabled"] = bool(provider["telegram_enabled"])
        provider["config"] = _json_load(provider.pop("config_json", "{}"))
        if not include_secrets:
            provider.pop("access_key_id_enc", None)
            provider.pop("secret_access_key_enc", None)
        return provider

    def list_providers(
        self,
        *,
        enabled_only: bool = False,
        telegram_only: bool = False,
        include_deleted: bool = False,
    ) -> list[dict[str, Any]]:
        where: list[str] = []
        params: list[Any] = []
        if not include_deleted:
            where.append("p.deleted_at IS NULL")
        if enabled_only:
            where.append("p.enabled = 1")
        if telegram_only:
            where.append("p.telegram_enabled = 1")
        clause = " WHERE " + " AND ".join(where) if where else ""
        query = f"""
            SELECT p.*,
                   s.last_test_at, s.last_test_ok, s.last_success_at, s.last_error
            FROM providers p
            LEFT JOIN provider_status s ON s.provider_id = p.id
            {clause}
            ORDER BY p.display_order, p.id
        """
        with self.connect() as conn:
            return [self._row_to_provider(row) for row in conn.execute(query, params)]

    def get_provider(self, provider_id: int, *, include_deleted: bool = False) -> dict[str, Any] | None:
        clause = "" if include_deleted else " AND p.deleted_at IS NULL"
        with self.connect() as conn:
            row = conn.execute(
                f"""
                SELECT p.*,
                       s.last_test_at, s.last_test_ok, s.last_success_at, s.last_error
                FROM providers p
                LEFT JOIN provider_status s ON s.provider_id = p.id
                WHERE p.id = ? {clause}
                """,
                (provider_id,),
            ).fetchone()
        return self._row_to_provider(row) if row else None

    def get_by_slug(self, slug: str, *, enabled_only: bool = False) -> dict[str, Any] | None:
        extra = " AND p.enabled = 1" if enabled_only else ""
        with self.connect() as conn:
            row = conn.execute(
                f"""
                SELECT p.*,
                       s.last_test_at, s.last_test_ok, s.last_success_at, s.last_error
                FROM providers p
                LEFT JOIN provider_status s ON s.provider_id = p.id
                WHERE p.slug = ? AND p.deleted_at IS NULL {extra}
                """,
                (slug,),
            ).fetchone()
        return self._row_to_provider(row) if row else None

    def get_credentials(self, provider_id: int) -> dict[str, str]:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT access_key_id_enc, secret_access_key_enc FROM providers WHERE id = ? AND deleted_at IS NULL",
                (provider_id,),
            ).fetchone()
        if not row:
            raise KeyError("Provider not found")
        return {
            "access_key_id": self.decrypt(row["access_key_id_enc"]),
            "secret_access_key": self.decrypt(row["secret_access_key_enc"]),
        }

    def create_provider(self, data: dict[str, Any], credentials: dict[str, str] | None = None) -> int:
        slug = self.validate_slug(str(data.get("slug", "")))
        provider_type = self.validate_type(str(data.get("provider_type", "")))
        name = str(data.get("name", "")).strip()
        if not name:
            raise ValueError("Dashboard name is required")
        if provider_type in {"portal", "hetzner"}:
            with self.connect() as conn:
                duplicate = conn.execute(
                    "SELECT id FROM providers WHERE provider_type = ? AND deleted_at IS NULL",
                    (provider_type,),
                ).fetchone()
            if duplicate:
                label = "External Portal" if provider_type == "portal" else "Hetzner"
                raise ValueError(f"Only one {label} dashboard can be configured")
        now = utc_now()
        credentials = credentials or {}
        with self.connect() as conn:
            cur = conn.execute(
                """
                INSERT INTO providers (
                    slug, name, provider_type, enabled, telegram_enabled,
                    display_order, icon, accent, currency, region, config_json,
                    access_key_id_enc, secret_access_key_enc, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    slug,
                    name,
                    provider_type,
                    int(bool(data.get("enabled", True))),
                    int(bool(data.get("telegram_enabled", True))),
                    int(data.get("display_order", 100)),
                    str(data.get("icon", "☁")).strip() or "☁",
                    str(data.get("accent", "#3B82F6")).strip() or "#3B82F6",
                    str(data.get("currency", "USD")).strip().upper() or "USD",
                    str(data.get("region", "")).strip(),
                    json.dumps(data.get("config", {}), separators=(",", ":")),
                    self.encrypt(credentials.get("access_key_id")),
                    self.encrypt(credentials.get("secret_access_key")),
                    now,
                    now,
                ),
            )
            provider_id = int(cur.lastrowid)
        return provider_id

    def update_provider(
        self,
        provider_id: int,
        data: dict[str, Any],
        credentials: dict[str, str] | None = None,
    ) -> None:
        existing = self.get_provider(provider_id)
        if not existing:
            raise KeyError("Provider not found")
        slug = self.validate_slug(str(data.get("slug", existing["slug"])))
        provider_type = self.validate_type(str(data.get("provider_type", existing["provider_type"])))
        name = str(data.get("name", existing["name"])).strip()
        if not name:
            raise ValueError("Dashboard name is required")
        if provider_type == "portal":
            with self.connect() as conn:
                duplicate = conn.execute(
                    "SELECT id FROM providers WHERE provider_type = 'portal' AND deleted_at IS NULL AND id != ?",
                    (provider_id,),
                ).fetchone()
            if duplicate:
                raise ValueError("Only one External Portal dashboard can be configured")
        credentials = credentials or {}
        assignments = [
            "slug = ?", "name = ?", "provider_type = ?", "enabled = ?",
            "telegram_enabled = ?", "display_order = ?", "icon = ?",
            "accent = ?", "currency = ?", "region = ?", "config_json = ?",
            "updated_at = ?",
        ]
        values: list[Any] = [
            slug,
            name,
            provider_type,
            int(bool(data.get("enabled", existing["enabled"]))),
            int(bool(data.get("telegram_enabled", existing["telegram_enabled"]))),
            int(data.get("display_order", existing["display_order"])),
            str(data.get("icon", existing["icon"])).strip() or existing["icon"],
            str(data.get("accent", existing["accent"])).strip() or existing["accent"],
            str(data.get("currency", existing["currency"])).strip().upper() or existing["currency"],
            str(data.get("region", existing["region"])).strip(),
            json.dumps(data.get("config", existing["config"]), separators=(",", ":")),
            utc_now(),
        ]
        if credentials.get("access_key_id"):
            assignments.append("access_key_id_enc = ?")
            values.append(self.encrypt(credentials["access_key_id"]))
        if credentials.get("secret_access_key"):
            assignments.append("secret_access_key_enc = ?")
            values.append(self.encrypt(credentials["secret_access_key"]))
        values.append(provider_id)
        with self.connect() as conn:
            conn.execute(
                f"UPDATE providers SET {', '.join(assignments)} WHERE id = ? AND deleted_at IS NULL",
                values,
            )

    def set_enabled(self, provider_id: int, enabled: bool) -> None:
        if not enabled:
            current = self.get_provider(provider_id)
            if current and current["enabled"]:
                active_count = len(self.list_providers(enabled_only=True))
                if active_count <= 1:
                    raise ValueError("At least one dashboard must remain enabled")
        with self.connect() as conn:
            conn.execute(
                "UPDATE providers SET enabled = ?, updated_at = ? WHERE id = ? AND deleted_at IS NULL",
                (int(enabled), utc_now(), provider_id),
            )

    def move(self, provider_id: int, direction: int) -> None:
        providers = self.list_providers()
        index = next((i for i, item in enumerate(providers) if item["id"] == provider_id), None)
        if index is None:
            raise KeyError("Provider not found")
        other_index = index + direction
        if other_index < 0 or other_index >= len(providers):
            return
        first, second = providers[index], providers[other_index]
        with self.connect() as conn:
            conn.execute("UPDATE providers SET display_order = ?, updated_at = ? WHERE id = ?", (second["display_order"], utc_now(), first["id"]))
            conn.execute("UPDATE providers SET display_order = ?, updated_at = ? WHERE id = ?", (first["display_order"], utc_now(), second["id"]))

    def soft_delete(self, provider_id: int) -> None:
        current = self.get_provider(provider_id)
        if not current:
            raise KeyError("Provider not found")
        if current["enabled"] and len(self.list_providers(enabled_only=True)) <= 1:
            raise ValueError("At least one dashboard must remain enabled")
        with self.connect() as conn:
            conn.execute(
                "UPDATE providers SET enabled = 0, deleted_at = ?, updated_at = ? WHERE id = ?",
                (utc_now(), utc_now(), provider_id),
            )

    def update_status(self, provider_id: int, ok: bool, error: str = "") -> None:
        now = utc_now()
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO provider_status(provider_id, last_test_at, last_test_ok, last_success_at, last_error)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(provider_id) DO UPDATE SET
                    last_test_at = excluded.last_test_at,
                    last_test_ok = excluded.last_test_ok,
                    last_success_at = CASE WHEN excluded.last_test_ok = 1 THEN excluded.last_test_at ELSE provider_status.last_success_at END,
                    last_error = excluded.last_error
                """,
                (provider_id, now, int(ok), now if ok else None, error[:2000]),
            )

    def audit(self, action: str, provider_id: int | None = None, details: str = "", remote_addr: str = "") -> None:
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO admin_audit_log(action, provider_id, details, remote_addr, created_at) VALUES (?, ?, ?, ?, ?)",
                (action, provider_id, details[:2000], remote_addr[:100], utc_now()),
            )

    def recent_audit(self, limit: int = 20) -> list[dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT a.*, p.name AS provider_name
                FROM admin_audit_log a
                LEFT JOIN providers p ON p.id = a.provider_id
                ORDER BY a.id DESC LIMIT ?
                """,
                (max(1, min(int(limit), 100)),),
            ).fetchall()
        return [dict(row) for row in rows]

    def get_setting(self, key: str, default: str = "") -> str:
        with self.connect() as conn:
            row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        return str(row["value"]) if row else default

    def set_setting(self, key: str, value: str) -> None:
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO settings(key, value, updated_at) VALUES (?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
                """,
                (key, value, utc_now()),
            )

    @staticmethod
    def _verify_legacy_password(stored: str, password: str) -> bool:
        if not stored:
            return False
        if stored.startswith(("pbkdf2:", "scrypt:")):
            try:
                return check_password_hash(stored, password)
            except ValueError:
                return False
        if len(stored) == 64 and all(ch in "0123456789abcdefABCDEF" for ch in stored):
            digest = hashlib.sha256(password.encode("utf-8")).hexdigest()
            return hmac.compare_digest(digest, stored.lower())
        return hmac.compare_digest(password, stored)

    def check_admin_password(self, password: str) -> bool:
        stored = self.get_setting("admin_password_hash")
        if stored:
            return self._verify_legacy_password(stored, password)
        fallback = os.environ.get("ADMIN_PASSWORD_HASH") or os.environ.get("AUTH_PASSWORD_HASH", "")
        return self._verify_legacy_password(fallback, password)

    def set_admin_password(self, password: str) -> None:
        if len(password) < 12:
            raise ValueError("Admin password must contain at least 12 characters")
        self.set_setting("admin_password_hash", generate_password_hash(password))

    def seed_defaults(self) -> int:
        with self.connect() as conn:
            count = int(conn.execute("SELECT COUNT(*) FROM providers WHERE deleted_at IS NULL").fetchone()[0])
        if count:
            return 0
        defaults = [
            {
                "slug": "primaryaws", "name": "Primary AWS", "provider_type": "aws",
                "enabled": True, "telegram_enabled": True, "display_order": 10,
                "icon": "⚡", "accent": "#F59E0B", "currency": "USD",
                "region": os.environ.get("AWS_DEFAULT_REGION", "us-east-1"), "config": {},
                "credentials": {
                    "access_key_id": os.environ.get("AWS_ACCESS_KEY_ID", ""),
                    "secret_access_key": os.environ.get("AWS_SECRET_ACCESS_KEY", ""),
                },
            },
            {
                "slug": "clientaws", "name": os.environ.get("CLIENT_AWS_NAME", "Secondary Client AWS"), "provider_type": "aws",
                "enabled": True, "telegram_enabled": True, "display_order": 20,
                "icon": "⚡", "accent": "#D97706", "currency": "USD",
                "region": os.environ.get("CLIENT_AWS_DEFAULT_REGION", "us-east-1"), "config": {},
                "credentials": {
                    "access_key_id": os.environ.get("CLIENT_AWS_ACCESS_KEY_ID", ""),
                    "secret_access_key": os.environ.get("CLIENT_AWS_SECRET_ACCESS_KEY", ""),
                },
            },
            {
                "slug": "portal", "name": "External Portal Cloud", "provider_type": "portal",
                "enabled": True, "telegram_enabled": True, "display_order": 30,
                "icon": "🌐", "accent": "#2563EB", "currency": "USD", "region": "Example Region",
                "config": {"low_credit_threshold": 1000}, "credentials": {},
            },
        ]
        oci_defaults = [
            ("primaryoci", "Primary OCI", "🔴", "#C74634", 40),
            ("clientalpha", "Client Alpha OCI", "🟣", "#7C3AED", 50),
            ("clientbeta", "Client Beta OCI", "🟢", "#059669", 60),
            ("clientgamma", "Client Gamma OCI", "🔵", "#0284C7", 70),
            ("clientdelta", "Client Delta OCI", "🟠", "#EA580C", 80),
        ]
        for slug, name, icon, accent, order in oci_defaults:
            defaults.append({
                "slug": slug, "name": name, "provider_type": "oci_tenant",
                "enabled": True, "telegram_enabled": True, "display_order": order,
                "icon": icon, "accent": accent, "currency": "USD",
                "region": os.environ.get("OCI_REGION", "us-ashburn-1"),
                "config": {"tenant_name": slug}, "credentials": {},
            })
        created = 0
        for item in defaults:
            credentials = item.pop("credentials", {})
            self.create_provider(item, credentials)
            created += 1
        return created

    def public_provider(self, provider: dict[str, Any]) -> dict[str, Any]:
        provider_type = provider["provider_type"]
        short = {"aws": "AWS", "oci_tenant": "OCI", "portal": "EXT", "hetzner": "HTZ"}.get(provider_type, provider_type.upper())
        return {
            "id": provider["slug"],
            "slug": provider["slug"],
            "name": provider["name"],
            "provider_type": provider_type,
            "short": short,
            "logo": provider["icon"],
            "accent": provider["accent"],
            "currency": provider["currency"],
            "region": provider["region"],
            "combined_invoice": provider_type == "oci_tenant" and provider["slug"] == "primaryoci",
        }


store = ProviderStore()
