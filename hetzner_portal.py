"""Hetzner Accounts invoice cache adapter.

The browser collector runs on a fixed-IP host. It pushes only sanitized invoice
metadata to the dashboard receiver. Hetzner credentials, OTPs, cookies, and the
browser profile never reach this application.
"""
from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

APP_ROOT = Path(os.environ.get("APP_ROOT", Path(__file__).resolve().parent))
CACHE_FILE = Path(os.environ.get("HETZNER_CACHE_FILE", APP_ROOT / "hetzner_cache.json"))
MAX_INVOICES = 100


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _clean_text(value: Any, max_length: int = 200) -> str:
    text = str(value or "").strip()
    text = " ".join(text.split())
    return text[:max_length]


def _parse_date(value: Any) -> tuple[str, datetime | None]:
    raw = _clean_text(value, 80)
    if not raw:
        return "", None
    candidates = [
        "%b %d, %Y",
        "%B %d, %Y",
        "%Y-%m-%d",
        "%d.%m.%Y",
        "%d/%m/%Y",
    ]
    for fmt in candidates:
        try:
            parsed = datetime.strptime(raw, fmt)
            return parsed.date().isoformat(), parsed
        except ValueError:
            continue
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        return parsed.date().isoformat(), parsed.replace(tzinfo=None)
    except ValueError:
        return raw, None


def _parse_amount(value: Any) -> float:
    if isinstance(value, (int, float)):
        return round(float(value), 2)
    raw = _clean_text(value, 100)
    if not raw:
        return 0.0
    cleaned = re.sub(r"[^0-9,.-]", "", raw)
    if not cleaned or cleaned in {"-", ".", ","}:
        return 0.0
    if "," in cleaned and "." in cleaned:
        if cleaned.rfind(",") > cleaned.rfind("."):
            cleaned = cleaned.replace(".", "").replace(",", ".")
        else:
            cleaned = cleaned.replace(",", "")
    elif "," in cleaned:
        tail = cleaned.rsplit(",", 1)[-1]
        cleaned = cleaned.replace(",", ".") if len(tail) in {1, 2} else cleaned.replace(",", "")
    try:
        return round(float(cleaned), 2)
    except ValueError as exc:
        raise ValueError(f"Invalid invoice amount: {raw}") from exc


def _detect_currency(raw_amount: Any, fallback: str) -> str:
    text = _clean_text(raw_amount, 100).upper()
    if "€" in text or "EUR" in text:
        return "EUR"
    if "£" in text or "GBP" in text:
        return "GBP"
    if "CHF" in text:
        return "CHF"
    if "$" in text or "USD" in text:
        return "USD"
    currency = _clean_text(fallback, 3).upper()
    return currency if len(currency) == 3 else "USD"


def _normalize_status(value: Any) -> tuple[str, str]:
    raw = _clean_text(value, 40).upper() or "UNKNOWN"
    if raw in {"SETTLED", "PAID", "CLOSED", "COMPLETE", "COMPLETED"}:
        return "PAID", raw
    if raw in {"PAST DUE", "PAST_DUE", "OVERDUE"}:
        return "PAST_DUE", raw
    if raw in {"UNPAID", "OPEN", "DUE"}:
        return raw, raw
    return raw, raw


def _normalize_invoice(item: Any, fallback_currency: str) -> dict[str, Any]:
    if not isinstance(item, dict):
        raise ValueError("Each invoice must be a JSON object")
    invoice_id = _clean_text(item.get("invoice_number") or item.get("id"), 80)
    if not invoice_id or not re.fullmatch(r"[A-Za-z0-9._/-]+", invoice_id):
        raise ValueError("Invoice number is missing or invalid")
    raw_amount = item.get("amount_value", item.get("amount", 0))
    issue_date, parsed_date = _parse_date(item.get("invoice_date") or item.get("issue_date"))
    status, source_status = _normalize_status(item.get("status"))
    currency = _clean_text(item.get("currency"), 3).upper() or _detect_currency(raw_amount, fallback_currency)
    if not re.fullmatch(r"[A-Z]{3}", currency):
        currency = fallback_currency if re.fullmatch(r"[A-Z]{3}", fallback_currency) else "USD"
    amount = _parse_amount(raw_amount)
    sort_key = parsed_date.strftime("%Y-%m-%d") if parsed_date else issue_date
    period = parsed_date.strftime("%B %Y") if parsed_date else (issue_date or "Unknown period")
    return {
        "id": invoice_id,
        "invoice_number": invoice_id,
        "issue_date": issue_date,
        "invoice_date": issue_date,
        "time_start": period,
        "time_invoice": "—",
        "amount": amount,
        "amount_due": 0.0 if status == "PAID" else amount,
        "currency": currency,
        "status": status,
        "source_status": source_status,
        "by_service": {},
        "_sort_key": sort_key,
    }


def save_payload(payload: dict[str, Any]) -> dict[str, Any]:
    if _clean_text(payload.get("provider"), 40).lower() not in {"", "hetzner"}:
        raise ValueError("Unexpected provider value")
    raw_invoices = payload.get("invoices")
    if not isinstance(raw_invoices, list):
        raise ValueError("invoices must be a JSON list")
    if not raw_invoices:
        raise ValueError("No invoices were supplied")
    if len(raw_invoices) > MAX_INVOICES:
        raise ValueError(f"At most {MAX_INVOICES} invoices are accepted")
    fallback_currency = _clean_text(payload.get("currency"), 3).upper() or "USD"
    invoices = [_normalize_invoice(item, fallback_currency) for item in raw_invoices]
    deduplicated: dict[str, dict[str, Any]] = {}
    for invoice in invoices:
        deduplicated[invoice["id"]] = invoice
    invoices = sorted(deduplicated.values(), key=lambda row: row.get("_sort_key", ""), reverse=True)
    for invoice in invoices:
        invoice.pop("_sort_key", None)
    sanitized = {
        "provider": "hetzner",
        "source_page": _clean_text(payload.get("page"), 250),
        "collected_at_utc": _clean_text(payload.get("collected_at_utc"), 80) or _utc_now(),
        "received_at_utc": _utc_now(),
        "invoice_count": len(invoices),
        "invoices": invoices,
    }
    CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
    temporary = CACHE_FILE.with_suffix(CACHE_FILE.suffix + ".tmp")
    temporary.write_text(json.dumps(sanitized, indent=2, ensure_ascii=False) + "\n")
    os.chmod(temporary, 0o600)
    os.replace(temporary, CACHE_FILE)
    os.chmod(CACHE_FILE, 0o600)
    latest = invoices[0]
    return {
        "invoice_count": len(invoices),
        "latest_invoice": latest["id"],
        "collected_at": sanitized["collected_at_utc"],
    }


def load_payload() -> dict[str, Any]:
    try:
        data = json.loads(CACHE_FILE.read_text())
    except FileNotFoundError:
        return {}
    except (OSError, ValueError) as exc:
        raise RuntimeError(f"Unable to read Hetzner cache: {exc}") from exc
    return data if isinstance(data, dict) else {}


def _invoices(provider: dict[str, Any]) -> list[dict[str, Any]]:
    data = load_payload()
    fallback_currency = _clean_text(provider.get("currency"), 3).upper() or "USD"
    rows = []
    for item in data.get("invoices", []):
        if not isinstance(item, dict):
            continue
        row = dict(item)
        row["currency"] = row.get("currency") or fallback_currency
        rows.append(row)
    return rows


def _enhanced(provider: dict[str, Any]) -> dict[str, Any]:
    data = load_payload()
    invoices = _invoices(provider)
    currency = invoices[0].get("currency", provider.get("currency", "USD")) if invoices else provider.get("currency", "USD")
    latest = invoices[0] if invoices else {}
    previous = invoices[1] if len(invoices) > 1 else {}
    latest_amount = float(latest.get("amount", 0) or 0)
    previous_amount = float(previous.get("amount", 0) or 0)
    mom = round(((latest_amount - previous_amount) / previous_amount) * 100, 1) if previous_amount else 0.0
    return {
        "current_month": latest_amount,
        "last_month": previous_amount,
        "forecast": 0.0,
        "avg_daily": 0.0,
        "mom_pct": mom,
        "currency": currency,
        "days_passed": 0,
        "trend6": [
            {"month": row.get("time_start", ""), "cost": float(row.get("amount", 0) or 0)}
            for row in reversed(invoices[:6])
        ],
        "latest_invoice_id": latest.get("id", ""),
        "latest_invoice_date": latest.get("issue_date", ""),
        "latest_invoice_amount": latest_amount,
        "latest_invoice_status": latest.get("source_status") or latest.get("status", "UNKNOWN"),
        "invoice_count": len(invoices),
        "collected_at": data.get("collected_at_utc", ""),
        "received_at": data.get("received_at_utc", ""),
    }


def fetch_metric(provider: dict[str, Any], metric: str, **params: Any) -> Any:
    invoices = _invoices(provider)
    currency = invoices[0].get("currency", provider.get("currency", "USD")) if invoices else provider.get("currency", "USD")
    latest = invoices[0] if invoices else {}
    if metric == "invoices":
        return invoices
    if metric == "enhanced_kpis":
        return _enhanced(provider)
    if metric == "kpis":
        return {
            "total_spend": float(latest.get("amount", 0) or 0),
            "active_services": 1 if invoices else 0,
            "active_resources": len(invoices),
            "regions": 1,
            "currency": currency,
        }
    if metric == "services":
        return [{"name": "Account invoice", "value": float(latest.get("amount", 0) or 0)}] if invoices else []
    if metric == "trend":
        limit = max(1, min(int(params.get("months", 7)), 24))
        return [
            {"month": row.get("time_start", ""), "Invoice": float(row.get("amount", 0) or 0)}
            for row in reversed(invoices[:limit])
        ]
    if metric == "daily":
        limit = max(1, min(int(params.get("days", 28)), 366))
        return [
            {"day": row.get("issue_date", ""), "cost": float(row.get("amount", 0) or 0)}
            for row in reversed(invoices[:limit])
            if row.get("issue_date")
        ]
    if metric == "resources":
        return []
    raise ValueError("Unsupported dashboard metric")


def test_connection(provider: dict[str, Any]) -> str:
    data = load_payload()
    invoices = _invoices(provider)
    if not data or not invoices:
        raise RuntimeError("Hetzner invoice cache is empty; run the collector and push first")
    return (
        f"Hetzner cache loaded; {len(invoices)} invoice(s); "
        f"latest={invoices[0].get('id', 'unknown')}; "
        f"collected_at={data.get('collected_at_utc', 'unknown')}"
    )
