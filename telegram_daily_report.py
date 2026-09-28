"""Daily Telegram billing reports with per-group provider routing.

Primary group:
  Receives all Telegram-enabled providers except Secondary Client by default.

secondary group:
  Receives only the configured Secondary Client provider.

OCI unpaid invoices:
  Sent once as the real combined OCI invoice rather than one derived item per tenant.
"""
from __future__ import annotations

import importlib.util
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests
from dotenv import load_dotenv

BASE = Path(os.environ.get("APP_ROOT", Path(__file__).resolve().parent))
sys.path.insert(0, str(BASE))
os.chdir(BASE)
load_dotenv(BASE / ".env", override=True)


def env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() not in {"0", "false", "no", "off"}


TELEGRAM_ENABLED = env_bool("TELEGRAM_ENABLED", True)
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
PRIMARY_CHAT_ID = os.environ.get("TELEGRAM_GROUP_ID", "").strip()
SECONDARY_CHAT_ID = os.environ.get("SECONDARY_TELEGRAM_GROUP_ID", "").strip()
SECONDARY_PROVIDER_SLUG = os.environ.get("SECONDARY_PROVIDER_SLUG", "clientaws").strip() or "clientaws"
SECONDARY_EXCLUDE_FROM_MAIN = env_bool("SECONDARY_EXCLUDE_FROM_MAIN", True)

spec = importlib.util.spec_from_file_location("billing_app", BASE / "app.py")
app_mod = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(app_mod)


def send_telegram(text: str, chat_id: str) -> None:
    if not TELEGRAM_ENABLED:
        print("Telegram reporting is disabled")
        return
    if not TELEGRAM_BOT_TOKEN:
        raise RuntimeError("TELEGRAM_BOT_TOKEN is missing")
    if not chat_id:
        raise RuntimeError("Telegram chat ID is missing")

    response = requests.post(
        f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
        data={"chat_id": chat_id, "text": text, "parse_mode": "HTML"},
        timeout=20,
    )
    if response.status_code != 200:
        raise RuntimeError(f"Telegram error {response.status_code}: {response.text}")
    print(f"✓ Sent to {chat_id}: {text[:80]}...")


def currency(amount: float, code: str) -> str:
    return f"${amount:,.2f}" if code == "USD" else f"{code} {amount:,.2f}"


def report_provider(provider: dict[str, Any], chat_id: str) -> None:
    try:
        if provider["provider_type"] == "hetzner":
            enhanced = app_mod.fetch_provider_metric(provider, "enhanced_kpis")
            code = enhanced.get("currency") or provider.get("currency", "USD")
            lines = [
                f"{provider['icon']} <b>{provider['name']}</b>",
                "━━━━━━━━━━━━━━━━━━",
                f"🧾 Latest Invoice: <b>{enhanced.get('latest_invoice_id', '—')}</b>",
                f"📅 Invoice Date: {enhanced.get('latest_invoice_date', '—')}",
                f"💰 Invoice Amount: <b>{currency(enhanced.get('latest_invoice_amount', 0), code)}</b>",
                f"📌 Status: <b>{enhanced.get('latest_invoice_status', 'UNKNOWN')}</b>",
                f"📚 Invoices Collected: {enhanced.get('invoice_count', 0)}",
                f"🕐 Collected: {enhanced.get('collected_at', '—')}",
            ]
            send_telegram("\n".join(lines), chat_id)
            return
        enhanced = app_mod.fetch_provider_metric(provider, "enhanced_kpis")
        daily = app_mod.fetch_provider_metric(provider, "daily", days=2)
        latest = daily[-1]["cost"] if daily else 0
        code = enhanced.get("currency") or provider.get("currency", "USD")
        lines = [
            f"{provider['icon']} <b>{provider['name']}</b>",
            "━━━━━━━━━━━━━━━━━━",
            f"📅 Latest Daily Spend: <b>{currency(latest, code)}</b>",
            f"📆 Month-to-Date: <b>{currency(enhanced.get('current_month', 0), code)}</b>",
            f"📊 Last Month: {currency(enhanced.get('last_month', 0), code)}",
            f"🔮 Forecast: {currency(enhanced.get('forecast', 0), code)}",
            f"📈 MoM Change: {enhanced.get('mom_pct', 0):+.1f}%",
        ]
        if provider["provider_type"] == "portal":
            lines.extend(
                [
                    f"💰 Balance: {currency(enhanced.get('balance', 0), code)}",
                    f"💳 Account Credit: {currency(enhanced.get('account_credit', 0), code)}"
                    + (" ⚠️" if enhanced.get("low_credit_alert") else ""),
                    f"🎁 Promo Credit: {currency(enhanced.get('promotional_credit', 0), code)}",
                ]
            )
        lines.append(f"🕐 {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
        send_telegram("\n".join(lines), chat_id)
    except Exception as exc:
        print(f"Provider report failed for {provider['name']}: {exc}")
        send_telegram(
            f"{provider['icon']} <b>{provider['name']}</b>\n⚠️ Error fetching data: {exc}",
            chat_id,
        )


def fetch_oci_combined_invoices() -> list[dict[str, Any]]:
    """Fetch actual OCI OSP invoice totals once, without per-tenant allocation."""
    cache_key = "oci-combined-invoices"
    cached = app_mod.cache_get(cache_key)
    if cached is not None:
        return cached

    from oci.osp_gateway import InvoiceServiceClient

    cfg = app_mod.oci_config()
    client = InvoiceServiceClient(cfg)
    response = client.list_invoices(
        osp_home_region=cfg["region"],
        compartment_id=app_mod.OCI_TENANCY_OCID,
    )

    results: list[dict[str, Any]] = []
    for invoice in response.data.items or []:
        try:
            amount = float(invoice.invoice_amount or 0)
            amount_due = float(invoice.invoice_amount_due or 0)
            code = invoice.currency.currency_code if invoice.currency else "USD"
            raw_status = str(invoice.invoice_status or "OPEN").upper()

            if amount_due == 0 or "CLOSED" in raw_status or "PAID" in raw_status:
                status = "PAID"
            elif "ACCUM" in raw_status:
                status = "ACCUMULATING"
            elif "PAST_DUE" in raw_status or "OPEN" in raw_status:
                status = "PAST_DUE"
            else:
                status = raw_status

            due_date = invoice.time_invoice_due
            due_text = due_date.strftime("%b %d, %Y") if due_date else "—"
            period_text = due_date.strftime("%B %Y") if due_date else str(invoice.invoice_id)

            results.append(
                {
                    "id": str(invoice.invoice_id),
                    "time_start": period_text,
                    "time_invoice": due_text,
                    "amount": round(amount, 2),
                    "amount_due": round(amount_due, 2),
                    "currency": code,
                    "status": status,
                }
            )
        except Exception as exc:
            print(f"Combined OCI invoice parse error: {exc}")

    results.sort(
        key=lambda item: int(item["id"]) if str(item["id"]).isdigit() else 0,
        reverse=True,
    )
    app_mod.cache_set(cache_key, results)
    return results


def unpaid_line(provider_name: str, icon: str, invoice: dict[str, Any], default_currency: str) -> str:
    status = str(invoice.get("status", "") or "UNKNOWN")
    code = invoice.get("currency") or default_currency
    return (
        f"{icon} <b>{provider_name}</b> — {invoice.get('time_start', '')}\n"
        f"   Invoice: {invoice.get('id', '—')} | Due: "
        f"{currency(float(invoice.get('amount_due', 0) or 0), code)} | "
        f"Due date: {invoice.get('time_invoice', '—')} | Status: {status}"
    )


def check_unpaid_invoices(providers: list[dict[str, Any]], chat_id: str) -> None:
    alerts: list[str] = []
    has_oci = any(provider["provider_type"] == "oci_tenant" for provider in providers)

    # Non-OCI providers remain provider-specific.
    for provider in providers:
        if provider["provider_type"] == "oci_tenant":
            continue
        try:
            invoices = app_mod.fetch_provider_metric(provider, "invoices") or []
            for invoice in invoices:
                status = str(invoice.get("status", "") or "")
                amount_due = float(invoice.get("amount_due", 0) or 0)
                if amount_due > 0 and status not in ("ACCUMULATING", "PAID", "CLOSED"):
                    alerts.append(
                        unpaid_line(
                            provider["name"],
                            provider["icon"],
                            invoice,
                            provider.get("currency", "USD"),
                        )
                    )
        except Exception as exc:
            print(f"Invoice check failed for {provider['name']}: {exc}")

    # All enabled OCI tenants are represented by one real combined OSP invoice.
    if has_oci:
        try:
            for invoice in fetch_oci_combined_invoices():
                status = str(invoice.get("status", "") or "")
                amount_due = float(invoice.get("amount_due", 0) or 0)
                if amount_due > 0 and status not in ("ACCUMULATING", "PAID", "CLOSED"):
                    alerts.append(unpaid_line("OCI Combined", "☁️", invoice, "USD"))
        except Exception as exc:
            print(f"Combined OCI invoice check failed: {exc}")

    if alerts:
        send_telegram(
            "🚨 <b>UNPAID INVOICE ALERT</b> 🚨\n━━━━━━━━━━━━━━━━━━\n\n"
            + "\n\n".join(alerts)
            + f"\n\n💰 Total unpaid items: {len(alerts)}",
            chat_id,
        )
    else:
        print(f"✓ No unpaid invoices found for chat {chat_id}")


def send_group_report(group_name: str, chat_id: str, providers: list[dict[str, Any]]) -> None:
    if not chat_id:
        print(f"Skipping {group_name}: chat ID is not configured")
        return
    if not providers:
        print(f"Skipping {group_name}: no matching Telegram-enabled providers")
        return

    send_telegram(
        f"📊 <b>Daily Billing Report</b>\n"
        f"{datetime.now(timezone.utc).strftime('%A, %B %d, %Y')}\n"
        f"Providers: {len(providers)}",
        chat_id,
    )
    for provider in providers:
        report_provider(provider, chat_id)
    check_unpaid_invoices(providers, chat_id)


if __name__ == "__main__":
    print(f"Starting daily report at {datetime.now()}")
    all_providers = app_mod.provider_store.list_providers(enabled_only=True, telegram_only=True)
    if not all_providers:
        print("No providers have Telegram reporting enabled")
        raise SystemExit(0)

    secondary_providers = [
        provider for provider in all_providers if provider["slug"] == SECONDARY_PROVIDER_SLUG
    ]
    primary_providers = list(all_providers)
    if SECONDARY_EXCLUDE_FROM_MAIN and SECONDARY_CHAT_ID:
        primary_providers = [
            provider for provider in primary_providers if provider["slug"] != SECONDARY_PROVIDER_SLUG
        ]

    send_group_report("primary group", PRIMARY_CHAT_ID, primary_providers)
    send_group_report("secondary group", SECONDARY_CHAT_ID, secondary_providers)
    print("Done!")
