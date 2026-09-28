"""Synthetic provider adapter used only by the public portfolio demo.

No values in this module originate from production or customer systems.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

def _currency(provider: dict[str, Any]) -> str:
    return provider.get("currency") or "USD"

def fetch_metric(provider: dict[str, Any], metric: str, **params: Any) -> Any:
    code = _currency(provider)
    now = datetime.now(timezone.utc)
    base = 120.0 + (sum(ord(c) for c in provider.get("slug", "demo")) % 80)
    current = round(base * 1.37, 2)
    last = round(base * 1.21, 2)
    if metric == "kpis":
        return {"total_spend": current, "active_services": 4, "active_resources": 12, "regions": 2, "currency": code}
    if metric == "services":
        return [
            {"name": "Compute", "value": round(current * .55, 2)},
            {"name": "Storage", "value": round(current * .25, 2)},
            {"name": "Network", "value": round(current * .20, 2)},
        ]
    if metric == "trend":
        months = max(1, min(int(params.get("months", 7)), 24))
        return [{"month": (now - timedelta(days=30*i)).strftime("%b %Y"), "cost": round(last + i*3.4,2)} for i in reversed(range(months))]
    if metric == "daily":
        days = max(1, min(int(params.get("days", 28)), 366))
        return [{"day": (now - timedelta(days=i)).date().isoformat(), "cost": round(current/max(now.day,1),2)} for i in reversed(range(days))]
    if metric == "resources":
        return [
            {"name": "demo-compute-01", "type": "compute", "region": "region-a", "cost": round(current*.32,2)},
            {"name": "demo-storage-01", "type": "storage", "region": "region-b", "cost": round(current*.18,2)},
        ]
    if metric == "invoices":
        return [
            {"id": "INV-DEMO-2026-001", "time_start": "Demo Period", "time_invoice": "—", "amount": last, "amount_due": 0.0, "currency": code, "status": "PAID", "by_service": {}},
        ]
    if metric == "enhanced_kpis":
        mom = round(((current-last)/last)*100,1) if last else 0.0
        return {"current_month": current, "last_month": last, "forecast": round(current*1.08,2), "avg_daily": round(current/max(now.day,1),2), "mom_pct": mom, "currency": code, "days_passed": now.day, "trend6": []}
    raise ValueError("Unsupported dashboard metric")

def test_connection(provider: dict[str, Any]) -> str:
    return f"Demo mode active for {provider.get('name','provider')}"
