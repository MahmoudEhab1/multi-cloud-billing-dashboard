"""
Multi-Cloud Billing Monitor
Supports: Oracle Cloud (OCI) + AWS + extensible for more
"""
import os, hashlib, hmac, functools, time
from pathlib import Path
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv
from flask import Flask, jsonify, request, render_template, session, redirect, url_for

APP_ROOT = Path(os.environ.get('APP_ROOT', Path(__file__).resolve().parent))
load_dotenv(APP_ROOT / '.env', override=True)

app = Flask(__name__, template_folder=str(APP_ROOT / 'templates'))
DEMO_MODE = os.environ.get("DEMO_MODE", "false").strip().lower() in {"1", "true", "yes", "on"}
app.secret_key = os.environ["SECRET_KEY"]
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=True,
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
)

from provider_store import store as provider_store
from hetzner_portal import fetch_metric as hetzner_fetch_metric, save_payload as hetzner_save_payload, test_connection as hetzner_test_connection
provider_store.seed_defaults()

OCI_USER_OCID        = os.environ.get("OCI_USER_OCID", "")
OCI_FINGERPRINT      = os.environ.get("OCI_FINGERPRINT", "")
OCI_TENANCY_OCID     = os.environ.get("OCI_TENANCY_OCID", "")
OCI_REGION           = os.environ.get("OCI_REGION", "us-ashburn-1")
OCI_KEY_FILE         = os.environ.get("OCI_KEY_FILE", "oci_private_key.pem")
OCI_COMPARTMENT_OCID = os.environ.get("OCI_COMPARTMENT_OCID", OCI_TENANCY_OCID)

# ── OCI Tenant definitions — uses existing API key, splits by tenantName ──────
OCI_TENANTS = [
    {"id": "primaryoci",       "name": "Primary Account",       "key": "primaryoci"},
    {"id": "clientalpha",      "name": "Client Alpha",      "key": "clientalpha"},
    {"id": "clientbeta",         "name": "Client Beta",         "key": "clientbeta"},
    {"id": "clientgamma",       "name": "Client Gamma",       "key": "clientgamma"},
    {"id": "clientdelta", "name": "Client Delta", "key": "clientdelta"},
]

# ── OCI Tenant definitions — uses existing API key, splits by tenantName ──────
OCI_TENANTS = [
    {"id": "primaryoci",       "name": "Primary Account",       "key": "primaryoci"},
    {"id": "clientalpha",      "name": "Client Alpha",      "key": "clientalpha"},
    {"id": "clientbeta",         "name": "Client Beta",         "key": "clientbeta"},
    {"id": "clientgamma",       "name": "Client Gamma",       "key": "clientgamma"},
    {"id": "clientdelta", "name": "Client Delta", "key": "clientdelta"},
]
REGION_MAP           = {"IAD": "us-ashburn-1", "us-ashburn-1": "us-ashburn-1"}
OCI_REGION_ID        = REGION_MAP.get(OCI_REGION, OCI_REGION)

# ── AWS account definitions ──────────────────────────────────────────────────
# Existing AWS_* variables remain the Primary AWS account for backward
# compatibility. The second account uses CLIENT_AWS_* variables.
AWS_ACCESS_KEY_ID     = os.environ.get("AWS_ACCESS_KEY_ID", "")
AWS_SECRET_ACCESS_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY", "")
AWS_DEFAULT_REGION    = os.environ.get("AWS_DEFAULT_REGION", "us-east-1")

CLIENT_AWS_NAME              = os.environ.get("CLIENT_AWS_NAME", "Client AWS")
CLIENT_AWS_ACCESS_KEY_ID     = os.environ.get("CLIENT_AWS_ACCESS_KEY_ID", "")
CLIENT_AWS_SECRET_ACCESS_KEY = os.environ.get("CLIENT_AWS_SECRET_ACCESS_KEY", "")
CLIENT_AWS_DEFAULT_REGION    = os.environ.get("CLIENT_AWS_DEFAULT_REGION", "us-east-1")

AWS_ACCOUNTS = {
    "primaryaws": {
        "name": "Primary AWS",
        "access_key_id": AWS_ACCESS_KEY_ID,
        "secret_access_key": AWS_SECRET_ACCESS_KEY,
        "region": AWS_DEFAULT_REGION,
    },
    "clientaws": {
        "name": CLIENT_AWS_NAME,
        "access_key_id": CLIENT_AWS_ACCESS_KEY_ID,
        "secret_access_key": CLIENT_AWS_SECRET_ACCESS_KEY,
        "region": CLIENT_AWS_DEFAULT_REGION,
    },
}

AUTH_PASSWORD_HASH = os.environ["AUTH_PASSWORD_HASH"]
API_KEY            = os.environ.get("API_KEY", "")

import json
import pathlib, pathlib as _pathlib

_cache = {}
_CACHE_FILE = os.environ.get("CACHE_FILE", str(APP_ROOT / "cache.json"))
_CACHE_LOCK_FILE = _CACHE_FILE + ".lock"
_CACHE_TTL_SECONDS = max(3600, int(os.environ.get("BILLING_CACHE_TTL_SECONDS", "86400")))
_CACHE_TTL = {
    "aws": _CACHE_TTL_SECONDS,
    "oci": _CACHE_TTL_SECONDS,
    "portal": _CACHE_TTL_SECONDS,
    "hetzner": _CACHE_TTL_SECONDS,
    "default": _CACHE_TTL_SECONDS,
}
_cache_file_mtime = 0.0


def _ttl(k):
    for prefix, ttl in _CACHE_TTL.items():
        if k.startswith(prefix):
            return ttl
    return _CACHE_TTL["default"]


def _valid_cache_entries(data):
    now = __import__('time').time()
    valid = {}
    if not isinstance(data, dict):
        return valid
    for key, entry in data.items():
        try:
            value, created_at = entry
            created_at = float(created_at)
            if now - created_at < _ttl(key):
                valid[key] = (value, created_at)
        except (TypeError, ValueError):
            continue
    return valid


def _read_cache_unlocked():
    try:
        raw = _pathlib.Path(_CACHE_FILE).read_text()
        return _valid_cache_entries(__import__('json').loads(raw))
    except FileNotFoundError:
        return {}
    except Exception as exc:
        print(f"[cache] Read failed: {exc}")
        return {}


def _write_cache_unlocked(entries):
    target = _pathlib.Path(_CACHE_FILE)
    temporary = target.with_suffix(target.suffix + ".tmp")
    payload = {key: [value, created_at] for key, (value, created_at) in entries.items()}
    temporary.write_text(__import__('json').dumps(payload))
    os.replace(temporary, target)


def _load_file_cache(force=False):
    global _cache, _cache_file_mtime
    try:
        path = _pathlib.Path(_CACHE_FILE)
        current_mtime = path.stat().st_mtime if path.exists() else 0.0
        if not force and current_mtime <= _cache_file_mtime:
            return

        import fcntl
        with open(_CACHE_LOCK_FILE, 'a+') as lock_file:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_SH)
            entries = _read_cache_unlocked()
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)

        _cache = entries
        _cache_file_mtime = path.stat().st_mtime if path.exists() else 0.0
        print(f"[cache] Loaded {len(entries)} valid entries from disk")
    except Exception as exc:
        print(f"[cache] No file cache: {exc}")


def cache_get(k):
    # Reload when another Passenger process updates the shared cache file.
    _load_file_cache()
    if k in _cache:
        value, created_at = _cache[k]
        if __import__('time').time() - created_at < _ttl(k):
            return value
        del _cache[k]
    return None


def cache_set(k, value):
    global _cache, _cache_file_mtime
    import fcntl
    now = __import__('time').time()
    with open(_CACHE_LOCK_FILE, 'a+') as lock_file:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        entries = _read_cache_unlocked()
        entries[k] = (value, now)
        _write_cache_unlocked(entries)
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
    _cache = entries
    _cache_file_mtime = _pathlib.Path(_CACHE_FILE).stat().st_mtime


def cache_clear(prefix=None):
    global _cache, _cache_file_mtime
    import fcntl
    with open(_CACHE_LOCK_FILE, 'a+') as lock_file:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        entries = _read_cache_unlocked()
        keys = [key for key in list(entries) if not prefix or key.startswith(prefix)]
        for key in keys:
            entries.pop(key, None)
        _write_cache_unlocked(entries)
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
    _cache = entries
    _cache_file_mtime = _pathlib.Path(_CACHE_FILE).stat().st_mtime
    return len(keys)


_load_file_cache(force=True)

def check_pw(p):
    h = hashlib.sha256(p.encode()).hexdigest()
    return hmac.compare_digest(h, AUTH_PASSWORD_HASH) or hmac.compare_digest(p, AUTH_PASSWORD_HASH)

def login_required(f):
    @functools.wraps(f)
    def d(*a, **kw):
        if not session.get("logged_in"): return redirect(url_for("login"))
        return f(*a, **kw)
    return d

def api_auth(f):
    @functools.wraps(f)
    def d(*a, **kw):
        if API_KEY and hmac.compare_digest(request.headers.get("X-API-Key",""), API_KEY): return f(*a,**kw)
        if session.get("logged_in"): return f(*a, **kw)
        return jsonify({"error": "Unauthorized"}), 401
    return d

def midnight(dt):
    return dt.replace(hour=0, minute=0, second=0, microsecond=0)

def date_range(period):
    today = midnight(datetime.now(timezone.utc))
    tomorrow = today + timedelta(days=1)
    if period == "daily":       return today - timedelta(days=1), today
    elif period == "monthly":   return today.replace(day=1), tomorrow
    elif period == "quarterly":
        qm = ((today.month - 1) // 3) * 3 + 1
        return today.replace(month=qm, day=1), tomorrow
    elif period == "ytd":       return today.replace(month=1, day=1), tomorrow
    else:                       return today - timedelta(days=30), tomorrow

def oci_config():
    kf = OCI_KEY_FILE if os.path.isabs(OCI_KEY_FILE) else os.path.join(str(APP_ROOT), OCI_KEY_FILE)
    return {"user": OCI_USER_OCID, "fingerprint": OCI_FINGERPRINT,
            "tenancy": OCI_TENANCY_OCID, "region": OCI_REGION_ID, "key_file": kf}

def oci_summarize(start, end, granularity="MONTHLY", group_by=None):
    import oci
    from oci.usage_api import UsageapiClient
    from oci.usage_api.models import RequestSummarizedUsagesDetails
    cfg = oci_config(); oci.config.validate_config(cfg)
    client = UsageapiClient(cfg)
    kwargs = dict(tenant_id=OCI_TENANCY_OCID, time_usage_started=start,
                  time_usage_ended=end, granularity=granularity,
                  query_type="COST", compartment_depth=6)
    if group_by: kwargs["group_by"] = group_by
    return client.request_summarized_usages(RequestSummarizedUsagesDetails(**kwargs)).data.items or []

def oci_fetch_kpis(period):
    ck = f"oci-kpis-{period}"; c = cache_get(ck)
    if c is not None: return c
    s, e = date_range(period)
    items = oci_summarize(s, e)
    total = round(sum(float(i.computed_amount or 0) for i in items), 2)
    rids = {i.resource_id for i in items if i.resource_id}
    regs = {i.region for i in items if i.region}
    svcs = {i.service for i in items if i.service}
    result = {"total_spend": total, "active_resources": len(rids),
              "active_services": len(svcs), "regions": len(regs),
              "currency": items[0].currency if items else "USD", "period": period}
    cache_set(ck, result); return result

def oci_fetch_services(period):
    ck = f"oci-services-{period}"; c = cache_get(ck)
    if c is not None: return c
    s, e = date_range(period)
    items = oci_summarize(s, e, group_by=["service"])
    t = {}
    for i in items:
        k = i.service or "Other"; t[k] = t.get(k, 0) + float(i.computed_amount or 0)
    result = [{"name": k, "value": round(v, 2)} for k, v in sorted(t.items(), key=lambda x: -x[1])]
    cache_set(ck, result); return result

def oci_fetch_trend(months=7):
    ck = f"oci-trend-{months}"; c = cache_get(ck)
    if c is not None: return c
    today = midnight(datetime.now(timezone.utc))
    s = today.replace(day=1)
    for _ in range(months - 1):
        s = (s - timedelta(days=1)).replace(day=1)
    s = midnight(s)
    items = oci_summarize(s, today + timedelta(days=1), group_by=["service"])
    t = {}
    for i in items:
        mk = i.time_usage_started.strftime("%b %Y") if i.time_usage_started else "?"
        svc = i.service or "Other"
        if mk not in t: t[mk] = {}
        t[mk][svc] = t[mk].get(svc, 0) + float(i.computed_amount or 0)
    result = [dict(month=m, **{k: round(v, 2) for k, v in sv.items()}) for m, sv in t.items()]
    cache_set(ck, result); return result

def oci_fetch_daily(days=28):
    ck = f"oci-daily-{days}"; c = cache_get(ck)
    if c is not None: return c
    today = midnight(datetime.now(timezone.utc))
    s = today - timedelta(days=days); e = today
    if s >= e: e = s + timedelta(days=1)
    items = oci_summarize(s, e, granularity="DAILY")
    t = {}
    for i in items:
        if i.time_usage_started:
            dk = i.time_usage_started.strftime("%Y-%m-%d")
            t[dk] = t.get(dk, 0) + float(i.computed_amount or 0)
    result = [{"day": k, "cost": round(v, 2)} for k, v in sorted(t.items())]
    cache_set(ck, result); return result

def oci_fetch_resources(limit=10):
    ck = f"oci-resources-{limit}"; c = cache_get(ck)
    if c is not None: return c
    today = midnight(datetime.now(timezone.utc))
    s = today.replace(day=1); e = today + timedelta(days=1)
    if s >= e: s = e - timedelta(days=1)
    items = oci_summarize(s, e, group_by=["resourceId", "service", "region"])
    res = []
    for i in items:
        name = i.resource_id or "Unknown"
        parts = name.split(".")
        res_type = parts[1] if len(parts) > 1 else ""
        uid = parts[-1] if parts else ""
        short_id = ("..." + uid[-8:]) if len(uid) > 8 else uid
        region_short = (i.region or "").replace("us-ashburn-1","IAD").replace("eu-frankfurt-1","JED")
        friendly = f"{res_type.title()} - {region_short} - {short_id}" if res_type else name[-30:]
        res.append({"id": name, "friendly": friendly,
                    "type": i.service or "-", "region": i.region or "-",
                    "cost": round(float(i.computed_amount or 0), 2)})
    result = sorted(res, key=lambda x: -x["cost"])[:limit]
    cache_set(ck, result); return result

def oci_fetch_invoices():
    ck = "oci-invoices"; c = cache_get(ck)
    if c is not None: return c
    try:
        from oci.osp_gateway import InvoiceServiceClient
        cfg = oci_config()
        client = InvoiceServiceClient(cfg)
        resp = client.list_invoices(
            osp_home_region=cfg["region"],
            compartment_id=OCI_TENANCY_OCID
        )
        results = []
        for inv in (resp.data.items or []):
            try:
                amt = float(inv.invoice_amount or 0)
                due = float(inv.invoice_amount_due or 0)
                try:
                    cur = inv.currency.currency_code if inv.currency else "USD"
                except: cur = "USD"
                raw = str(inv.invoice_status or "OPEN")
                if "PAST_DUE" in raw or "OVERDUE" in raw: status = "PAST_DUE"
                elif "PAID" in raw: status = "PAID"
                elif "ACCUM" in raw or "OPEN" in raw: status = "ACCUMULATING"
                else: status = raw
                due_dt = inv.time_invoice_due
                due_str = due_dt.strftime("%b %d, %Y") if due_dt else "—"
                period_str = due_dt.strftime("%B %Y") if due_dt else str(inv.invoice_id)
                # Fetch service breakdown from Usage API for this billing period
                by_svc = {}
                try:
                    if due_dt:
                        # due_dt is last day of billing month (e.g. Feb 28)
                        # so billing period = that same month
                        bill_end_date = due_dt.date() if hasattr(due_dt, 'date') else due_dt
                        period_start_dt = bill_end_date.replace(day=1)
                        # end = first day of next month
                        period_end_dt = (bill_end_date.replace(day=28) + timedelta(days=4)).replace(day=1)
                        s = midnight(datetime(period_start_dt.year, period_start_dt.month, period_start_dt.day, tzinfo=timezone.utc))
                        e = midnight(datetime(period_end_dt.year, period_end_dt.month, period_end_dt.day, tzinfo=timezone.utc))
                        svc_items = oci_summarize(s, e, group_by=["service"])
                        for si in svc_items:
                            k = si.service or "Other"
                            v = float(si.computed_amount or 0)
                            if v > 0:
                                by_svc[k] = round(by_svc.get(k, 0) + v, 2)
                except Exception as se:
                    print(f"Service breakdown error: {se}")
                # Fetch service breakdown
                by_svc = {}
                try:
                    if due_dt:
                        bill_end_date = due_dt.date() if hasattr(due_dt, 'date') else due_dt
                        period_start_dt = bill_end_date.replace(day=1)
                        period_end_dt = (bill_end_date.replace(day=28) + timedelta(days=4)).replace(day=1)
                        s = midnight(datetime(period_start_dt.year, period_start_dt.month, period_start_dt.day, tzinfo=timezone.utc))
                        e = midnight(datetime(period_end_dt.year, period_end_dt.month, period_end_dt.day, tzinfo=timezone.utc))
                        svc_items = oci_summarize(s, e, group_by=["service"])
                        for si in svc_items:
                            k = si.service or "Other"
                            v = float(si.computed_amount or 0)
                            if v > 0:
                                by_svc[k] = round(by_svc.get(k, 0) + v, 2)
                except Exception as se:
                    print(f"Service breakdown error: {se}")
                results.append({
                    "id": str(inv.invoice_id),
                    "time_start": period_str,
                    "issue_date": due_dt.replace(day=1).strftime("%b %d, %Y") if due_dt else "—",
                    "time_invoice": due_str,
                    "amount": round(amt, 2),
                    "amount_due": round(due, 2),
                    "currency": cur,
                    "status": status,
                    "by_service": by_svc
                })
            except Exception as ie:
                print("Invoice parse error:", ie)
                continue
        results.sort(key=lambda x: int(x["id"]) if x["id"].isdigit() else 0, reverse=True)
        cache_set(ck, results)
        return results
    except Exception as e:
        print("OSP Gateway failed, using fallback:", e)
        return _oci_invoices_fallback()

def _oci_invoices_fallback():
    today = midnight(datetime.now(timezone.utc))
    results = []
    for i in range(3):
        if i == 0:
            s = today.replace(day=1); e = today + timedelta(days=1); status = "ACCUMULATING"
        else:
            tmp = today.replace(day=1) - timedelta(days=1)
            for _ in range(i - 1): tmp = (tmp.replace(day=1) - timedelta(days=1))
            s = midnight(tmp.replace(day=1))
            e = midnight(s.replace(day=28) + timedelta(days=4)).replace(day=1)
            status = "PAID"
        if s >= e: e = s + timedelta(days=1)
        try:
            items = oci_summarize(s, e, group_by=["service"])
            total = round(sum(float(x.computed_amount or 0) for x in items), 2)
            currency = items[0].currency if items else "USD"
            by_svc = {}
            for x in items:
                k = x.service or "Other"
                by_svc[k] = round(by_svc.get(k, 0) + float(x.computed_amount or 0), 2)
        except: total = 0; currency = "USD"; by_svc = {}
        try:
            due_date = (s.replace(day=28) + timedelta(days=4)).replace(day=1).replace(day=5)
        except: due_date = None
        results.append({
            "id": f"INV-{s.strftime('%Y%m')}",
            "time_start": s.strftime("%B %Y"),
            "time_invoice": due_date.strftime("%b %d, %Y") if due_date else "—",
            "amount": total,
            "amount_due": total if status != "PAID" else 0,
            "currency": currency,
            "status": status,
            "by_service": by_svc
        })
    return results



# ── Per-Tenant OCI Functions ───────────────────────────────────────────────────
def oci_date_range(period):
    """Return (start, end) datetimes for a given period string."""
    from datetime import datetime, timedelta, timezone
    def midnight(dt): return dt.replace(hour=0,minute=0,second=0,microsecond=0)
    today = midnight(datetime.now(timezone.utc))
    if period == "daily":
        return today, today + timedelta(days=1)
    elif period == "monthly":
        return today.replace(day=1), today + timedelta(days=1)
    elif period == "quarterly":
        m = today.month; qstart = m - ((m-1)%3)
        return today.replace(month=qstart, day=1), today + timedelta(days=1)
    elif period == "ytd":
        return today.replace(month=1, day=1), today + timedelta(days=1)
    else:
        return today.replace(day=1), today + timedelta(days=1)

def oci_tenant_summarize(tenant_name, start, end, granularity="MONTHLY", group_by=None):
    """Query OCI Usage API filtered to a specific tenant name."""
    import oci
    from oci.usage_api import UsageapiClient
    from oci.usage_api.models import RequestSummarizedUsagesDetails
    cfg = oci_config()
    client = UsageapiClient(cfg)
    gb = (group_by or []) + ["tenantName"]
    # deduplicate
    gb = list(dict.fromkeys(gb))
    import time as _time
    for _attempt in range(3):
        try:
            all_items = client.request_summarized_usages(
                RequestSummarizedUsagesDetails(
                    tenant_id=OCI_TENANCY_OCID,
                    time_usage_started=start,
                    time_usage_ended=end,
                    granularity=granularity,
                    query_type="COST",
                    compartment_depth=6,
                    group_by=gb
                )
            ).data.items or []
            break
        except Exception as _e:
            if "429" in str(_e) and _attempt < 2:
                _time.sleep(3 + _attempt * 2)
                continue
            raise
    else:
        all_items = []
    # Filter to this tenant only
    return [i for i in all_items
            if (getattr(i, 'tenant_name', None) or '').lower() == tenant_name.lower()]

def oci_tenant_fetch_kpis(tenant_key, period):
    ck = f"oci-tenant-kpis-{tenant_key}-{period}"; c = cache_get(ck)
    if c is not None: return c
    s, e = oci_date_range(period)
    items = oci_tenant_summarize(tenant_key, s, e)
    total = round(sum(float(i.computed_amount or 0) for i in items), 2)
    svcs  = {i.service for i in items if i.service}
    regs  = {i.region  for i in items if i.region}
    result = {"total_spend": total, "active_resources": 0,
              "active_services": len(svcs), "regions": len(regs),
              "currency": items[0].currency if items else "USD"}
    cache_set(ck, result); return result

def oci_tenant_fetch_services(tenant_key, period):
    ck = f"oci-tenant-services-{tenant_key}-{period}"; c = cache_get(ck)
    if c is not None: return c
    s, e = oci_date_range(period)
    items = oci_tenant_summarize(tenant_key, s, e, group_by=["service"])
    t = {}
    for i in items:
        k = i.service or "Other"
        t[k] = t.get(k, 0) + float(i.computed_amount or 0)
    result = [{"name": k, "value": round(v, 2)}
              for k, v in sorted(t.items(), key=lambda x: -x[1])]
    cache_set(ck, result); return result

def oci_tenant_fetch_trend(tenant_key, months=7):
    ck = f"oci-tenant-trend-{tenant_key}-{months}"; c = cache_get(ck)
    if c is not None: return c
    today = midnight(datetime.now(timezone.utc))
    s = today.replace(day=1)
    for _ in range(months - 1): s = (s - timedelta(days=1)).replace(day=1)
    e = today + timedelta(days=1)
    items = oci_tenant_summarize(tenant_key, s, e, granularity="MONTHLY",
                                  group_by=["service"])
    month_svc = {}
    for i in items:
        if not i.time_usage_started: continue
        mk = i.time_usage_started.strftime("%b %Y")
        sv = i.service or "Other"
        if mk not in month_svc: month_svc[mk] = {}
        month_svc[mk][sv] = month_svc[mk].get(sv, 0) + float(i.computed_amount or 0)
    result = [{"month": mk, **{sv: round(v, 2) for sv, v in svcs.items()}}
              for mk, svcs in month_svc.items()]
    cache_set(ck, result); return result

def oci_tenant_fetch_daily(tenant_key, days=28):
    ck = f"oci-tenant-daily-{tenant_key}-{days}"; c = cache_get(ck)
    if c is not None: return c
    today = midnight(datetime.now(timezone.utc))
    s = today - timedelta(days=days); e = today + timedelta(days=1)
    items = oci_tenant_summarize(tenant_key, s, e, granularity="DAILY")
    t = {}
    for i in items:
        if i.time_usage_started:
            dk = i.time_usage_started.strftime("%m-%d")
            t[dk] = t.get(dk, 0) + float(i.computed_amount or 0)
    result = [{"day": k, "cost": round(v, 2)} for k, v in sorted(t.items())]
    cache_set(ck, result); return result

def oci_tenant_fetch_resources(tenant_key, limit=10):
    ck = f"oci-tenant-resources-{tenant_key}-{limit}"; c = cache_get(ck)
    if c is not None: return c
    today = midnight(datetime.now(timezone.utc))
    s = today.replace(day=1); e = today + timedelta(days=1)
    if s >= e: s = e - timedelta(days=1)
    items = oci_tenant_summarize(tenant_key, s, e,
                                  group_by=["resourceId", "service", "region"])
    t = {}
    for i in items:
        rid = i.resource_id or "unknown"
        if rid not in t:
            rname = rid.split(".")[-1] if "." in rid else rid
        rname = rname[:40] if len(rname) > 40 else rname
        t[rid] = {"name": rname,
                      "type": i.service or "Other",
                      "region": (i.region or "").replace("us-ashburn-1","Example Region").replace("us-east-1","US East"),
                      "cost": 0}
        t[rid]["cost"] += float(i.computed_amount or 0)
    result = sorted([{"name": v["name"], "type": v["type"],
                      "region": v["region"], "cost": round(v["cost"], 2)}
                     for v in t.values()], key=lambda x: -x["cost"])[:limit]
    cache_set(ck, result); return result

def oci_tenant_fetch_enhanced_kpis(tenant_key):
    ck = f"oci-tenant-enhanced-{tenant_key}"; c = cache_get(ck)
    if c is not None: return c
    from calendar import monthrange
    today = midnight(datetime.now(timezone.utc))
    s_cur = today.replace(day=1); e_cur = today + timedelta(days=1)
    items_cur = oci_tenant_summarize(tenant_key, s_cur, e_cur)
    current  = round(sum(float(i.computed_amount or 0) for i in items_cur), 2)
    currency = items_cur[0].currency if items_cur else "USD"
    last_end   = today.replace(day=1)
    last_start = (last_end - timedelta(days=1)).replace(day=1)
    items_last = oci_tenant_summarize(tenant_key, last_start, last_end)
    last_month = round(sum(float(i.computed_amount or 0) for i in items_last), 2)
    days_passed   = today.day
    days_in_month = monthrange(today.year, today.month)[1]
    forecast = round((current / days_passed) * days_in_month, 2) if days_passed else 0
    s_daily = today - timedelta(days=30)
    items_d = oci_tenant_summarize(tenant_key, s_daily, today + timedelta(days=1),
                                    granularity="DAILY")
    daily_t = {}
    for i in items_d:
        if i.time_usage_started:
            dk = i.time_usage_started.strftime("%Y-%m-%d")
            daily_t[dk] = daily_t.get(dk, 0) + float(i.computed_amount or 0)
    avg_daily = round(sum(daily_t.values()) / len(daily_t), 2) if daily_t else 0
    s_trend = today.replace(day=1)
    for _ in range(5): s_trend = (s_trend - timedelta(days=1)).replace(day=1)
    items_tr = oci_tenant_summarize(tenant_key, s_trend, today + timedelta(days=1),
                                     granularity="MONTHLY")
    trend_map = {}
    for i in items_tr:
        if i.time_usage_started:
            mk = i.time_usage_started.strftime("%b %Y")
            trend_map[mk] = trend_map.get(mk, 0) + float(i.computed_amount or 0)
    trend6  = [{"month": k, "cost": round(v, 2)} for k, v in trend_map.items()]
    mom_pct = round(((current - last_month) / last_month * 100), 1) if last_month else 0
    result = {"current_month": current, "last_month": last_month, "forecast": forecast,
              "avg_daily": avg_daily, "currency": currency, "mom_pct": mom_pct,
              "days_passed": days_passed, "trend6": trend6}
    cache_set(ck, result); return result

def oci_tenant_fetch_invoices(tenant_key):
    ck = f"oci-tenant-invoices-{tenant_key}"; c = cache_get(ck)
    if c is not None: return c
    import oci as _oci
    from oci.osp_gateway import InvoiceServiceClient
    try:
        cfg = oci_config()
        client = InvoiceServiceClient(cfg)
        resp = client.list_invoices(
            osp_home_region=cfg["region"],
            compartment_id=OCI_TENANCY_OCID
        )
        results = []
        for inv in (resp.data.items or []):
            try:
                amt  = float(inv.invoice_amount or 0)
                due  = float(inv.invoice_amount_due or 0)
                cur  = inv.currency.currency_code if inv.currency else "USD"
                raw  = str(inv.invoice_status or "OPEN")
                if "PAST_DUE" in raw:   status = "PAST_DUE"
                elif "PAID" in raw:     status = "PAID"
                elif "ACCUM" in raw:    status = "ACCUMULATING"
                else:                   status = raw
                due_dt   = inv.time_invoice_due
                due_str  = due_dt.strftime("%b %d, %Y") if due_dt else "—"
                period_str = due_dt.strftime("%B %Y") if due_dt else str(inv.invoice_id)
                # Get tenant share via usage API
                by_svc = {}
                if due_dt:
                    bd  = due_dt.date() if hasattr(due_dt,"date") else due_dt
                    ps  = bd.replace(day=1)
                    pe  = (bd.replace(day=28) + timedelta(days=4)).replace(day=1)
                    ts  = midnight(datetime(ps.year,ps.month,ps.day,tzinfo=timezone.utc))
                    te  = midnight(datetime(pe.year,pe.month,pe.day,tzinfo=timezone.utc))
                    import time as _t; _t.sleep(1)  # avoid 429
                    sitems = oci_tenant_summarize(tenant_key, ts, te, group_by=["service"])
                    for si in sitems:
                        k = si.service or "Other"
                        v = float(si.computed_amount or 0)
                        if v > 0: by_svc[k] = round(by_svc.get(k,0)+v, 2)
                tenant_total = round(sum(by_svc.values()), 2)
                if tenant_total == 0: continue  # skip if tenant has no spend this period
                results.append({
                    "id": str(inv.invoice_id),
                    "time_start": period_str,
                    "issue_date": due_dt.replace(day=1).strftime("%b %d, %Y") if due_dt else "—",
                    "time_invoice": due_str,
                    "amount": tenant_total,
                    "amount_due": tenant_total if status != "PAID" else 0,
                    "currency": cur, "status": status,
                    "by_service": by_svc
                })
            except Exception as ie:
                print(f"Invoice parse error: {ie}")
        results.sort(key=lambda x: int(x["id"]) if x["id"].isdigit() else 0, reverse=True)
        cache_set(ck, results); return results
    except Exception as e:
        print(f"Tenant invoice error {tenant_key}: {e}"); return []
    ck = f"oci-tenant-invoices-{tenant_key}"; c = cache_get(ck)
    if c is not None: return c
    # Use OSP Gateway for totals, Usage API for service breakdown
    try:
        from oci.osp_gateway import InvoiceServiceClient
        cfg = oci_config()
        client = InvoiceServiceClient(cfg)
        resp = client.list_invoices(
            osp_home_region=cfg["region"],
            compartment_id=OCI_TENANCY_OCID
        )
        results = []
        for inv in (resp.data.items or []):
            try:
                amt  = float(inv.invoice_amount or 0)
                due  = float(inv.invoice_amount_due or 0)
                cur  = inv.currency.currency_code if inv.currency else "USD"
                raw  = str(inv.invoice_status or "OPEN")
                if "PAST_DUE" in raw:   status = "PAST_DUE"
                elif "PAID" in raw:     status = "PAID"
                elif "ACCUM" in raw:    status = "ACCUMULATING"
                else:                   status = raw
                due_dt  = inv.time_invoice_due
                due_str = due_dt.strftime("%b %d, %Y") if due_dt else "—"
                period_str = due_dt.strftime("%B %Y") if due_dt else str(inv.invoice_id)
                # Service breakdown filtered to this tenant
                by_svc = {}
                if due_dt:
                    bd   = due_dt.date() if hasattr(due_dt, 'date') else due_dt
                    ps   = bd.replace(day=1)
                    pe   = (bd.replace(day=28) + timedelta(days=4)).replace(day=1)
                    ts   = midnight(datetime(ps.year, ps.month, ps.day, tzinfo=timezone.utc))
                    te   = midnight(datetime(pe.year, pe.month, pe.day, tzinfo=timezone.utc))
                    sitems = oci_tenant_summarize(tenant_key, ts, te, group_by=["service"])
                    for si in sitems:
                        k = si.service or "Other"
                        v = float(si.computed_amount or 0)
                        if v > 0: by_svc[k] = round(by_svc.get(k, 0) + v, 2)
                # Tenant share = by_svc total (not full invoice amt which covers all tenants)
                tenant_total = round(sum(by_svc.values()), 2)
                results.append({
                    "id": str(inv.invoice_id),
                    "time_start": period_str,
                    "issue_date": due_dt.replace(day=1).strftime("%b %d, %Y") if due_dt else "—",
                    "time_invoice": due_str,
                    "amount": tenant_total,
                    "amount_due": tenant_total if status != "PAID" else 0,
                    "currency": cur, "status": status,
                    "by_service": by_svc
                })
            except Exception as ie:
                print(f"Invoice parse error: {ie}")
        results.sort(key=lambda x: int(x["id"]) if x["id"].isdigit() else 0, reverse=True)
        cache_set(ck, results); return results
    except Exception as e:
        print(f"Tenant invoice error: {e}"); return []



# ── Per-Tenant OCI Functions ───────────────────────────────────────────────────
def oci_date_range(period):
    """Return (start, end) datetimes for a given period string."""
    from datetime import datetime, timedelta, timezone
    def midnight(dt): return dt.replace(hour=0,minute=0,second=0,microsecond=0)
    today = midnight(datetime.now(timezone.utc))
    if period == "daily":
        return today, today + timedelta(days=1)
    elif period == "monthly":
        return today.replace(day=1), today + timedelta(days=1)
    elif period == "quarterly":
        m = today.month; qstart = m - ((m-1)%3)
        return today.replace(month=qstart, day=1), today + timedelta(days=1)
    elif period == "ytd":
        return today.replace(month=1, day=1), today + timedelta(days=1)
    else:
        return today.replace(day=1), today + timedelta(days=1)

def oci_tenant_summarize(tenant_name, start, end, granularity="MONTHLY", group_by=None):
    """Query OCI Usage API filtered to a specific tenant name."""
    import oci
    from oci.usage_api import UsageapiClient
    from oci.usage_api.models import RequestSummarizedUsagesDetails
    cfg = oci_config()
    client = UsageapiClient(cfg)
    gb = (group_by or []) + ["tenantName"]
    # deduplicate
    gb = list(dict.fromkeys(gb))
    import time as _time
    for _attempt in range(3):
        try:
            all_items = client.request_summarized_usages(
                RequestSummarizedUsagesDetails(
                    tenant_id=OCI_TENANCY_OCID,
                    time_usage_started=start,
                    time_usage_ended=end,
                    granularity=granularity,
                    query_type="COST",
                    compartment_depth=6,
                    group_by=gb
                )
            ).data.items or []
            break
        except Exception as _e:
            if "429" in str(_e) and _attempt < 2:
                _time.sleep(3 + _attempt * 2)
                continue
            raise
    else:
        all_items = []
    # Filter to this tenant only
    return [i for i in all_items
            if (getattr(i, 'tenant_name', None) or '').lower() == tenant_name.lower()]

def oci_tenant_fetch_kpis(tenant_key, period):
    ck = f"oci-tenant-kpis-{tenant_key}-{period}"; c = cache_get(ck)
    if c is not None: return c
    s, e = oci_date_range(period)
    items = oci_tenant_summarize(tenant_key, s, e)
    total = round(sum(float(i.computed_amount or 0) for i in items), 2)
    svcs  = {i.service for i in items if i.service}
    regs  = {i.region  for i in items if i.region}
    result = {"total_spend": total, "active_resources": 0,
              "active_services": len(svcs), "regions": len(regs),
              "currency": items[0].currency if items else "USD"}
    cache_set(ck, result); return result

def oci_tenant_fetch_services(tenant_key, period):
    ck = f"oci-tenant-services-{tenant_key}-{period}"; c = cache_get(ck)
    if c is not None: return c
    s, e = oci_date_range(period)
    items = oci_tenant_summarize(tenant_key, s, e, group_by=["service"])
    t = {}
    for i in items:
        k = i.service or "Other"
        t[k] = t.get(k, 0) + float(i.computed_amount or 0)
    result = [{"name": k, "value": round(v, 2)}
              for k, v in sorted(t.items(), key=lambda x: -x[1])]
    cache_set(ck, result); return result

def oci_tenant_fetch_trend(tenant_key, months=7):
    ck = f"oci-tenant-trend-{tenant_key}-{months}"; c = cache_get(ck)
    if c is not None: return c
    today = midnight(datetime.now(timezone.utc))
    s = today.replace(day=1)
    for _ in range(months - 1): s = (s - timedelta(days=1)).replace(day=1)
    e = today + timedelta(days=1)
    items = oci_tenant_summarize(tenant_key, s, e, granularity="MONTHLY",
                                  group_by=["service"])
    month_svc = {}
    for i in items:
        if not i.time_usage_started: continue
        mk = i.time_usage_started.strftime("%b %Y")
        sv = i.service or "Other"
        if mk not in month_svc: month_svc[mk] = {}
        month_svc[mk][sv] = month_svc[mk].get(sv, 0) + float(i.computed_amount or 0)
    result = [{"month": mk, **{sv: round(v, 2) for sv, v in svcs.items()}}
              for mk, svcs in month_svc.items()]
    cache_set(ck, result); return result

def oci_tenant_fetch_daily(tenant_key, days=28):
    ck = f"oci-tenant-daily-{tenant_key}-{days}"; c = cache_get(ck)
    if c is not None: return c
    today = midnight(datetime.now(timezone.utc))
    s = today - timedelta(days=days); e = today + timedelta(days=1)
    items = oci_tenant_summarize(tenant_key, s, e, granularity="DAILY")
    t = {}
    for i in items:
        if i.time_usage_started:
            dk = i.time_usage_started.strftime("%m-%d")
            t[dk] = t.get(dk, 0) + float(i.computed_amount or 0)
    result = [{"day": k, "cost": round(v, 2)} for k, v in sorted(t.items())]
    cache_set(ck, result); return result

def oci_tenant_fetch_resources(tenant_key, limit=10):
    ck = f"oci-tenant-resources-{tenant_key}-{limit}"; c = cache_get(ck)
    if c is not None: return c
    today = midnight(datetime.now(timezone.utc))
    s = today.replace(day=1); e = today + timedelta(days=1)
    if s >= e: s = e - timedelta(days=1)
    items = oci_tenant_summarize(tenant_key, s, e,
                                  group_by=["resourceId", "service", "region"])
    t = {}
    for i in items:
        rid = i.resource_id or "unknown"
        if rid not in t:
            rname = rid.split(".")[-1] if "." in rid else rid
        rname = rname[:40] if len(rname) > 40 else rname
        t[rid] = {"name": rname,
                      "type": i.service or "Other",
                      "region": (i.region or "").replace("us-ashburn-1","Example Region").replace("us-east-1","US East"),
                      "cost": 0}
        t[rid]["cost"] += float(i.computed_amount or 0)
    result = sorted([{"name": v["name"], "type": v["type"],
                      "region": v["region"], "cost": round(v["cost"], 2)}
                     for v in t.values()], key=lambda x: -x["cost"])[:limit]
    cache_set(ck, result); return result

def oci_tenant_fetch_enhanced_kpis(tenant_key):
    ck = f"oci-tenant-enhanced-{tenant_key}"; c = cache_get(ck)
    if c is not None: return c
    from calendar import monthrange
    today = midnight(datetime.now(timezone.utc))
    s_cur = today.replace(day=1); e_cur = today + timedelta(days=1)
    items_cur = oci_tenant_summarize(tenant_key, s_cur, e_cur)
    current  = round(sum(float(i.computed_amount or 0) for i in items_cur), 2)
    currency = items_cur[0].currency if items_cur else "USD"
    last_end   = today.replace(day=1)
    last_start = (last_end - timedelta(days=1)).replace(day=1)
    items_last = oci_tenant_summarize(tenant_key, last_start, last_end)
    last_month = round(sum(float(i.computed_amount or 0) for i in items_last), 2)
    days_passed   = today.day
    days_in_month = monthrange(today.year, today.month)[1]
    forecast = round((current / days_passed) * days_in_month, 2) if days_passed else 0
    s_daily = today - timedelta(days=30)
    items_d = oci_tenant_summarize(tenant_key, s_daily, today + timedelta(days=1),
                                    granularity="DAILY")
    daily_t = {}
    for i in items_d:
        if i.time_usage_started:
            dk = i.time_usage_started.strftime("%Y-%m-%d")
            daily_t[dk] = daily_t.get(dk, 0) + float(i.computed_amount or 0)
    avg_daily = round(sum(daily_t.values()) / len(daily_t), 2) if daily_t else 0
    s_trend = today.replace(day=1)
    for _ in range(5): s_trend = (s_trend - timedelta(days=1)).replace(day=1)
    items_tr = oci_tenant_summarize(tenant_key, s_trend, today + timedelta(days=1),
                                     granularity="MONTHLY")
    trend_map = {}
    for i in items_tr:
        if i.time_usage_started:
            mk = i.time_usage_started.strftime("%b %Y")
            trend_map[mk] = trend_map.get(mk, 0) + float(i.computed_amount or 0)
    trend6  = [{"month": k, "cost": round(v, 2)} for k, v in trend_map.items()]
    mom_pct = round(((current - last_month) / last_month * 100), 1) if last_month else 0
    result = {"current_month": current, "last_month": last_month, "forecast": forecast,
              "avg_daily": avg_daily, "currency": currency, "mom_pct": mom_pct,
              "days_passed": days_passed, "trend6": trend6}
    cache_set(ck, result); return result

def oci_tenant_fetch_invoices(tenant_key):
    ck = f"oci-tenant-invoices-{tenant_key}"; c = cache_get(ck)
    if c is not None: return c
    import oci as _oci
    from oci.osp_gateway import InvoiceServiceClient
    try:
        cfg = oci_config()
        client = InvoiceServiceClient(cfg)
        resp = client.list_invoices(
            osp_home_region=cfg["region"],
            compartment_id=OCI_TENANCY_OCID
        )
        results = []
        for inv in (resp.data.items or []):
            try:
                amt  = float(inv.invoice_amount or 0)
                due  = float(inv.invoice_amount_due or 0)
                cur  = inv.currency.currency_code if inv.currency else "USD"
                raw  = str(inv.invoice_status or "OPEN")
                if "PAST_DUE" in raw:   status = "PAST_DUE"
                elif "PAID" in raw:     status = "PAID"
                elif "ACCUM" in raw:    status = "ACCUMULATING"
                else:                   status = raw
                due_dt   = inv.time_invoice_due
                due_str  = due_dt.strftime("%b %d, %Y") if due_dt else "—"
                period_str = due_dt.strftime("%B %Y") if due_dt else str(inv.invoice_id)
                # Get tenant share via usage API
                by_svc = {}
                if due_dt:
                    bd  = due_dt.date() if hasattr(due_dt,"date") else due_dt
                    ps  = bd.replace(day=1)
                    pe  = (bd.replace(day=28) + timedelta(days=4)).replace(day=1)
                    ts  = midnight(datetime(ps.year,ps.month,ps.day,tzinfo=timezone.utc))
                    te  = midnight(datetime(pe.year,pe.month,pe.day,tzinfo=timezone.utc))
                    import time as _t; _t.sleep(1)  # avoid 429
                    sitems = oci_tenant_summarize(tenant_key, ts, te, group_by=["service"])
                    for si in sitems:
                        k = si.service or "Other"
                        v = float(si.computed_amount or 0)
                        if v > 0: by_svc[k] = round(by_svc.get(k,0)+v, 2)
                tenant_total = round(sum(by_svc.values()), 2)
                if tenant_total == 0: continue  # skip if tenant has no spend this period
                results.append({
                    "id": str(inv.invoice_id),
                    "time_start": period_str,
                    "issue_date": due_dt.replace(day=1).strftime("%b %d, %Y") if due_dt else "—",
                    "time_invoice": due_str,
                    "amount": tenant_total,
                    "amount_due": tenant_total if status != "PAID" else 0,
                    "currency": cur, "status": status,
                    "by_service": by_svc
                })
            except Exception as ie:
                print(f"Invoice parse error: {ie}")
        results.sort(key=lambda x: int(x["id"]) if x["id"].isdigit() else 0, reverse=True)
        cache_set(ck, results); return results
    except Exception as e:
        print(f"Tenant invoice error {tenant_key}: {e}"); return []
    ck = f"oci-tenant-invoices-{tenant_key}"; c = cache_get(ck)
    if c is not None: return c
    # Use OSP Gateway for totals, Usage API for service breakdown
    try:
        from oci.osp_gateway import InvoiceServiceClient
        cfg = oci_config()
        client = InvoiceServiceClient(cfg)
        resp = client.list_invoices(
            osp_home_region=cfg["region"],
            compartment_id=OCI_TENANCY_OCID
        )
        results = []
        for inv in (resp.data.items or []):
            try:
                amt  = float(inv.invoice_amount or 0)
                due  = float(inv.invoice_amount_due or 0)
                cur  = inv.currency.currency_code if inv.currency else "USD"
                raw  = str(inv.invoice_status or "OPEN")
                if "PAST_DUE" in raw:   status = "PAST_DUE"
                elif "PAID" in raw:     status = "PAID"
                elif "ACCUM" in raw:    status = "ACCUMULATING"
                else:                   status = raw
                due_dt  = inv.time_invoice_due
                due_str = due_dt.strftime("%b %d, %Y") if due_dt else "—"
                period_str = due_dt.strftime("%B %Y") if due_dt else str(inv.invoice_id)
                # Service breakdown filtered to this tenant
                by_svc = {}
                if due_dt:
                    bd   = due_dt.date() if hasattr(due_dt, 'date') else due_dt
                    ps   = bd.replace(day=1)
                    pe   = (bd.replace(day=28) + timedelta(days=4)).replace(day=1)
                    ts   = midnight(datetime(ps.year, ps.month, ps.day, tzinfo=timezone.utc))
                    te   = midnight(datetime(pe.year, pe.month, pe.day, tzinfo=timezone.utc))
                    sitems = oci_tenant_summarize(tenant_key, ts, te, group_by=["service"])
                    for si in sitems:
                        k = si.service or "Other"
                        v = float(si.computed_amount or 0)
                        if v > 0: by_svc[k] = round(by_svc.get(k, 0) + v, 2)
                # Tenant share = by_svc total (not full invoice amt which covers all tenants)
                tenant_total = round(sum(by_svc.values()), 2)
                results.append({
                    "id": str(inv.invoice_id),
                    "time_start": period_str,
                    "issue_date": due_dt.replace(day=1).strftime("%b %d, %Y") if due_dt else "—",
                    "time_invoice": due_str,
                    "amount": tenant_total,
                    "amount_due": tenant_total if status != "PAID" else 0,
                    "currency": cur, "status": status,
                    "by_service": by_svc
                })
            except Exception as ie:
                print(f"Invoice parse error: {ie}")
        results.sort(key=lambda x: int(x["id"]) if x["id"].isdigit() else 0, reverse=True)
        cache_set(ck, results); return results
    except Exception as e:
        print(f"Tenant invoice error: {e}"); return []


def aws_account(account_key="primaryaws"):
    """Return a validated AWS account configuration without exposing secrets."""
    account = AWS_ACCOUNTS.get(account_key)
    if not account:
        raise ValueError(f"Unknown AWS account: {account_key}")
    if not account.get("access_key_id") or not account.get("secret_access_key"):
        raise RuntimeError(f"AWS credentials are not configured for {account['name']}")
    return account


def aws_client(service, account_key="primaryaws"):
    import boto3
    account = aws_account(account_key)
    return boto3.client(
        service,
        aws_access_key_id=account["access_key_id"],
        aws_secret_access_key=account["secret_access_key"],
        region_name=account["region"],
    )


def aws_date_range(period):
    today = datetime.now(timezone.utc).date()
    if period == "daily":       return (today - timedelta(days=1)).isoformat(), today.isoformat()
    elif period == "monthly":   return today.replace(day=1).isoformat(), today.isoformat()
    elif period == "quarterly":
        qm = ((today.month - 1) // 3) * 3 + 1
        return today.replace(month=qm, day=1).isoformat(), today.isoformat()
    elif period == "ytd":       return today.replace(month=1, day=1).isoformat(), today.isoformat()
    else:                        return (today - timedelta(days=30)).isoformat(), today.isoformat()


def aws_safe_range(period):
    s, e = aws_date_range(period)
    if s >= e:
        from datetime import date
        e_date = date.fromisoformat(e)
        s = (e_date - timedelta(days=1)).isoformat()
    return s, e



def aws_cost_query_options(account_key="primaryaws"):
    """
    Exclude credits and refunds for AWS providers configured to show
    gross usage charges rather than the net amount payable.
    """
    import os as _os

    gross_slugs = {
        item.strip()
        for item in _os.environ.get(
            "AWS_GROSS_COST_PROVIDER_SLUGS",
            "primaryaws"
        ).split(",")
        if item.strip()
    }

    if account_key not in gross_slugs:
        return {}

    return {
        "Filter": {
            "Not": {
                "Dimensions": {
                    "Key": "RECORD_TYPE",
                    "Values": ["Credit", "Refund"],
                }
            }
        }
    }


def aws_fetch_kpis(period, account_key="primaryaws"):
    ck = f"aws-{account_key}-kpis-{period}"; c = cache_get(ck)
    if c is not None: return c
    ce = aws_client("ce", account_key); s, e = aws_safe_range(period)
    r = ce.get_cost_and_usage(
        TimePeriod={"Start": s, "End": e},
        Granularity="MONTHLY", Metrics=["BlendedCost"],
        **aws_cost_query_options(account_key),
        GroupBy=[{"Type": "DIMENSION", "Key": "SERVICE"}],
    )
    total = 0; svcs = set()
    for res in r.get("ResultsByTime", []):
        for grp in res.get("Groups", []):
            cost = float(grp["Metrics"]["BlendedCost"]["Amount"])
            if cost > 0:
                total += cost; svcs.add(grp["Keys"][0])
    result = {
        "total_spend": round(total, 2), "active_resources": 0,
        "active_services": len(svcs), "regions": 1,
        "currency": "USD", "period": period,
    }
    cache_set(ck, result); return result


def aws_fetch_services(period, account_key="primaryaws"):
    ck = f"aws-{account_key}-services-{period}"; c = cache_get(ck)
    if c is not None: return c
    ce = aws_client("ce", account_key); s, e = aws_safe_range(period)
    r = ce.get_cost_and_usage(
        TimePeriod={"Start": s, "End": e},
        Granularity="MONTHLY", Metrics=["BlendedCost"],
        **aws_cost_query_options(account_key),
        GroupBy=[{"Type": "DIMENSION", "Key": "SERVICE"}],
    )
    totals = {}
    for res in r.get("ResultsByTime", []):
        for grp in res.get("Groups", []):
            service = grp["Keys"][0]
            cost = float(grp["Metrics"]["BlendedCost"]["Amount"])
            if cost > 0.001:
                totals[service] = totals.get(service, 0) + cost
    result = [
        {"name": name, "value": round(value, 2)}
        for name, value in sorted(totals.items(), key=lambda x: -x[1])
    ]
    cache_set(ck, result); return result


def aws_fetch_trend(months=7, account_key="primaryaws"):
    months = max(1, min(int(months), 24))
    ck = f"aws-{account_key}-trend-{months}"; c = cache_get(ck)
    if c is not None: return c
    ce = aws_client("ce", account_key)
    today = datetime.now(timezone.utc).date()
    start = today.replace(day=1)
    for _ in range(months - 1):
        start = (start - timedelta(days=1)).replace(day=1)
    r = ce.get_cost_and_usage(
        TimePeriod={"Start": start.isoformat(), "End": today.isoformat()},
        Granularity="MONTHLY", Metrics=["BlendedCost"],
        **aws_cost_query_options(account_key),
        GroupBy=[{"Type": "DIMENSION", "Key": "SERVICE"}],
    )
    totals = {}
    for res in r.get("ResultsByTime", []):
        month = datetime.strptime(res["TimePeriod"]["Start"][:7], "%Y-%m").strftime("%b %Y")
        totals.setdefault(month, {})
        for grp in res.get("Groups", []):
            service = grp["Keys"][0]
            cost = float(grp["Metrics"]["BlendedCost"]["Amount"])
            if cost > 0:
                totals[month][service] = totals[month].get(service, 0) + cost
    result = [
        dict(month=month, **{name: round(value, 2) for name, value in services.items()})
        for month, services in totals.items()
    ]
    cache_set(ck, result); return result


def aws_fetch_daily(days=28, account_key="primaryaws"):
    days = max(1, min(int(days), 366))
    ck = f"aws-{account_key}-daily-{days}"; c = cache_get(ck)
    if c is not None: return c
    ce = aws_client("ce", account_key)
    today = datetime.now(timezone.utc).date()
    start = (today - timedelta(days=days)).isoformat()
    end = today.isoformat()
    r = ce.get_cost_and_usage(
        TimePeriod={"Start": start, "End": end},
        Granularity="DAILY", Metrics=["BlendedCost"],
        **aws_cost_query_options(account_key),
    )
    result = [
        {
            "day": res["TimePeriod"]["Start"],
            "cost": round(float(res["Total"]["BlendedCost"]["Amount"]), 2),
        }
        for res in r.get("ResultsByTime", [])
    ]
    cache_set(ck, result); return result


def aws_fetch_resources(limit=10, account_key="primaryaws"):
    limit = max(1, min(int(limit), 50))
    ck = f"aws-{account_key}-resources-{limit}"; c = cache_get(ck)
    if c is not None: return c
    ce = aws_client("ce", account_key); s, e = aws_safe_range("monthly")
    r = ce.get_cost_and_usage(
        TimePeriod={"Start": s, "End": e},
        Granularity="MONTHLY", Metrics=["BlendedCost"],
        **aws_cost_query_options(account_key),
        GroupBy=[
            {"Type": "DIMENSION", "Key": "SERVICE"},
            {"Type": "DIMENSION", "Key": "REGION"},
        ],
    )
    resources = []
    for result in r.get("ResultsByTime", []):
        for grp in result.get("Groups", []):
            service, region = grp["Keys"][0], grp["Keys"][1]
            cost = float(grp["Metrics"]["BlendedCost"]["Amount"])
            if cost > 0:
                resources.append({
                    "id": f"{service} ({region})", "friendly": service,
                    "type": service, "region": region, "cost": round(cost, 2),
                })
    result = sorted(resources, key=lambda x: -x["cost"])[:limit]
    cache_set(ck, result); return result


def aws_fetch_invoices(account_key="primaryaws"):
    ck = f"aws-{account_key}-invoices"; c = cache_get(ck)
    if c is not None: return c
    ce = aws_client("ce", account_key)
    today = datetime.now(timezone.utc).date()
    results = []
    for i in range(6):
        if i == 0:
            start = today.replace(day=1)
            end = today + timedelta(days=1)
            status = "ACCUMULATING"
        else:
            previous = today.replace(day=1) - timedelta(days=1)
            for _ in range(i - 1):
                previous = previous.replace(day=1) - timedelta(days=1)
            start = previous.replace(day=1)
            end = (start.replace(day=28) + timedelta(days=4)).replace(day=1)
            status = "PAID"
        if start >= end:
            end = start + timedelta(days=1)
        try:
            response = ce.get_cost_and_usage(
                TimePeriod={"Start": start.isoformat(), "End": end.isoformat()},
                Granularity="MONTHLY", Metrics=["BlendedCost"],
                **aws_cost_query_options(account_key),
                GroupBy=[{"Type": "DIMENSION", "Key": "SERVICE"}],
            )
            total = 0; by_service = {}
            for result in response.get("ResultsByTime", []):
                for grp in result.get("Groups", []):
                    service = grp["Keys"][0]
                    cost = float(grp["Metrics"]["BlendedCost"]["Amount"])
                    if cost > 0:
                        total += cost
                        by_service[service] = by_service.get(service, 0) + cost
        except Exception as exc:
            print(f"AWS invoice error for {account_key}: {exc}")
            total = 0; by_service = {}
        due_date = (start.replace(day=28) + timedelta(days=4)).replace(day=1) - timedelta(days=1)
        results.append({
            "id": f"AWS-{start.strftime('%Y%m')}",
            "period": start.strftime("%B %Y"),
            "status": status,
            "amount": round(total, 2),
            "amount_due": round(total, 2) if status != "PAID" else 0,
            "currency": "USD",
            "time_invoice": due_date.strftime("%b %d, %Y"),
            "time_start": start.strftime("%B %Y"),
            "issue_date": (start.replace(day=28) + timedelta(days=4)).replace(day=1).strftime("%b %d, %Y"),
            "date_from": start.isoformat(), "date_to": end.isoformat(),
            "by_service": {
                name: round(value, 2)
                for name, value in sorted(by_service.items(), key=lambda x: -x[1])
            },
        })
    cache_set(ck, results); return results


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        if check_pw(request.form.get("password", "")):
            session["logged_in"] = True; return redirect(url_for("index"))
        error = "Invalid password"
    return render_template("login.html", error=error)

@app.route("/logout")
def logout():
    session.clear(); return redirect(url_for("login"))

@app.route("/")
@login_required
def index():
    providers = [
        provider_store.public_provider(item)
        for item in provider_store.list_providers(enabled_only=True)
    ]
    return render_template(
        "dashboard.html",
        provider_rows=providers,
        oci_region=OCI_REGION_ID,
        aws_region=AWS_DEFAULT_REGION,
    )

# ── Per-Tenant OCI API Routes ─────────────────────────────────────────────────
@app.route("/api/oci/tenants")
@api_auth
def api_oci_tenants():
    return jsonify({"ok": True, "data": OCI_TENANTS})

@app.route("/api/oci/<tenant_key>/kpis")
@api_auth
def api_oci_tenant_kpis(tenant_key):
    try: return jsonify({"ok": True, "data": oci_tenant_fetch_kpis(tenant_key, request.args.get("period","monthly"))})
    except Exception as e: return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/api/oci/<tenant_key>/services")
@api_auth
def api_oci_tenant_services(tenant_key):
    try: return jsonify({"ok": True, "data": oci_tenant_fetch_services(tenant_key, request.args.get("period","monthly"))})
    except Exception as e: return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/api/oci/<tenant_key>/trend")
@api_auth
def api_oci_tenant_trend(tenant_key):
    try: return jsonify({"ok": True, "data": oci_tenant_fetch_trend(tenant_key, int(request.args.get("months",7)))})
    except Exception as e: return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/api/oci/<tenant_key>/daily")
@api_auth
def api_oci_tenant_daily(tenant_key):
    try: return jsonify({"ok": True, "data": oci_tenant_fetch_daily(tenant_key, int(request.args.get("days",28)))})
    except Exception as e: return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/api/oci/<tenant_key>/resources")
@api_auth
def api_oci_tenant_resources(tenant_key):
    try: return jsonify({"ok": True, "data": oci_tenant_fetch_resources(tenant_key, int(request.args.get("limit",10)))})
    except Exception as e: return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/api/oci/<tenant_key>/enhanced_kpis")
@api_auth
def api_oci_tenant_enhanced(tenant_key):
    try: return jsonify({"ok": True, "data": oci_tenant_fetch_enhanced_kpis(tenant_key)})
    except Exception as e: return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/api/oci/<tenant_key>/invoices")
@api_auth
def api_oci_tenant_invoices(tenant_key):
    try: return jsonify({"ok": True, "data": oci_tenant_fetch_invoices(tenant_key)})
    except Exception as e: return jsonify({"ok": False, "error": str(e)}), 500



@app.route("/api/oci/combined/invoices")
@api_auth
def api_oci_combined_invoices():
    try:
        ck = "oci-combined-invoices"; c = cache_get(ck)
        if c is not None: return jsonify({"ok": True, "data": c})
        from oci.osp_gateway import InvoiceServiceClient
        cfg = oci_config()
        client = InvoiceServiceClient(cfg)
        resp = client.list_invoices(
            osp_home_region=cfg["region"],
            compartment_id=OCI_TENANCY_OCID
        )
        TENANT_KEYS = [
            item.get("config", {}).get("tenant_name", item["slug"])
            for item in provider_store.list_providers(enabled_only=True)
            if item["provider_type"] == "oci_tenant"
        ]
        results = []
        for inv in (resp.data.items or []):
            try:
                amt    = float(inv.invoice_amount or 0)
                due    = float(inv.invoice_amount_due or 0)
                cur    = inv.currency.currency_code if inv.currency else "USD"
                raw    = str(inv.invoice_status or "OPEN")
                # Use balance_due to determine real status — OSP sometimes shows PAST_DUE even when paid
                _due_amt = float(inv.invoice_amount_due or 0)
                if _due_amt == 0 or "CLOSED" in raw or "PAID" in raw:
                    status = "PAID"
                elif "ACCUM" in raw:
                    status = "ACCUMULATING"
                elif "PAST_DUE" in raw or "OPEN" in raw:
                    status = "PAST_DUE"
                else:
                    status = raw
                due_dt     = inv.time_invoice_due
                due_str    = due_dt.strftime("%b %d, %Y") if due_dt else "—"
                period_str = due_dt.strftime("%B %Y") if due_dt else str(inv.invoice_id)
                # Per-tenant breakdown
                by_tenant = {}
                if due_dt:
                    import time as _t
                    bd = due_dt.date() if hasattr(due_dt,"date") else due_dt
                    ps = bd.replace(day=1)
                    pe = (bd.replace(day=28) + timedelta(days=4)).replace(day=1)
                    ts = midnight(datetime(ps.year,ps.month,ps.day,tzinfo=timezone.utc))
                    te = midnight(datetime(pe.year,pe.month,pe.day,tzinfo=timezone.utc))
                    for tk in TENANT_KEYS:
                        _t.sleep(0.5)
                        try:
                            sitems = oci_tenant_summarize(tk, ts, te, group_by=["service"])
                            total  = round(sum(float(i.computed_amount or 0) for i in sitems), 2)
                            svcs   = {}
                            for si in sitems:
                                k = si.service or "Other"
                                v = float(si.computed_amount or 0)
                                if v > 0: svcs[k] = round(svcs.get(k,0)+v,2)
                            if total > 0:
                                by_tenant[tk] = {"total": total, "services": svcs}
                        except Exception as te_err:
                            print(f"Tenant {tk} breakdown error: {te_err}")
                results.append({
                    "id": str(inv.invoice_id),
                    "time_start": period_str,
                    "issue_date": due_dt.replace(day=1).strftime("%b %d, %Y") if due_dt else "—",
                    "time_invoice": due_str,
                    "amount": round(amt, 2),
                    "amount_due": round(due, 2),
                    "currency": cur,
                    "status": status,
                    "by_tenant": by_tenant
                })
            except Exception as ie:
                print(f"Combined invoice parse error: {ie}")
        results.sort(key=lambda x: int(x["id"]) if x["id"].isdigit() else 0, reverse=True)
        cache_set(ck, results)
        return jsonify({"ok": True, "data": results})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/api/oci/combined/invoices/<invoice_id>/download")
@api_auth
def api_oci_combined_invoice_download(invoice_id):
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib import colors
        from reportlab.lib.units import cm
        from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, HRFlowable
        from reportlab.lib.styles import ParagraphStyle
        from reportlab.lib.enums import TA_RIGHT, TA_CENTER
        from io import BytesIO
        # Get combined invoices
        resp = api_oci_combined_invoices()
        inv_list = resp.get_json()["data"]
        inv = next((x for x in inv_list if x["id"] == invoice_id), None)
        if not inv: return jsonify({"ok": False, "error": "Invoice not found"}), 404

        accent = colors.HexColor("#C74634")
        muted  = colors.HexColor("#888888")
        buf    = BytesIO()
        doc    = SimpleDocTemplate(buf, pagesize=A4,
                     rightMargin=2*cm, leftMargin=2*cm,
                     topMargin=2*cm, bottomMargin=2*cm)
        story  = []

        # Header
        story.append(Paragraph("Oracle Cloud Infrastructure",
            ParagraphStyle("t", fontSize=22, textColor=accent, spaceAfter=4, fontName="Helvetica-Bold")))
        story.append(Paragraph("Combined Billing Invoice — All Tenants",
            ParagraphStyle("s", fontSize=10, textColor=muted, spaceAfter=2)))
        story.append(HRFlowable(width="100%", thickness=2, color=accent, spaceAfter=12))

        # Meta
        meta = [
            ["Invoice ID:", inv["id"], "Status:", inv["status"]],
            ["Billing Period:", inv["time_start"], "Due Date:", inv["time_invoice"]],
            ["Currency:", inv["currency"], "Total Amount:", f"{inv['currency']} {inv['amount']:,.2f}"],
        ]
        mt = Table(meta, colWidths=[3.5*cm, 7*cm, 3*cm, 4*cm])
        mt.setStyle(TableStyle([
            ("FONTNAME", (0,0), (-1,-1), "Helvetica"),
            ("FONTNAME", (0,0), (0,-1), "Helvetica-Bold"),
            ("FONTNAME", (2,0), (2,-1), "Helvetica-Bold"),
            ("FONTSIZE", (0,0), (-1,-1), 9),
            ("ROWBACKGROUNDS", (0,0), (-1,-1), [colors.HexColor("#F9F9F9"), colors.white]),
            ("PADDING", (0,0), (-1,-1), 5),
            ("GRID", (0,0), (-1,-1), 0.25, colors.HexColor("#E0E0E0")),
        ]))
        story.append(mt)
        story.append(Spacer(1, 16))

        # Per-tenant breakdown
        TENANT_NAMES = {"primaryoci":"Primary Account","clientalpha":"Client Alpha","clientbeta":"Client Beta","clientgamma":"Client Gamma","clientdelta":"Client Delta"}
        TENANT_COLORS = {"primaryoci":"#C74634","clientalpha":"#7C3AED","clientbeta":"#059669","clientgamma":"#0284C7","clientdelta":"#EA580C"}
        cur = inv["currency"]
        grand_subtotal = 0

        for tk, tdata in inv.get("by_tenant", {}).items():
            tname  = TENANT_NAMES.get(tk, tk)
            tcolor = colors.HexColor(TENANT_COLORS.get(tk, "#444444"))
            story.append(Spacer(1, 10))
            story.append(Paragraph(f"▸ {tname}",
                ParagraphStyle("th", fontSize=12, textColor=tcolor,
                               spaceBefore=6, spaceAfter=4, fontName="Helvetica-Bold")))
            svc_data = [["Service", f"Amount ({cur})"]]
            for svc, cost in sorted(tdata["services"].items(), key=lambda x:-x[1]):
                svc_data.append([svc, f"{cur} {cost:,.2f}"])
            subtotal = tdata["total"]
            grand_subtotal += subtotal
            svc_data.append(["", ""])
            svc_data.append([f"{tname} Subtotal", f"{cur} {subtotal:,.2f}"])
            st = Table(svc_data, colWidths=[13*cm, 4.5*cm])
            st.setStyle(TableStyle([
                ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
                ("FONTNAME", (0,-1), (-1,-1), "Helvetica-Bold"),
                ("FONTSIZE", (0,0), (-1,-1), 9),
                ("BACKGROUND", (0,0), (-1,0), tcolor),
                ("TEXTCOLOR", (0,0), (-1,0), colors.white),
                ("BACKGROUND", (0,-1), (-1,-1), colors.HexColor("#F5F5F5")),
                ("TEXTCOLOR", (0,-1), (-1,-1), tcolor),
                ("ALIGN", (1,0), (1,-1), "RIGHT"),
                ("ROWBACKGROUNDS", (0,1), (-1,-2), [colors.white, colors.HexColor("#F9F9F9")]),
                ("GRID", (0,0), (-1,-1), 0.25, colors.HexColor("#E0E0E0")),
                ("PADDING", (0,0), (-1,-1), 6),
                ("LINEABOVE", (0,-1), (-1,-1), 1, tcolor),
            ]))
            story.append(st)

        # Tax adjustment + Grand Total
        story.append(Spacer(1, 16))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#CCCCCC"), spaceAfter=8))
        vat = round(inv["amount"] - grand_subtotal, 2)
        summary_data = [["", ""]]
        summary_data.append(["Combined Subtotal", f"{cur} {grand_subtotal:,.2f}"])
        if vat > 0:
            summary_data.append(["Tax adjustment", f"{cur} {vat:,.2f}"])
        summary_data.append(["TOTAL INVOICE AMOUNT", f"{cur} {inv['amount']:,.2f}"])
        st2 = Table(summary_data, colWidths=[13*cm, 4.5*cm])
        st2.setStyle(TableStyle([
            ("FONTNAME", (0,-1), (-1,-1), "Helvetica-Bold"),
            ("FONTSIZE", (0,0), (-1,-1), 10),
            ("BACKGROUND", (0,-1), (-1,-1), colors.HexColor("#F5F5F5")),
            ("TEXTCOLOR", (0,-1), (-1,-1), accent),
            ("ALIGN", (1,0), (1,-1), "RIGHT"),
            ("LINEABOVE", (0,-1), (-1,-1), 1.5, accent),
            ("PADDING", (0,0), (-1,-1), 6),
        ]))
        story.append(st2)

        # Amount Due
        story.append(Spacer(1, 20))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#EEEEEE"), spaceAfter=10))
        story.append(Paragraph(
            f"Amount Due: {cur} {inv['amount_due']:,.2f}",
            ParagraphStyle("due", fontSize=16, textColor=accent,
                           fontName="Helvetica-Bold", alignment=TA_RIGHT)))
        story.append(Spacer(1, 6))
        story.append(Paragraph(
            "Generated from Oracle Cloud Infrastructure billing API. For official invoices visit your cloud console.",
            ParagraphStyle("foot", fontSize=7, textColor=muted, alignment=TA_CENTER)))

        doc.build(story)
        buf.seek(0)
        from flask import send_file
        return send_file(buf, mimetype="application/pdf",
                        as_attachment=True,
                        download_name=f"OCI_Combined_Invoice_{inv['time_start'].replace(' ','_')}.pdf")
    except Exception as e:
        import traceback; traceback.print_exc()
        return jsonify({"ok": False, "error": str(e)}), 500


# ══════════════════════════════════════════════════════════
# TELEGRAM BOT — provider list is loaded dynamically from SQLite
# ══════════════════════════════════════════════════════════
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_GROUP_ID = int(os.environ.get("TELEGRAM_GROUP_ID", "0") or 0)
SECONDARY_TELEGRAM_GROUP_ID = int(os.environ.get("SECONDARY_TELEGRAM_GROUP_ID", "0") or 0)
SECONDARY_PROVIDER_SLUG = os.environ.get("SECONDARY_PROVIDER_SLUG", "clientaws").strip() or "clientaws"
SECONDARY_EXCLUDE_FROM_MAIN = os.environ.get("SECONDARY_EXCLUDE_FROM_MAIN", "true").lower() not in {"0", "false", "no", "off"}


def tg_send(chat_id, text):
    """Send a Telegram message."""
    if not TELEGRAM_BOT_TOKEN:
        print("[tg] TELEGRAM_BOT_TOKEN is not configured")
        return
    import urllib.request
    import json as _json
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    data = _json.dumps({"chat_id": chat_id, "text": text, "parse_mode": "HTML"}).encode()
    try:
        req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=20)
    except Exception as exc:
        print(f"[tg] send error: {exc}")


def telegram_provider_rows(chat_id=None):
    providers = provider_store.list_providers(enabled_only=True, telegram_only=True)
    try:
        chat_id_value = int(chat_id) if chat_id is not None else 0
    except (TypeError, ValueError):
        chat_id_value = 0

    if SECONDARY_TELEGRAM_GROUP_ID and chat_id_value == SECONDARY_TELEGRAM_GROUP_ID:
        return [provider for provider in providers if provider["slug"] == SECONDARY_PROVIDER_SLUG]

    if (
        SECONDARY_EXCLUDE_FROM_MAIN
        and SECONDARY_TELEGRAM_GROUP_ID
        and chat_id_value == TELEGRAM_GROUP_ID
    ):
        return [provider for provider in providers if provider["slug"] != SECONDARY_PROVIDER_SLUG]

    return providers


def tg_currency(amount, currency):
    return f"${amount:,.2f}" if currency == "USD" else f"{currency} {amount:,.2f}"


def tg_report_provider(provider):
    try:
        enhanced = fetch_provider_metric(provider, "enhanced_kpis")
        daily = fetch_provider_metric(provider, "daily", days=2)
        latest = daily[-1]["cost"] if daily else 0
        currency = enhanced.get("currency") or provider.get("currency", "USD")
        lines = [
            f"{provider['icon']} <b>{provider['name']}</b>",
            "━━━━━━━━━━━━━━━━━━",
            f"📅 Latest Daily Spend: <b>{tg_currency(latest, currency)}</b>",
            f"📆 Month-to-Date: <b>{tg_currency(enhanced.get('current_month', 0), currency)}</b>",
            f"📊 Last Month: {tg_currency(enhanced.get('last_month', 0), currency)}",
            f"🔮 Forecast: {tg_currency(enhanced.get('forecast', 0), currency)}",
            f"📈 MoM: {enhanced.get('mom_pct', 0):+.1f}%",
        ]
        if provider["provider_type"] == "portal":
            lines.extend([
                f"💰 Balance: {tg_currency(enhanced.get('balance', 0), currency)}",
                f"💳 Account Credit: {tg_currency(enhanced.get('account_credit', 0), currency)}" + (" ⚠️" if enhanced.get("low_credit_alert") else ""),
                f"🎁 Promo Credit: {tg_currency(enhanced.get('promotional_credit', 0), currency)}",
            ])
        return "\n".join(lines)
    except Exception as exc:
        return f"{provider.get('icon', '☁')} <b>{provider.get('name', provider.get('slug', 'Provider'))}</b>\n⚠️ Error: {exc}"


def tg_fetch_oci_combined_invoices():
    """Fetch actual OCI invoice totals once instead of duplicating them per tenant."""
    ck = "oci-combined-invoices"
    cached = cache_get(ck)
    if cached is not None:
        return cached

    from oci.osp_gateway import InvoiceServiceClient

    cfg = oci_config()
    client = InvoiceServiceClient(cfg)
    response = client.list_invoices(
        osp_home_region=cfg["region"],
        compartment_id=OCI_TENANCY_OCID,
    )
    results = []
    for invoice in response.data.items or []:
        try:
            amount = float(invoice.invoice_amount or 0)
            amount_due = float(invoice.invoice_amount_due or 0)
            currency = invoice.currency.currency_code if invoice.currency else "USD"
            raw = str(invoice.invoice_status or "OPEN").upper()
            if amount_due == 0 or "CLOSED" in raw or "PAID" in raw:
                status = "PAID"
            elif "ACCUM" in raw:
                status = "ACCUMULATING"
            elif "PAST_DUE" in raw or "OPEN" in raw:
                status = "PAST_DUE"
            else:
                status = raw
            due_date = invoice.time_invoice_due
            results.append({
                "id": str(invoice.invoice_id),
                "time_start": due_date.strftime("%B %Y") if due_date else str(invoice.invoice_id),
                "time_invoice": due_date.strftime("%b %d, %Y") if due_date else "—",
                "amount": round(amount, 2),
                "amount_due": round(amount_due, 2),
                "currency": currency,
                "status": status,
            })
        except Exception as exc:
            print(f"[tg] combined OCI invoice parse error: {exc}")
    results.sort(key=lambda item: int(item["id"]) if str(item["id"]).isdigit() else 0, reverse=True)
    cache_set(ck, results)
    return results


def tg_help_text(chat_id):
    lines = [
        "📊 <b>ExaBilling Bot Commands</b>",
        "━━━━━━━━━━━━━━━━━━",
        "/today — Latest daily spend for enabled providers",
        "/month — Month-to-date and forecast",
        "/invoices — Invoice status and unpaid alerts",
    ]
    for provider in telegram_provider_rows(chat_id):
        lines.append(f"/{provider['slug']} — {provider['name']}")
    lines.append("/help — Show this menu")
    return "\n".join(lines)


def tg_report_invoices(chat_id):
    lines = ["🧾 <b>Invoice Status</b>", "━━━━━━━━━━━━━━━━━━"]
    unpaid = 0
    providers = telegram_provider_rows(chat_id)
    has_oci = any(provider["provider_type"] == "oci_tenant" for provider in providers)

    for provider in providers:
        if provider["provider_type"] == "oci_tenant":
            continue
        try:
            invoices = fetch_provider_metric(provider, "invoices") or []
            for inv in invoices[:6]:
                status_raw = inv.get("status", "")
                status = "🟡 ACCUM" if status_raw == "ACCUMULATING" else "✅ PAID" if status_raw in ("PAID", "CLOSED") or inv.get("amount_due", 0) == 0 else "🔴 OVERDUE"
                currency = inv.get("currency", provider.get("currency", "USD"))
                lines.append(f"{provider['icon']} {provider['name']} {inv.get('time_start', '')}: {tg_currency(inv.get('amount', 0), currency)} {status}")
                if inv.get("amount_due", 0) > 0 and status_raw not in ("ACCUMULATING", "PAID", "CLOSED"):
                    unpaid += 1
        except Exception as exc:
            lines.append(f"{provider['icon']} {provider['name']} error: {exc}")

    if has_oci:
        try:
            for inv in tg_fetch_oci_combined_invoices()[:6]:
                status_raw = inv.get("status", "")
                status = "🟡 ACCUM" if status_raw == "ACCUMULATING" else "✅ PAID" if status_raw in ("PAID", "CLOSED") or inv.get("amount_due", 0) == 0 else "🔴 OVERDUE"
                currency = inv.get("currency", "USD")
                lines.append(f"☁️ OCI Combined {inv.get('time_start', '')}: {tg_currency(inv.get('amount', 0), currency)} {status}")
                if inv.get("amount_due", 0) > 0 and status_raw not in ("ACCUMULATING", "PAID", "CLOSED"):
                    unpaid += 1
        except Exception as exc:
            lines.append(f"☁️ OCI Combined error: {exc}")

    if unpaid:
        lines.append(f"\n⚠️ <b>{unpaid} unpaid invoice(s) require attention!</b>")
    return "\n".join(lines)


@app.route(f"/tg/webhook/{TELEGRAM_BOT_TOKEN}", methods=["POST"])
def tg_webhook():
    import threading
    data = request.get_json(silent=True) or {}
    msg = data.get("message") or data.get("edited_message") or {}
    chat_id = (msg.get("chat") or {}).get("id")
    text_value = (msg.get("text") or "").strip()

    allowed_chat_ids = {value for value in (TELEGRAM_GROUP_ID, SECONDARY_TELEGRAM_GROUP_ID) if value}
    if chat_id not in allowed_chat_ids:
        return jsonify({"ok": True})

    cmd = text_value.split()[0].split("@")[0].lower() if text_value.startswith("/") else ""

    def handle():
        providers = telegram_provider_rows(chat_id)
        allowed_slugs = {provider["slug"] for provider in providers}

        if cmd in ("/help", "/start"):
            tg_send(chat_id, tg_help_text(chat_id))
            return
        if cmd == "/today":
            lines = ["📅 <b>Latest Daily Spend</b>", "━━━━━━━━━━━━━━━━━━"]
            for provider in providers:
                try:
                    daily = fetch_provider_metric(provider, "daily", days=2)
                    latest = daily[-1]["cost"] if daily else 0
                    lines.append(f"{provider['icon']} {provider['name']}: <b>{tg_currency(latest, provider['currency'])}</b>")
                except Exception as exc:
                    lines.append(f"{provider['icon']} {provider['name']}: error ({exc})")
            tg_send(chat_id, "\n".join(lines))
            return
        if cmd == "/month":
            lines = ["📆 <b>Month-to-Date Spend</b>", "━━━━━━━━━━━━━━━━━━"]
            for provider in providers:
                try:
                    enhanced = fetch_provider_metric(provider, "enhanced_kpis")
                    currency = enhanced.get("currency") or provider["currency"]
                    lines.append(
                        f"{provider['icon']} {provider['name']}: <b>{tg_currency(enhanced.get('current_month', 0), currency)}</b> → forecast {tg_currency(enhanced.get('forecast', 0), currency)}"
                    )
                except Exception as exc:
                    lines.append(f"{provider['icon']} {provider['name']}: error ({exc})")
            tg_send(chat_id, "\n".join(lines))
            return
        if cmd == "/invoices":
            tg_send(chat_id, tg_report_invoices(chat_id))
            return

        slug = cmd.lstrip("/")
        legacy = {"aws": "primaryaws", "secondary": SECONDARY_PROVIDER_SLUG}
        slug = legacy.get(slug, slug)
        if slug not in allowed_slugs:
            return
        provider = provider_store.get_by_slug(slug, enabled_only=True)
        if provider and provider.get("telegram_enabled"):
            tg_send(chat_id, tg_report_provider(provider))

    if cmd:
        threading.Thread(target=handle, daemon=True).start()
    return jsonify({"ok": True})


# ══════════════════════════════════════════════════════════
# PORTAL PROVIDER
# ══════════════════════════════════════════════════════════
PORTAL_CACHE_FILE = os.environ.get("PORTAL_CACHE_FILE", str(APP_ROOT / "portal_cache.json"))
PORTAL_PUSH_KEY   = os.environ.get("PORTAL_PUSH_KEY", "").strip()

def portal_load():
    """Load External Portal data from local cache file."""
    try:
        data = json.loads(pathlib.Path(PORTAL_CACHE_FILE).read_text())
        return data
    except Exception as e:
        print(f"[portal] cache load error: {e}")
        return {}

def portal_kpis(period="monthly"):
    """Return KPI summary from cached External Portal data."""
    data = portal_load()
    bills = data.get("bills", [])
    profile = data.get("profile", {})
    if not bills:
        return {"total_spend": 0, "active_services": 0,
                "active_resources": 0, "regions": 1, "currency": "USD"}
    # Current open bill
    open_bill = next((b for b in bills if b.get("status") == "OPEN"), None)
    if period == "monthly" and open_bill:
        total = float(open_bill.get("netAmount", 0))
        resources = len(open_bill.get("items", []))
        svc_types = {i.get("resourceType","Other") for i in open_bill.get("items",[])}
    else:
        total = sum(float(b.get("netAmount", 0)) for b in bills[:1])
        resources = 0
        svc_types = set()
    return {"total_spend": round(total, 2), "active_services": len(svc_types),
            "active_resources": resources, "regions": 1, "currency": "USD"}

def portal_services(period="monthly"):
    """Return service breakdown."""
    data = portal_load()
    bills = data.get("bills", [])
    open_bill = next((b for b in bills if b.get("status") == "OPEN"), None)
    bill = open_bill or (bills[0] if bills else None)
    if not bill:
        return []
    by_type = {}
    for item in bill.get("items", []):
        t = item.get("resourceType", "Other")
        by_type[t] = by_type.get(t, 0) + float(item.get("netAmount", 0))
    return [{"name": k, "value": round(v, 2)}
            for k, v in sorted(by_type.items(), key=lambda x: -x[1])]

def portal_trend(months=7):
    """Return monthly trend data."""
    data = portal_load()
    bills = data.get("bills", [])
    result = []
    for bill in bills[:months]:
        period = bill.get("billingPeriodStart", "")[:7]  # YYYY-MM
        try:
            from datetime import datetime
            dt = datetime.strptime(period, "%Y-%m")
            label = dt.strftime("%b %Y")
        except:
            label = period
        by_type = {}
        for item in bill.get("items", []):
            t = item.get("resourceType", "Other")
            by_type[t] = by_type.get(t, 0) + float(item.get("netAmount", 0))
        result.append({"month": label, **{k: round(v, 2) for k, v in by_type.items()}})
    return list(reversed(result))

def portal_daily(days=28):
    """Approximate daily from open bill total / days elapsed."""
    data = portal_load()
    bills = data.get("bills", [])
    open_bill = next((b for b in bills if b.get("status") == "OPEN"), None)
    if not open_bill:
        return []
    from datetime import datetime, timedelta, timezone
    today = datetime.now(timezone.utc).date()
    total = float(open_bill.get("netAmount", 0))
    days_elapsed = today.day
    daily_avg = total / days_elapsed if days_elapsed else 0
    result = []
    for i in range(days - 1, -1, -1):
        d = today - timedelta(days=i)
        result.append({"day": d.isoformat(), "cost": round(daily_avg, 2)})
    return result

def portal_resources(limit=10):
    """Return top spending resources."""
    data = portal_load()
    bills = data.get("bills", [])
    open_bill = next((b for b in bills if b.get("status") == "OPEN"), None)
    bill = open_bill or (bills[0] if bills else None)
    if not bill:
        return []
    items = sorted(bill.get("items", []),
                   key=lambda x: float(x.get("netAmount", 0)), reverse=True)
    result = []
    for item in items[:limit]:
        cost = float(item.get("netAmount", 0))
        if cost <= 0:
            continue
        result.append({
            "name": item.get("resourceName") or item.get("resourceId", "Unknown"),
            "type": item.get("resourceType", "Other"),
            "region": "Region A",
            "cost": round(cost, 2),
        })
    return result

def portal_invoices():
    """Return bill history as invoices."""
    data = portal_load()
    bills = data.get("bills", [])
    result = []
    for bill in bills[:6]:  # limit to last 6 bills
        status_raw = bill.get("status", "OPEN")
        if status_raw == "PAID":
            status = "PAID"
        elif status_raw == "OPEN":
            status = "ACCUMULATING"
        else:
            status = status_raw
        start = bill.get("billingPeriodStart", "")[:7]
        try:
            from datetime import datetime
            dt = datetime.strptime(start, "%Y-%m")
            period_str = dt.strftime("%B %Y")
            due_str = (dt.replace(day=28) + __import__('datetime').timedelta(days=4)).replace(day=1).__add__(__import__('datetime').timedelta(days=-1)).strftime("%b %d, %Y")
        except:
            period_str = start
            due_str = "—"
        net = float(bill.get("netAmount", 0))
        _ac = bill.get("appliedAccountCredits", 0)
        credits = sum(float(x.get("amount",0)) for x in _ac) if isinstance(_ac, list) else float(_ac or 0)
        result.append({
            "id": str(bill.get("id", "")),
            "time_start": period_str,
            "issue_date": start,
            "time_invoice": due_str,
            "amount": round(net, 2),
            "amount_due": round(max(0, net - credits), 2) if status != "PAID" else 0,
            "currency": bill.get("currency", "USD"),
            "status": status,
            "by_service": {},
        })
    return result

def portal_enhanced_kpis():
    """Return enhanced KPIs for External Portal using cost_info API data."""
    from calendar import monthrange
    from datetime import datetime, timezone, timedelta
    data       = portal_load()
    bills      = data.get("bills", [])
    cost_info  = data.get("cost_info", {})
    profile    = data.get("profile", {})
    open_bill  = next((b for b in bills if b.get("status") == "OPEN"), None)
    paid_bills = [b for b in bills if b.get("status") == "PAID"]
    today      = datetime.now(timezone.utc)
    days_passed   = today.day
    days_in_month = monthrange(today.year, today.month)[1]

    # Use cost_info API values if available (more accurate)
    # API returns data wrapped in "data" key
    ci   = cost_info.get("data", cost_info)
    prof = profile.get("data", profile)

    def _safe_float(val, fallback=0.0):
        try: return float(val or fallback)
        except: return fallback

    current    = _safe_float(
        ci.get("currentMonthCosts") or ci.get("currentMonthUsage") or
        prof.get("currentMonthUsage"),
        float(open_bill.get("netAmount",0)) if open_bill else 0)
    last_month = _safe_float(
        ci.get("lastMonthCosts") or ci.get("lastMonthCost"),
        float(paid_bills[0].get("netAmount",0)) if paid_bills else 0)
    forecast   = _safe_float(
        ci.get("forecastedMonthEndCosts") or ci.get("forecastedMonthEnd"),
        round((current/days_passed)*days_in_month,2) if days_passed else 0)

    avg_daily  = round(current / days_passed, 2) if days_passed else 0
    mom_pct    = round(((current - last_month) / last_month * 100), 1) if last_month else 0
    currency   = "USD"

    # Account credit info from profile (nested under "data")
    account_credit     = _safe_float(prof.get("accountCredit", 0))
    promotional_credit = _safe_float(prof.get("promotionalCredit") or prof.get("promotionalCredits") or ci.get("promotionalCredits", 0))
    balance            = _safe_float(prof.get("balance", 0) or ci.get("balance", 0))
    low_credit_alert   = account_credit < 1000

    trend6 = []
    for bill in reversed(bills[:6]):
        s = bill.get("billingPeriodStart","")[:7]
        try:
            dt = datetime.strptime(s, "%Y-%m")
            label = dt.strftime("%b %Y")
        except:
            label = s
        trend6.append({"month": label, "cost": round(float(bill.get("netAmount",0)), 2)})

    return {"current_month": round(current, 2), "last_month": round(last_month, 2),
            "forecast": round(forecast, 2), "avg_daily": avg_daily, "currency": currency,
            "mom_pct": mom_pct, "days_passed": days_passed, "trend6": trend6,
            "account_credit": round(account_credit, 2),
            "promotional_credit": round(promotional_credit, 2),
            "balance": round(balance, 2),
            "low_credit_alert": low_credit_alert}

# ── External Portal API Routes ────────────────────────────────────────────────────────
@app.route("/api/portal/push", methods=["POST"])
def portal_push():
    """Receive billing data from the local collector."""
    key = request.headers.get("X-Push-Key") or request.args.get("key")
    if not PORTAL_PUSH_KEY or not hmac.compare_digest(str(key or ""), PORTAL_PUSH_KEY):
        return jsonify({"ok": False, "error": "Unauthorized"}), 401
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"ok": False, "error": "No JSON body"}), 400
    try:
        pathlib.Path(PORTAL_CACHE_FILE).write_text(json.dumps(data))
        # Also invalidate any in-memory cache keys
        cache_clear("portal")
        return jsonify({"ok": True, "bills": len(data.get("bills", [])),
                        "fetched_at": data.get("fetched_at", "")})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

# ── Hetzner collector receiver ────────────────────────────────────────────────
HETZNER_PUSH_KEY = os.environ.get("HETZNER_PUSH_KEY", "").strip()

@app.route("/api/hetzner/push", methods=["POST"])
def hetzner_push():
    """Receive sanitized invoice data from the fixed-IP Hetzner collector."""
    supplied = request.headers.get("X-Push-Key", "")
    if not HETZNER_PUSH_KEY or not hmac.compare_digest(supplied, HETZNER_PUSH_KEY):
        return jsonify({"ok": False, "error": "Unauthorized"}), 401
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"ok": False, "error": "JSON object required"}), 400
    try:
        summary = hetzner_save_payload(data)
        cache_clear("hetzner")
        return jsonify({"ok": True, **summary})
    except ValueError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500

@app.route("/api/portal/kpis")
@api_auth
def api_portal_kpis():
    period = request.args.get("period","monthly")
    ck = f"portal-kpis-{period}"; c = cache_get(ck)
    if c is not None: return jsonify({"ok": True, "data": c})
    result = portal_kpis(period)
    cache_set(ck, result)
    return jsonify({"ok": True, "data": result})

@app.route("/api/portal/services")
@api_auth
def api_portal_services():
    period = request.args.get("period","monthly")
    ck = f"portal-services-{period}"; c = cache_get(ck)
    if c is not None: return jsonify({"ok": True, "data": c})
    result = portal_services(period)
    cache_set(ck, result)
    return jsonify({"ok": True, "data": result})

@app.route("/api/portal/trend")
@api_auth
def api_portal_trend():
    months = int(request.args.get("months", 7))
    ck = f"portal-trend-{months}"; c = cache_get(ck)
    if c is not None: return jsonify({"ok": True, "data": c})
    result = portal_trend(months)
    cache_set(ck, result)
    return jsonify({"ok": True, "data": result})

@app.route("/api/portal/daily")
@api_auth
def api_portal_daily():
    days = int(request.args.get("days", 28))
    ck = f"portal-daily-{days}"; c = cache_get(ck)
    if c is not None: return jsonify({"ok": True, "data": c})
    result = portal_daily(days)
    cache_set(ck, result)
    return jsonify({"ok": True, "data": result})

@app.route("/api/portal/resources")
@api_auth
def api_portal_resources():
    limit = int(request.args.get("limit", 10))
    ck = f"portal-resources-{limit}"; c = cache_get(ck)
    if c is not None: return jsonify({"ok": True, "data": c})
    result = portal_resources(limit)
    cache_set(ck, result)
    return jsonify({"ok": True, "data": result})

@app.route("/api/portal/invoices")
@api_auth
def api_portal_invoices():
    ck = "portal-invoices"; c = cache_get(ck)
    if c is not None: return jsonify({"ok": True, "data": c})
    result = portal_invoices()
    cache_set(ck, result)
    return jsonify({"ok": True, "data": result})

@app.route("/api/portal/enhanced_kpis")
@api_auth
def api_portal_enhanced_kpis():
    ck = "portal-enhanced"; c = cache_get(ck)
    if c is not None: return jsonify({"ok": True, "data": c})
    result = portal_enhanced_kpis()
    cache_set(ck, result)
    return jsonify({"ok": True, "data": result})

@app.route("/api/health")
def health():
    return jsonify({"ok": True, "ts": datetime.now(timezone.utc).isoformat(), "providers": ["oci","aws"]})

@app.route("/api/oci/kpis")
@api_auth
def api_oci_kpis():
    try: return jsonify({"ok": True, "data": oci_fetch_kpis(request.args.get("period","monthly"))})
    except Exception as e: return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/api/oci/services")
@api_auth
def api_oci_services():
    try: return jsonify({"ok": True, "data": oci_fetch_services(request.args.get("period","monthly"))})
    except Exception as e: return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/api/oci/trend")
@api_auth
def api_oci_trend():
    try: return jsonify({"ok": True, "data": oci_fetch_trend(int(request.args.get("months",7)))})
    except Exception as e: return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/api/oci/daily")
@api_auth
def api_oci_daily():
    try: return jsonify({"ok": True, "data": oci_fetch_daily(int(request.args.get("days",28)))})
    except Exception as e: return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/api/oci/resources")
@api_auth
def api_oci_resources():
    try: return jsonify({"ok": True, "data": oci_fetch_resources(int(request.args.get("limit",10)))})
    except Exception as e: return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/api/oci/invoices")
@api_auth
def api_oci_invoices():
    try: return jsonify({"ok": True, "data": oci_fetch_invoices()})
    except Exception as e: return jsonify({"ok": False, "error": str(e)}), 500

# ── Multi-account AWS API Routes ─────────────────────────────────────────────
def _aws_api_error(exc):
    return jsonify({"ok": False, "error": str(exc)}), 500


@app.route("/api/aws/<account_key>/kpis")
@api_auth
def api_aws_account_kpis(account_key):
    try:
        return jsonify({"ok": True, "data": aws_fetch_kpis(request.args.get("period", "monthly"), account_key)})
    except Exception as exc:
        return _aws_api_error(exc)


@app.route("/api/aws/<account_key>/services")
@api_auth
def api_aws_account_services(account_key):
    try:
        return jsonify({"ok": True, "data": aws_fetch_services(request.args.get("period", "monthly"), account_key)})
    except Exception as exc:
        return _aws_api_error(exc)


@app.route("/api/aws/<account_key>/trend")
@api_auth
def api_aws_account_trend(account_key):
    try:
        return jsonify({"ok": True, "data": aws_fetch_trend(request.args.get("months", 7), account_key)})
    except Exception as exc:
        return _aws_api_error(exc)


@app.route("/api/aws/<account_key>/daily")
@api_auth
def api_aws_account_daily(account_key):
    try:
        return jsonify({"ok": True, "data": aws_fetch_daily(request.args.get("days", 28), account_key)})
    except Exception as exc:
        return _aws_api_error(exc)


@app.route("/api/aws/<account_key>/resources")
@api_auth
def api_aws_account_resources(account_key):
    try:
        return jsonify({"ok": True, "data": aws_fetch_resources(request.args.get("limit", 10), account_key)})
    except Exception as exc:
        return _aws_api_error(exc)


@app.route("/api/aws/<account_key>/invoices")
@api_auth
def api_aws_account_invoices(account_key):
    try:
        return jsonify({"ok": True, "data": aws_fetch_invoices(account_key)})
    except Exception as exc:
        return _aws_api_error(exc)


# Backward-compatible routes: old /api/aws/... URLs use Primary AWS.
@app.route("/api/aws/kpis")
@api_auth
def api_aws_kpis():
    try: return jsonify({"ok": True, "data": aws_fetch_kpis(request.args.get("period", "monthly"), "primaryaws")})
    except Exception as exc: return _aws_api_error(exc)


@app.route("/api/aws/services")
@api_auth
def api_aws_services():
    try: return jsonify({"ok": True, "data": aws_fetch_services(request.args.get("period", "monthly"), "primaryaws")})
    except Exception as exc: return _aws_api_error(exc)


@app.route("/api/aws/trend")
@api_auth
def api_aws_trend():
    try: return jsonify({"ok": True, "data": aws_fetch_trend(request.args.get("months", 7), "primaryaws")})
    except Exception as exc: return _aws_api_error(exc)


@app.route("/api/aws/daily")
@api_auth
def api_aws_daily():
    try: return jsonify({"ok": True, "data": aws_fetch_daily(request.args.get("days", 28), "primaryaws")})
    except Exception as exc: return _aws_api_error(exc)


@app.route("/api/aws/resources")
@api_auth
def api_aws_resources():
    try: return jsonify({"ok": True, "data": aws_fetch_resources(request.args.get("limit", 10), "primaryaws")})
    except Exception as exc: return _aws_api_error(exc)


@app.route("/api/aws/invoices")
@api_auth
def api_aws_invoices():
    try: return jsonify({"ok": True, "data": aws_fetch_invoices("primaryaws")})
    except Exception as exc: return _aws_api_error(exc)


@app.route("/api/<provider>/invoices/<invoice_id>/download")
@api_auth
def download_invoice(provider, invoice_id):
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib import colors
        from reportlab.lib.units import cm
        from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, HRFlowable
        from reportlab.lib.styles import ParagraphStyle
        from reportlab.lib.enums import TA_RIGHT, TA_CENTER
        from io import BytesIO

        oci_tenant_names = {
            "primaryoci": "Primary OCI", "clientalpha": "Client Alpha OCI",
            "clientbeta": "Client Beta OCI", "clientgamma": "Client Gamma OCI",
            "clientdelta": "Client Delta OCI",
        }
        if provider in AWS_ACCOUNTS:
            invoices = aws_fetch_invoices(provider)
            accent = colors.HexColor("#FF9900")
            provider_name = AWS_ACCOUNTS[provider]["name"]
        elif provider == "portal":
            invoices = portal_invoices()
            accent = colors.HexColor("#2563EB")
            provider_name = "External Portal Cloud"
        elif provider in oci_tenant_names:
            invoices = oci_tenant_fetch_invoices(provider)
            accent = colors.HexColor("#C74634")
            provider_name = oci_tenant_names[provider]
        elif provider == "oci":
            invoices = oci_fetch_invoices()
            accent = colors.HexColor("#C74634")
            provider_name = "Oracle Cloud Infrastructure"
        else:
            return jsonify({"ok": False, "error": "Unknown provider"}), 404

        inv = next((x for x in invoices if x["id"] == invoice_id), None)
        if not inv: return jsonify({"ok": False, "error": "Invoice not found"}), 404
        muted = colors.HexColor("#888")
        buf = BytesIO()
        doc = SimpleDocTemplate(buf, pagesize=A4, rightMargin=2*cm, leftMargin=2*cm,
                                topMargin=2*cm, bottomMargin=2*cm)
        story = []
        story.append(Paragraph(provider_name, ParagraphStyle("t", fontSize=22, textColor=accent, spaceAfter=4, fontName="Helvetica-Bold")))
        story.append(Paragraph("Billing Invoice", ParagraphStyle("s", fontSize=10, textColor=muted, spaceAfter=2)))
        story.append(HRFlowable(width="100%", thickness=2, color=accent, spaceAfter=12))
        meta = [
            ["Invoice ID:", inv["id"], "Status:", inv["status"]],
            ["Billing Period:", inv.get("period", inv.get("time_start","—")), "Due Date:", inv["time_invoice"]],
            ["Date Range:", inv.get("date_from","") + (" to " + inv.get("date_to","") if inv.get("date_to") else ""), "Currency:", inv["currency"]],
        ]
        mt = Table(meta, colWidths=[3.5*cm, 7*cm, 3*cm, 4*cm])
        mt.setStyle(TableStyle([
            ("FONTNAME", (0,0), (-1,-1), "Helvetica"),
            ("FONTNAME", (0,0), (0,-1), "Helvetica-Bold"),
            ("FONTNAME", (2,0), (2,-1), "Helvetica-Bold"),
            ("FONTSIZE", (0,0), (-1,-1), 9),
            ("ROWBACKGROUNDS", (0,0), (-1,-1), [colors.HexColor("#F9F9F9"), colors.white]),
            ("PADDING", (0,0), (-1,-1), 5),
            ("GRID", (0,0), (-1,-1), 0.25, colors.HexColor("#E0E0E0")),
        ]))
        story.append(mt); story.append(Spacer(1, 16))
        story.append(Paragraph("Cost by Service", ParagraphStyle("h2", fontSize=13, textColor=colors.HexColor("#1A1A2E"), spaceBefore=8, spaceAfter=6, fontName="Helvetica-Bold")))
        svc_data = [["Service", f"Amount ({inv['currency']})"]]
        for svc, cost in inv.get("by_service", {}).items():
            svc_data.append([svc, f"{inv.get('currency','USD')} {cost:,.2f}"])
        # Add tax/adjustment row — difference between Usage API subtotal and OSP Gateway total
        subtotal = sum(inv.get("by_service", {}).values())
        vat = round(inv["amount"] - subtotal, 2)
        svc_data.append(["", ""])
        if vat > 0:
            svc_data.append([f"Tax adjustment", f"{inv.get('currency','USD')} {vat:,.2f}"])
        svc_data += [["TOTAL", f"{inv.get('currency','USD')} {inv['amount']:,.2f}"]]
        st = Table(svc_data, colWidths=[13*cm, 4.5*cm])
        st.setStyle(TableStyle([
            ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
            ("FONTNAME", (0,-1), (-1,-1), "Helvetica-Bold"),
            ("FONTNAME", (0,-2), (-1,-2), "Helvetica-Bold"),
            ("FONTSIZE", (0,0), (-1,-1), 9),
            ("BACKGROUND", (0,0), (-1,0), accent),
            ("TEXTCOLOR", (0,0), (-1,0), colors.white),
            ("BACKGROUND", (0,-1), (-1,-1), colors.HexColor("#F5F5F5")),
            ("TEXTCOLOR", (0,-1), (-1,-1), accent),
            ("TEXTCOLOR", (0,-2), (-1,-2), colors.HexColor("#555555")),
            ("ALIGN", (1,0), (1,-1), "RIGHT"),
            ("ROWBACKGROUNDS", (0,1), (-1,-3), [colors.white, colors.HexColor("#F9F9F9")]),
            ("GRID", (0,0), (-1,-1), 0.25, colors.HexColor("#E0E0E0")),
            ("PADDING", (0,0), (-1,-1), 6),
            ("LINEABOVE", (0,-2), (-1,-2), 0.5, colors.HexColor("#CCCCCC")),
            ("LINEABOVE", (0,-1), (-1,-1), 1.5, accent),
        ]))
        story.append(st); story.append(Spacer(1, 20))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#E0E0E0")))
        story.append(Spacer(1, 8))
        amt_due = inv["amount_due"]
        due_text = f"Amount Due: ${amt_due:,.2f} {inv['currency']}" if amt_due > 0 else "Amount Due: PAID"
        due_color = accent if amt_due > 0 else colors.HexColor("#34D399")
        story.append(Paragraph(due_text, ParagraphStyle("due", fontSize=14, textColor=due_color, fontName="Helvetica-Bold", alignment=TA_RIGHT)))
        story.append(Spacer(1, 8))
        story.append(Paragraph(f"Generated from {provider_name} billing API. For official invoices visit your cloud console.",
                               ParagraphStyle("footer", fontSize=7, textColor=muted, alignment=TA_CENTER)))
        doc.build(story); buf.seek(0)
        from flask import Response
        return Response(buf.read(), mimetype="application/pdf",
                       headers={"Content-Disposition": f"attachment; filename={provider}-invoice-{invoice_id}.pdf"})
    except ImportError:
        return jsonify({"ok": False, "error": "reportlab not installed"}), 500
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

# ── Enhanced KPIs: last month, forecast, avg daily ────────────────────────────
def oci_fetch_enhanced_kpis():
    ck = "oci-enhanced-kpis"; c = cache_get(ck)
    if c is not None: return c
    from calendar import monthrange
    today = midnight(datetime.now(timezone.utc))

    # Current month
    s_cur = today.replace(day=1)
    e_cur = today + timedelta(days=1)
    items_cur = oci_summarize(s_cur, e_cur)
    current = round(sum(float(i.computed_amount or 0) for i in items_cur), 2)
    currency = items_cur[0].currency if items_cur else "USD"

    # Last month
    last_end = today.replace(day=1)
    last_start = (last_end - timedelta(days=1)).replace(day=1)
    items_last = oci_summarize(last_start, last_end)
    last_month = round(sum(float(i.computed_amount or 0) for i in items_last), 2)

    # Forecast: project current spend to end of month
    days_passed = today.day
    days_in_month = monthrange(today.year, today.month)[1]
    forecast = round((current / days_passed) * days_in_month, 2) if days_passed > 0 else 0

    # Average daily (last 30 days)
    s_daily = today - timedelta(days=30)
    items_daily = oci_summarize(s_daily, today + timedelta(days=1), granularity="DAILY")
    daily_totals = {}
    for i in items_daily:
        if i.time_usage_started:
            dk = i.time_usage_started.strftime("%Y-%m-%d")
            daily_totals[dk] = daily_totals.get(dk, 0) + float(i.computed_amount or 0)
    avg_daily = round(sum(daily_totals.values()) / len(daily_totals), 2) if daily_totals else 0

    # 6-month trend (single total per month)
    s_trend = today.replace(day=1)
    for _ in range(5): s_trend = (s_trend - timedelta(days=1)).replace(day=1)
    items_trend = oci_summarize(s_trend, today + timedelta(days=1), granularity="MONTHLY")
    trend_map = {}
    for i in items_trend:
        if i.time_usage_started:
            mk = i.time_usage_started.strftime("%b %Y")
            trend_map[mk] = trend_map.get(mk, 0) + float(i.computed_amount or 0)
    trend6 = [{"month": k, "cost": round(v, 2)} for k, v in trend_map.items()]

    # MoM change
    mom_pct = round(((current - last_month) / last_month * 100), 1) if last_month > 0 else 0

    result = {
        "current_month": current, "last_month": last_month,
        "forecast": forecast, "avg_daily": avg_daily,
        "currency": currency, "mom_pct": mom_pct,
        "days_passed": days_passed, "trend6": trend6,
    }
    cache_set(ck, result); return result


def aws_fetch_enhanced_kpis(account_key="primaryaws"):
    ck = f"aws-{account_key}-enhanced-kpis"; c = cache_get(ck)
    if c is not None: return c
    from calendar import monthrange
    today = datetime.now(timezone.utc).date()
    ce = aws_client("ce", account_key)

    current_start = today.replace(day=1).isoformat()
    current_end = (today + timedelta(days=1)).isoformat()
    current_response = ce.get_cost_and_usage(
        TimePeriod={"Start": current_start, "End": current_end},
        Granularity="MONTHLY", Metrics=["UnblendedCost"],
        **aws_cost_query_options(account_key),
    )
    current = sum(
        max(0, float(item["Total"]["UnblendedCost"]["Amount"]))
        for item in current_response.get("ResultsByTime", [])
    )

    last_end = today.replace(day=1)
    last_start = (last_end - timedelta(days=1)).replace(day=1)
    last_response = ce.get_cost_and_usage(
        TimePeriod={"Start": last_start.isoformat(), "End": last_end.isoformat()},
        Granularity="MONTHLY", Metrics=["UnblendedCost"],
        **aws_cost_query_options(account_key),
    )
    last_month = sum(
        max(0, float(item["Total"]["UnblendedCost"]["Amount"]))
        for item in last_response.get("ResultsByTime", [])
    )

    days_passed = today.day
    days_in_month = monthrange(today.year, today.month)[1]
    forecast = round((current / days_passed) * days_in_month, 2) if days_passed else 0

    daily_response = ce.get_cost_and_usage(
        TimePeriod={
            "Start": (today - timedelta(days=30)).isoformat(),
            "End": today.isoformat(),
        },
        Granularity="DAILY", Metrics=["BlendedCost"],
        **aws_cost_query_options(account_key),
    )
    daily_values = [
        float(item["Total"]["BlendedCost"]["Amount"])
        for item in daily_response.get("ResultsByTime", [])
    ]
    avg_daily = round(sum(daily_values) / len(daily_values), 2) if daily_values else 0

    trend_start = today.replace(day=1)
    for _ in range(5):
        trend_start = (trend_start - timedelta(days=1)).replace(day=1)
    trend_response = ce.get_cost_and_usage(
        TimePeriod={"Start": trend_start.isoformat(), "End": today.isoformat()},
        Granularity="MONTHLY", Metrics=["BlendedCost"],
        **aws_cost_query_options(account_key),
    )
    trend6 = [
        {
            "month": datetime.strptime(item["TimePeriod"]["Start"][:7], "%Y-%m").strftime("%b %Y"),
            "cost": round(float(item["Total"]["BlendedCost"]["Amount"]), 2),
        }
        for item in trend_response.get("ResultsByTime", [])
    ]

    mom_pct = round(((current - last_month) / last_month * 100), 1) if last_month else 0
    result = {
        "current_month": round(current, 2), "last_month": round(last_month, 2),
        "forecast": forecast, "avg_daily": avg_daily,
        "currency": "USD", "mom_pct": mom_pct,
        "days_passed": days_passed, "trend6": trend6,
    }
    cache_set(ck, result); return result


@app.route("/api/oci/enhanced_kpis")
@api_auth
def api_oci_enhanced_kpis():
    try: return jsonify({"ok": True, "data": oci_fetch_enhanced_kpis()})
    except Exception as e: return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/api/aws/<account_key>/enhanced_kpis")
@api_auth
def api_aws_account_enhanced_kpis(account_key):
    try: return jsonify({"ok": True, "data": aws_fetch_enhanced_kpis(account_key)})
    except Exception as e: return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/aws/enhanced_kpis")
@api_auth
def api_aws_enhanced_kpis():
    try: return jsonify({"ok": True, "data": aws_fetch_enhanced_kpis("primaryaws")})
    except Exception as e: return jsonify({"ok": False, "error": str(e)}), 500



# ══════════════════════════════════════════════════════════
# DATABASE-DRIVEN PROVIDERS + ADMIN PANEL
# ══════════════════════════════════════════════════════════
def refresh_provider_runtime():
    """Refresh runtime AWS configuration from the encrypted provider registry."""
    for provider in provider_store.list_providers():
        if provider["provider_type"] != "aws":
            continue
        credentials = provider_store.get_credentials(provider["id"])
        AWS_ACCOUNTS[provider["slug"]] = {
            "name": provider["name"],
            "access_key_id": credentials["access_key_id"],
            "secret_access_key": credentials["secret_access_key"],
            "region": provider["region"] or "us-east-1",
        }
    return True


def _resolve_provider(provider_or_slug, enabled_only=True):
    if isinstance(provider_or_slug, dict):
        provider = provider_or_slug
    else:
        provider = provider_store.get_by_slug(str(provider_or_slug), enabled_only=enabled_only)
    if not provider:
        raise KeyError("Dashboard provider not found or disabled")
    return provider


def fetch_provider_metric(provider_or_slug, metric, **params):
    """Fetch one standard dashboard metric using the provider's adapter."""
    provider = _resolve_provider(provider_or_slug, enabled_only=False)
    if DEMO_MODE:
        from demo_provider import fetch_metric as demo_fetch_metric
        return demo_fetch_metric(provider, metric, **params)
    provider_type = provider["provider_type"]
    if provider_type == "aws":
        refresh_provider_runtime()
        account_key = provider["slug"]
        mapping = {
            "kpis": lambda: aws_fetch_kpis(params.get("period", "monthly"), account_key),
            "services": lambda: aws_fetch_services(params.get("period", "monthly"), account_key),
            "trend": lambda: aws_fetch_trend(params.get("months", 7), account_key),
            "daily": lambda: aws_fetch_daily(params.get("days", 28), account_key),
            "resources": lambda: aws_fetch_resources(params.get("limit", 10), account_key),
            "invoices": lambda: aws_fetch_invoices(account_key),
            "enhanced_kpis": lambda: aws_fetch_enhanced_kpis(account_key),
        }
    elif provider_type == "oci_tenant":
        tenant_name = provider.get("config", {}).get("tenant_name") or provider["slug"]
        mapping = {
            "kpis": lambda: oci_tenant_fetch_kpis(tenant_name, params.get("period", "monthly")),
            "services": lambda: oci_tenant_fetch_services(tenant_name, params.get("period", "monthly")),
            "trend": lambda: oci_tenant_fetch_trend(tenant_name, params.get("months", 7)),
            "daily": lambda: oci_tenant_fetch_daily(tenant_name, params.get("days", 28)),
            "resources": lambda: oci_tenant_fetch_resources(tenant_name, params.get("limit", 10)),
            "invoices": lambda: oci_tenant_fetch_invoices(tenant_name),
            "enhanced_kpis": lambda: oci_tenant_fetch_enhanced_kpis(tenant_name),
        }
    elif provider_type == "portal":
        mapping = {
            "kpis": lambda: portal_kpis(params.get("period", "monthly")),
            "services": lambda: portal_services(params.get("period", "monthly")),
            "trend": lambda: portal_trend(params.get("months", 7)),
            "daily": lambda: portal_daily(params.get("days", 28)),
            "resources": lambda: portal_resources(params.get("limit", 10)),
            "invoices": portal_invoices,
            "enhanced_kpis": portal_enhanced_kpis,
        }
    elif provider_type == "hetzner":
        return hetzner_fetch_metric(provider, metric, **params)
    else:
        raise ValueError("Unsupported provider type")
    if metric not in mapping:
        raise ValueError("Unsupported dashboard metric")
    result = mapping[metric]()
    if provider_type == "portal" and metric == "enhanced_kpis":
        threshold = float(provider.get("config", {}).get("low_credit_threshold", 1000))
        result = dict(result)
        result["low_credit_alert"] = float(result.get("account_credit", 0)) < threshold
    return result


def _cache_clear_matching(predicate):
    """Atomically remove shared cache entries matching a predicate."""
    global _cache, _cache_file_mtime
    import fcntl
    with open(_CACHE_LOCK_FILE, "a+") as lock_file:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        entries = _read_cache_unlocked()
        keys = [key for key in list(entries) if predicate(key)]
        for key in keys:
            entries.pop(key, None)
        _write_cache_unlocked(entries)
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
    _cache = entries
    _cache_file_mtime = _pathlib.Path(_CACHE_FILE).stat().st_mtime
    return len(keys)


def clear_provider_cache(provider):
    provider = _resolve_provider(provider, enabled_only=False)
    if provider["provider_type"] == "aws":
        return _cache_clear_matching(lambda key: key.startswith(f"aws-{provider['slug']}-"))
    if provider["provider_type"] == "oci_tenant":
        tenant_name = provider.get("config", {}).get("tenant_name") or provider["slug"]
        return _cache_clear_matching(
            lambda key: key.startswith("oci-tenant-") and f"-{tenant_name}-" in f"-{key}-"
        )
    if provider["provider_type"] == "hetzner":
        return _cache_clear_matching(lambda key: key.startswith("hetzner"))
    return _cache_clear_matching(lambda key: key.startswith("portal"))


def test_provider_connection(provider):
    provider = _resolve_provider(provider, enabled_only=False)
    if DEMO_MODE:
        from demo_provider import test_connection as demo_test_connection
        return demo_test_connection(provider)
    if provider["provider_type"] == "aws":
        refresh_provider_runtime()
        identity = aws_client("sts", provider["slug"]).get_caller_identity()
        # Also verify Cost Explorer access with one completed day.
        today = datetime.now(timezone.utc).date()
        aws_client("ce", provider["slug"]).get_cost_and_usage(
            TimePeriod={"Start": (today - timedelta(days=1)).isoformat(), "End": today.isoformat()},
            Granularity="DAILY",
            Metrics=["BlendedCost"],
        )
        return f"AWS account {identity.get('Account')}"
    if provider["provider_type"] == "oci_tenant":
        tenant_name = provider.get("config", {}).get("tenant_name") or provider["slug"]
        start, end = oci_date_range("daily")
        items = oci_tenant_summarize(tenant_name, start, end)
        return f"OCI tenantName {tenant_name}; {len(items)} usage rows"
    if provider["provider_type"] == "hetzner":
        return hetzner_test_connection(provider)
    data = portal_load()
    if not data:
        raise RuntimeError("External Portal cache is empty or unavailable")
    return f"External Portal cache loaded; fetched_at={data.get('fetched_at', 'unknown')}"


@app.route("/api/providers")
@api_auth
def api_dynamic_providers():
    rows = [provider_store.public_provider(item) for item in provider_store.list_providers(enabled_only=True)]
    return jsonify({"ok": True, "data": rows})


@app.route("/api/provider/<slug>/<metric>")
@api_auth
def api_dynamic_provider_metric(slug, metric):
    try:
        provider = provider_store.get_by_slug(slug, enabled_only=True)
        if not provider:
            return jsonify({"ok": False, "error": "Provider not found or disabled"}), 404
        params = {
            "period": request.args.get("period", "monthly"),
            "months": max(1, min(int(request.args.get("months", 7)), 24)),
            "days": max(1, min(int(request.args.get("days", 28)), 366)),
            "limit": max(1, min(int(request.args.get("limit", 10)), 50)),
        }
        result = fetch_provider_metric(provider, metric, **params)
        return jsonify({"ok": True, "data": result})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


def _provider_invoice_pdf(provider, invoice):
    from io import BytesIO
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER, TA_RIGHT
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.platypus import HRFlowable, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    accent = colors.HexColor(provider.get("accent") or "#3B82F6")
    currency = invoice.get("currency") or provider.get("currency", "USD")
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=2*cm, leftMargin=2*cm, topMargin=2*cm, bottomMargin=2*cm)
    story = [
        Paragraph(provider["name"], ParagraphStyle("title", fontSize=22, textColor=accent, fontName="Helvetica-Bold", spaceAfter=4)),
        Paragraph("Billing Invoice", ParagraphStyle("subtitle", fontSize=10, textColor=colors.grey, spaceAfter=4)),
        HRFlowable(width="100%", thickness=2, color=accent, spaceAfter=12),
    ]
    meta = [
        ["Invoice ID", invoice.get("id", "—"), "Status", invoice.get("status", "—")],
        ["Billing Period", invoice.get("time_start", invoice.get("period", "—")), "Due Date", invoice.get("time_invoice", "—")],
        ["Currency", currency, "Amount", f"{currency} {float(invoice.get('amount', 0)):,.2f}"],
    ]
    table = Table(meta, colWidths=[3.5*cm, 7*cm, 3*cm, 4*cm])
    table.setStyle(TableStyle([("GRID", (0,0), (-1,-1), .25, colors.lightgrey), ("PADDING", (0,0), (-1,-1), 6), ("FONTNAME", (0,0), (0,-1), "Helvetica-Bold"), ("FONTNAME", (2,0), (2,-1), "Helvetica-Bold")]))
    story.extend([table, Spacer(1, 16)])
    service_rows = [["Service", f"Amount ({currency})"]]
    for name, amount in (invoice.get("by_service") or {}).items():
        service_rows.append([name, f"{currency} {float(amount):,.2f}"])
    if len(service_rows) == 1:
        service_rows.append(["Total usage", f"{currency} {float(invoice.get('amount', 0)):,.2f}"])
    service_rows.append(["TOTAL", f"{currency} {float(invoice.get('amount', 0)):,.2f}"])
    services = Table(service_rows, colWidths=[13*cm, 4.5*cm])
    services.setStyle(TableStyle([("BACKGROUND", (0,0), (-1,0), accent), ("TEXTCOLOR", (0,0), (-1,0), colors.white), ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"), ("FONTNAME", (0,-1), (-1,-1), "Helvetica-Bold"), ("ALIGN", (1,0), (1,-1), "RIGHT"), ("GRID", (0,0), (-1,-1), .25, colors.lightgrey), ("PADDING", (0,0), (-1,-1), 6)]))
    story.extend([services, Spacer(1, 20)])
    amount_due = float(invoice.get("amount_due", 0))
    due_text = f"Amount Due: {currency} {amount_due:,.2f}" if amount_due else "Amount Due: PAID"
    story.append(Paragraph(due_text, ParagraphStyle("due", fontSize=15, textColor=accent, fontName="Helvetica-Bold", alignment=TA_RIGHT)))
    story.append(Spacer(1, 10))
    story.append(Paragraph("Generated from the billing dashboard. Use the provider console for the official invoice.", ParagraphStyle("foot", fontSize=7, textColor=colors.grey, alignment=TA_CENTER)))
    doc.build(story)
    buffer.seek(0)
    return buffer


@app.route("/api/provider/<slug>/invoices/<invoice_id>/download")
@api_auth
def api_dynamic_invoice_download(slug, invoice_id):
    try:
        provider = provider_store.get_by_slug(slug, enabled_only=True)
        if not provider:
            return jsonify({"ok": False, "error": "Provider not found"}), 404
        invoices = fetch_provider_metric(provider, "invoices")
        invoice = next((item for item in invoices if str(item.get("id")) == str(invoice_id)), None)
        if not invoice:
            return jsonify({"ok": False, "error": "Invoice not found"}), 404
        from flask import send_file
        return send_file(
            _provider_invoice_pdf(provider, invoice),
            mimetype="application/pdf",
            as_attachment=True,
            download_name=f"{provider['slug']}-invoice-{invoice_id}.pdf",
        )
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


refresh_provider_runtime()

from admin_routes import admin_bp
app.extensions["refresh_provider_runtime"] = refresh_provider_runtime
app.extensions["test_provider_connection"] = test_provider_connection
app.extensions["clear_provider_cache"] = clear_provider_cache
app.register_blueprint(admin_bp)

application = app
if __name__ == "__main__":
    app.run(debug=False, host="127.0.0.1", port=5000)
