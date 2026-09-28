"""Admin panel routes for provider management."""
from __future__ import annotations

import secrets
from functools import wraps
from typing import Any

from flask import (
    Blueprint,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from provider_store import PROVIDER_TYPES, store

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")


def _csrf_token() -> str:
    token = session.get("admin_csrf")
    if not token:
        token = secrets.token_urlsafe(32)
        session["admin_csrf"] = token
    return token


def _validate_csrf() -> None:
    supplied = request.form.get("csrf_token", "")
    expected = session.get("admin_csrf", "")
    if not expected or not secrets.compare_digest(supplied, expected):
        raise ValueError("Invalid or expired form token. Refresh the page and try again.")


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("admin_logged_in"):
            return redirect(url_for("admin.login", next=request.path))
        return view(*args, **kwargs)

    return wrapped


def _checkbox(name: str, default: bool = False) -> bool:
    return request.form.get(name) == "1" if request.method == "POST" else default


def _provider_form_data(existing: dict[str, Any] | None = None) -> tuple[dict[str, Any], dict[str, str]]:
    existing = existing or {}
    provider_type = request.form.get("provider_type", existing.get("provider_type", "aws"))
    config = dict(existing.get("config", {}))
    if provider_type == "oci_tenant":
        config["tenant_name"] = request.form.get("tenant_name", config.get("tenant_name", "")).strip()
        if not config["tenant_name"]:
            raise ValueError("OCI tenantName is required")
    elif provider_type == "portal":
        threshold = request.form.get("low_credit_threshold", config.get("low_credit_threshold", 1000))
        try:
            config["low_credit_threshold"] = float(threshold)
        except (TypeError, ValueError) as exc:
            raise ValueError("Low-credit threshold must be a number") from exc
    data = {
        "slug": request.form.get("slug", existing.get("slug", "")).strip().lower(),
        "name": request.form.get("name", existing.get("name", "")).strip(),
        "provider_type": provider_type,
        "enabled": _checkbox("enabled", bool(existing.get("enabled", True))),
        "telegram_enabled": _checkbox("telegram_enabled", bool(existing.get("telegram_enabled", True))),
        "display_order": int(request.form.get("display_order", existing.get("display_order", 100))),
        "icon": request.form.get("icon", existing.get("icon", "☁")).strip() or "☁",
        "accent": request.form.get("accent", existing.get("accent", "#3B82F6")).strip() or "#3B82F6",
        "currency": request.form.get("currency", existing.get("currency", "USD")).strip().upper() or "USD",
        "region": request.form.get("region", existing.get("region", "")).strip(),
        "config": config,
    }
    credentials = {
        "access_key_id": request.form.get("access_key_id", "").strip(),
        "secret_access_key": request.form.get("secret_access_key", "").strip(),
    }
    if provider_type == "aws" and (not existing or existing.get("provider_type") != "aws"):
        if not credentials["access_key_id"] or not credentials["secret_access_key"]:
            raise ValueError("AWS access key ID and secret access key are required")
    return data, credentials


@admin_bp.app_context_processor
def inject_admin_helpers():
    return {"admin_csrf_token": _csrf_token, "provider_types": sorted(PROVIDER_TYPES)}


@admin_bp.route("/login", methods=["GET", "POST"])
def login():
    if session.get("admin_logged_in"):
        return redirect(url_for("admin.index"))
    if request.method == "POST":
        try:
            _validate_csrf()
            if store.check_admin_password(request.form.get("password", "")):
                session["admin_logged_in"] = True
                session.permanent = True
                store.audit("admin_login", remote_addr=request.remote_addr or "")
                return redirect(request.args.get("next") or url_for("admin.index"))
            flash("Invalid admin password", "error")
        except ValueError as exc:
            flash(str(exc), "error")
    return render_template("admin_login.html")


@admin_bp.route("/logout")
def logout():
    session.pop("admin_logged_in", None)
    session.pop("admin_csrf", None)
    return redirect(url_for("admin.login"))


@admin_bp.route("/")
@admin_required
def index():
    return render_template(
        "admin_providers.html",
        providers=store.list_providers(),
        audit_rows=store.recent_audit(15),
        using_fallback_password=not bool(store.get_setting("admin_password_hash")),
    )


@admin_bp.route("/providers/new", methods=["GET", "POST"])
@admin_required
def provider_new():
    if request.method == "POST":
        try:
            _validate_csrf()
            data, credentials = _provider_form_data()
            provider_id = store.create_provider(data, credentials)
            store.audit("provider_create", provider_id, data["name"], request.remote_addr or "")
            current_app.extensions["refresh_provider_runtime"]()
            flash(f"Dashboard {data['name']} created", "success")
            return redirect(url_for("admin.index"))
        except Exception as exc:
            flash(str(exc), "error")
    return render_template("admin_provider_form.html", provider=None)


@admin_bp.route("/providers/<int:provider_id>/edit", methods=["GET", "POST"])
@admin_required
def provider_edit(provider_id: int):
    provider = store.get_provider(provider_id)
    if not provider:
        flash("Provider not found", "error")
        return redirect(url_for("admin.index"))
    if request.method == "POST":
        try:
            _validate_csrf()
            data, credentials = _provider_form_data(provider)
            store.update_provider(provider_id, data, credentials)
            store.audit("provider_update", provider_id, data["name"], request.remote_addr or "")
            current_app.extensions["refresh_provider_runtime"]()
            flash(f"Dashboard {data['name']} updated", "success")
            return redirect(url_for("admin.index"))
        except Exception as exc:
            flash(str(exc), "error")
            provider = {**provider, **request.form.to_dict()}
    return render_template("admin_provider_form.html", provider=provider)


@admin_bp.post("/providers/<int:provider_id>/toggle")
@admin_required
def provider_toggle(provider_id: int):
    try:
        _validate_csrf()
        provider = store.get_provider(provider_id)
        if not provider:
            raise KeyError("Provider not found")
        store.set_enabled(provider_id, not provider["enabled"])
        store.audit("provider_enable" if not provider["enabled"] else "provider_disable", provider_id, provider["name"], request.remote_addr or "")
        current_app.extensions["refresh_provider_runtime"]()
        flash("Dashboard status updated", "success")
    except Exception as exc:
        flash(str(exc), "error")
    return redirect(url_for("admin.index"))


@admin_bp.post("/providers/<int:provider_id>/move/<direction>")
@admin_required
def provider_move(provider_id: int, direction: str):
    try:
        _validate_csrf()
        store.move(provider_id, -1 if direction == "up" else 1)
        store.audit("provider_reorder", provider_id, direction, request.remote_addr or "")
        flash("Dashboard order updated", "success")
    except Exception as exc:
        flash(str(exc), "error")
    return redirect(url_for("admin.index"))


@admin_bp.post("/providers/<int:provider_id>/delete")
@admin_required
def provider_delete(provider_id: int):
    try:
        _validate_csrf()
        provider = store.get_provider(provider_id)
        store.soft_delete(provider_id)
        store.audit("provider_delete", provider_id, provider["name"] if provider else "", request.remote_addr or "")
        current_app.extensions["refresh_provider_runtime"]()
        flash("Dashboard removed", "success")
    except Exception as exc:
        flash(str(exc), "error")
    return redirect(url_for("admin.index"))


@admin_bp.post("/providers/<int:provider_id>/test")
@admin_required
def provider_test(provider_id: int):
    try:
        _validate_csrf()
        provider = store.get_provider(provider_id)
        if not provider:
            raise KeyError("Provider not found")
        result = current_app.extensions["test_provider_connection"](provider)
        store.update_status(provider_id, True)
        store.audit("provider_test_ok", provider_id, result, request.remote_addr or "")
        flash(f"Connection successful: {result}", "success")
    except Exception as exc:
        store.update_status(provider_id, False, str(exc))
        store.audit("provider_test_failed", provider_id, str(exc), request.remote_addr or "")
        flash(f"Connection failed: {exc}", "error")
    return redirect(url_for("admin.index"))


@admin_bp.post("/providers/<int:provider_id>/clear-cache")
@admin_required
def provider_clear_cache(provider_id: int):
    try:
        _validate_csrf()
        provider = store.get_provider(provider_id)
        if not provider:
            raise KeyError("Provider not found")
        count = current_app.extensions["clear_provider_cache"](provider)
        store.audit("provider_cache_clear", provider_id, f"{count} entries", request.remote_addr or "")
        flash(f"Cleared {count} cached entries", "success")
    except Exception as exc:
        flash(str(exc), "error")
    return redirect(url_for("admin.index"))


@admin_bp.route("/password", methods=["GET", "POST"])
@admin_required
def password():
    if request.method == "POST":
        try:
            _validate_csrf()
            current_password = request.form.get("current_password", "")
            new_password = request.form.get("new_password", "")
            confirm = request.form.get("confirm_password", "")
            if not store.check_admin_password(current_password):
                raise ValueError("Current admin password is incorrect")
            if new_password != confirm:
                raise ValueError("New passwords do not match")
            store.set_admin_password(new_password)
            store.audit("admin_password_change", remote_addr=request.remote_addr or "")
            flash("Admin password updated", "success")
            return redirect(url_for("admin.index"))
        except Exception as exc:
            flash(str(exc), "error")
    return render_template("admin_password.html")
