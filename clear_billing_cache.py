#!/usr/bin/env python3

import fcntl
import json
import os
from datetime import datetime, timezone
from pathlib import Path

APP_ROOT = Path(os.environ.get("APP_ROOT", Path(__file__).resolve().parent))
CACHE_FILE = APP_ROOT / "cache.json"
LOCK_FILE = APP_ROOT / "cache.json.lock"

APP_ROOT.mkdir(parents=True, exist_ok=True)

with LOCK_FILE.open("a+") as lock:
    fcntl.flock(lock.fileno(), fcntl.LOCK_EX)

    try:
        current = json.loads(CACHE_FILE.read_text()) if CACHE_FILE.exists() else {}
        removed = len(current) if isinstance(current, dict) else 0
    except Exception:
        removed = 0

    temporary = APP_ROOT / f"cache.json.tmp.{os.getpid()}"
    temporary.write_text("{}")
    os.chmod(temporary, 0o640)
    os.replace(temporary, CACHE_FILE)

    fcntl.flock(lock.fileno(), fcntl.LOCK_UN)

print(
    f"{datetime.now(timezone.utc).isoformat()} "
    f"cleared {removed} billing cache entries"
)
