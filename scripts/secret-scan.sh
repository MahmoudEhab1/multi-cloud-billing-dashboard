#!/usr/bin/env bash
set -euo pipefail
root="${1:-.}"
cd "$root"
status=0
patterns='([0-9]{8,12}:[A-Za-z0-9_-]{30,}|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY-----|(?i)(password|passwd|secret|token|api[_-]?key)["'"'"']?[[:space:]]*[:=][[:space:]]*["'"'"'][^"'"'"']{12,}["'"'"'])'
if command -v rg >/dev/null 2>&1; then
  if rg -n --hidden -g '!.git/**' -g '!.env.example' -e "$patterns" .; then status=1; fi
else
  echo "ripgrep (rg) not installed; manual secret scan required" >&2
fi
exit "$status"
