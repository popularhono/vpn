#!/usr/bin/env bash
# Проверка secrets/ без расшифровки: структурная проверка всегда, а при наличии
# sops — дополнительно `sops filestatus` для каждого tracked SOPS-файла.
set -euo pipefail

root="$(git rev-parse --show-toplevel)"
cd "$root"

python="${PYTHON:-}"
if [[ -z "$python" ]]; then
  if [[ -x .venv/bin/python ]]; then python=.venv/bin/python; else python=python3; fi
fi
"$python" scripts/secrets/check_sops.py

if ! command -v sops >/dev/null; then
  printf '%s\n' 'sops не найден: sops filestatus пропущен, структурная проверка выполнена.'
  exit 0
fi

failed=0
checked=0
while IFS= read -r -d '' path; do
  [[ "$path" =~ ^secrets/([^/]+/)*[^/]+\.sops\.ya?ml$ ]] || continue
  checked=$((checked + 1))
  status="$(sops filestatus "$path" 2>/dev/null || true)"
  if [[ ! "$status" =~ \"encrypted\":[[:space:]]*true ]]; then
    printf '%s: sops filestatus не подтверждает encrypted: true\n' "$path" >&2
    failed=1
  fi
done < <(git ls-files -z -- secrets)

[[ "$failed" -eq 0 ]] || exit 1
printf 'sops filestatus: проверено файлов: %s.\n' "$checked"
