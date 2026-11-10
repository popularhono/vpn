#!/usr/bin/env bash
# Шифрует YAML вне репозитория в secrets/<имя>.sops.yaml для публичного
# recipient из SOPS_AGE_RECIPIENT. Приватный ключ не нужен и не читается.
set -euo pipefail
umask 077

usage() {
  printf '%s\n' 'Использование: SOPS_AGE_RECIPIENT=age1... scripts/secrets/encrypt.sh [--force] INPUT.yaml' >&2
  exit 2
}

force=0
input=''
while (($#)); do
  case "$1" in
    --force) force=1 ;;
    -h | --help) usage ;;
    -*) printf 'Неизвестный параметр: %s\n' "$1" >&2; usage ;;
    *) [[ -z "$input" ]] || usage; input="$1" ;;
  esac
  shift
done
[[ -n "$input" ]] || usage

command -v sops >/dev/null || { printf '%s\n' 'Не найден sops.' >&2; exit 1; }
[[ -n "${SOPS_AGE_RECIPIENT:-}" ]] || { printf '%s\n' 'Задайте SOPS_AGE_RECIPIENT (публичный ключ age).' >&2; exit 1; }
IFS=',' read -r -a recipients <<<"$SOPS_AGE_RECIPIENT"
for recipient in "${recipients[@]}"; do
  if [[ ! "$recipient" =~ ^age1[02-9ac-hj-np-z]{58}$ || "$recipient" =~ ^age1q+$ ]]; then
    printf '%s\n' 'SOPS_AGE_RECIPIENT должен содержать только публичные ключи age1..., не placeholder.' >&2
    exit 1
  fi
done

root="$(git rev-parse --show-toplevel)"
[[ -f "$input" && -r "$input" ]] || { printf 'Нет читаемого файла: %s\n' "$input" >&2; exit 1; }
input_dir="$(cd "$(dirname "$input")" && pwd -P)"
case "$input_dir/" in
  "$root/secrets/"*) printf '%s\n' 'Входной файл не должен находиться в secrets/.' >&2; exit 1 ;;
esac

name="$(basename "$input")"
name="${name%.yaml}"
name="${name%.yml}"
if [[ ! "$name" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ || "$name" == *.sops || "$name" == *.decrypted* || "$name" == *.plain* ]]; then
  printf 'Недопустимое имя для secrets/: %s\n' "$name" >&2
  exit 1
fi
output="secrets/$name.sops.yaml"

cd "$root"
if [[ -e "$output" && "$force" -ne 1 ]]; then
  printf '%s уже существует; используйте --force для перезаписи.\n' "$output" >&2
  exit 1
fi

python="${PYTHON:-}"
if [[ -z "$python" ]]; then
  if [[ -x .venv/bin/python ]]; then python=.venv/bin/python; else python=python3; fi
fi

mkdir -p secrets
# Промежуточный каталог внутри secrets/: путь соответствует правилу .sops.yaml,
# а готовый файл появляется только после успешной проверки.
workdir="$(mktemp -d secrets/.encrypt.XXXXXX)"
trap 'rm -rf "$workdir"' EXIT
staged="$workdir/$name.sops.yaml"

sops --config .sops.yaml --encrypt --age "$SOPS_AGE_RECIPIENT" \
  --input-type yaml --output-type yaml \
  --filename-override "$output" --output "$staged" "$input_dir/$(basename "$input")"

if ! "$python" scripts/secrets/check_sops.py "$staged"; then
  rm -f "$staged"
  printf '%s\n' 'Результат не прошёл проверку и удалён.' >&2
  exit 1
fi
mv -f "$staged" "$output"
printf 'Зашифровано: %s\n' "$output"
