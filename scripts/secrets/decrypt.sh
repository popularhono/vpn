#!/usr/bin/env bash
# Расшифровывает secrets/**/*.sops.y*ml в stdout или, с --output, в файл вне
# репозитория. Ключ ищет сам SOPS: SOPS_AGE_KEY_FILE, SOPS_AGE_KEY или
# стандартный keys.txt (~/.config/sops/age/keys.txt; на macOS — каталог
# ~/Library/Application Support/sops/age/). Скрипт ключ не читает и не выводит.
set -euo pipefail
umask 077

usage() {
  printf '%s\n' 'Использование: scripts/secrets/decrypt.sh [--output FILE [--force]] secrets/NAME.sops.yaml' >&2
  exit 2
}

force=0
output=''
input=''
while (($#)); do
  case "$1" in
    --force) force=1 ;;
    --output) (($# >= 2)) || usage; output="$2"; shift ;;
    -h | --help) usage ;;
    -*) printf 'Неизвестный параметр: %s\n' "$1" >&2; usage ;;
    *) [[ -z "$input" ]] || usage; input="$1" ;;
  esac
  shift
done
[[ -n "$input" ]] || usage
[[ "$force" -eq 0 || -n "$output" ]] || { printf '%s\n' '--force используется только с --output.' >&2; exit 2; }

command -v sops >/dev/null || { printf '%s\n' 'Не найден sops.' >&2; exit 1; }
if [[ -n "${SOPS_AGE_KEY_FILE:-}" && ! -r "$SOPS_AGE_KEY_FILE" ]]; then
  printf '%s\n' 'SOPS_AGE_KEY_FILE задан, но файл недоступен для чтения.' >&2
  exit 1
fi

root="$(git rev-parse --show-toplevel)"
[[ -f "$input" ]] || { printf 'Нет файла: %s\n' "$input" >&2; exit 1; }
input_path="$(cd "$(dirname "$input")" && pwd -P)/$(basename "$input")"
relative="${input_path#"$root/"}"
if [[ "$relative" == "$input_path" || ! "$relative" =~ ^secrets/([^/]+/)*[^/]+\.sops\.ya?ml$ ]]; then
  printf '%s\n' 'Ожидается файл secrets/**/*.sops.yaml или *.sops.yml этого репозитория.' >&2
  exit 1
fi

if [[ -z "$output" ]]; then
  exec sops --decrypt --input-type yaml --output-type yaml "$input_path"
fi

output_dir="$(cd "$(dirname "$output")" 2>/dev/null && pwd -P)" || {
  printf '%s\n' 'Каталог для --output не существует.' >&2
  exit 1
}
output_path="$output_dir/$(basename "$output")"
# Расшифрованный файл никогда не пишется в рабочее дерево: ни в secrets/,
# ни в другие каталоги, где его можно случайно добавить в Git.
case "$output_path/" in
  "$root/"*) printf '%s\n' '--output должен указывать за пределы репозитория.' >&2; exit 1 ;;
esac
if [[ -e "$output_path" && "$force" -ne 1 ]]; then
  printf '%s уже существует; используйте --force для перезаписи.\n' "$output" >&2
  exit 1
fi

staged="$(mktemp "$output_dir/.decrypt.XXXXXX")"
trap 'rm -f "$staged"' EXIT
sops --decrypt --input-type yaml --output-type yaml --output "$staged" "$input_path"
mv -f "$staged" "$output_path"
trap - EXIT
printf 'Расшифровано в файл вне репозитория: %s\n' "$output" >&2
