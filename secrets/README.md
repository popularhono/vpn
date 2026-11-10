# Каталог secrets

Здесь хранятся только секреты, зашифрованные SOPS для публичных ключей age.
Полное описание процесса, модели угроз, ротации и реагирования на компрометацию —
в [docs/SECRETS.md](../docs/SECRETS.md). Этот файл — краткая памятка.

## Что разрешено

- `secrets/README.md` — единственный файл в открытом виде.
- `secrets/**/*.sops.yaml` и `secrets/**/*.sops.yml` — только зашифрованные SOPS:
  верхнеуровневый блок `sops` с непустыми `age`, `mac` и `version`, а каждое
  значение вне `sops` имеет вид `ENC[...]`.

Любой другой путь в `secrets/` блокируется `scripts/check_repository.py` и
`scripts/secrets/check_sops.py` (в составе `make check` и CI).

## Что запрещено

- Открытый текст: файлы `*.plain`, `*.decrypted`, `*.decrypted.*`, любые
  нешифрованные YAML. Сначала создавайте исходный YAML вне репозитория.
- Приватные ключи age (`keys.txt`, `*.agekey`), а также `*.key` и `*.pem` —
  нигде в репозитории. Приватный ключ хранится только у оператора вне Git.
- Расшифрованный вывод в рабочем дереве. `scripts/secrets/decrypt.sh` не пишет
  файлы внутрь репозитория.

`.gitignore` игнорирует всё в `secrets/`, кроме разрешённых шаблонов, но не
защищает уже отслеживаемые файлы и не заменяет проверку diff.

## Команды

```sh
# Публичный recipient оператора (не приватный ключ).
export SOPS_AGE_RECIPIENT='age1...'

# Шифрование файла вне репозитория в secrets/<имя>.sops.yaml.
scripts/secrets/encrypt.sh /path/outside/repo/app.yaml
scripts/secrets/encrypt.sh --force /path/outside/repo/app.yaml   # перезапись

# Расшифровка в stdout или в файл вне репозитория (нужен приватный ключ).
scripts/secrets/decrypt.sh secrets/app.sops.yaml
scripts/secrets/decrypt.sh --output /path/outside/repo/app.yaml secrets/app.sops.yaml

# Проверка без расшифровки.
scripts/secrets/check.sh
make secrets-check
```

Сейчас в каталоге нет ни одного реального секрета.
