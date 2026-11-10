"""Структурная проверка SOPS-файлов в secrets/ без расшифровки.

Без аргументов проверяет только пути из индекса Git (`git ls-files -z`) и их
содержимое из индекса. С аргументами проверяет явно указанные файлы рабочего
дерева (используется scripts/secrets/encrypt.sh до публикации результата).
"""

from __future__ import annotations

import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys

import yaml


README = "secrets/README.md"
SOPS_CONFIG = ".sops.yaml"
ENCRYPTED_PATH = re.compile(r"secrets/(?:[^/]+/)*[^/]+\.sops\.ya?ml")
ENC_VALUE = re.compile(r"ENC\[.*\]")
ENC_COMMENT = re.compile(r"\s*#ENC\[[^\]\s]*\]\s*")
AGE_RECIPIENT = re.compile(r"age1[02-9ac-hj-np-z]{58}")
# Полный приватный ключ age; одного префикса недостаточно для срабатывания.
AGE_PRIVATE_KEY = re.compile(rb"AGE-SECRET-KEY-1[02-9AC-HJ-NP-Z]{58}", re.IGNORECASE)
PLACEHOLDER_MARKERS = ("placeholder", "replace", "example", "changeme")
# Пути, которые правило .sops.yaml обязано принимать и отклонять.
RULE_MATCHES = ("secrets/app.sops.yaml", "secrets/nested/app.sops.yml")
RULE_REJECTS = ("secrets/app.yaml", "config/app.sops.yaml")


def plaintext_name(path: str) -> bool:
    name = PurePosixPath(path).name.lower()
    return (
        name in {"keys.txt", "age-keys.txt"}
        or name.endswith((".plain", ".decrypted", ".agekey", ".key", ".pem"))
        or ".decrypted." in name
        or ".plain." in name
    )


def placeholder_recipient(recipient: str) -> bool:
    lowered = recipient.lower()
    return any(marker in lowered for marker in PLACEHOLDER_MARKERS) or (
        lowered.startswith("age1") and set(lowered[4:]) <= {"q"}
    )


def recipient_errors(recipient: object, where: str) -> list[str]:
    if not isinstance(recipient, str) or not recipient:
        return [f"{where}: recipient должен быть непустой строкой"]
    if placeholder_recipient(recipient):
        return [f"{where}: используется placeholder вместо публичного recipient оператора"]
    if not AGE_RECIPIENT.fullmatch(recipient):
        return [f"{where}: recipient не похож на публичный ключ age (age1...)"]
    return []


def path_errors(path: str) -> list[str]:
    """Ошибки по имени пути; содержимое не читается."""
    if plaintext_name(path):
        return [f"{path}: открытый текст, расшифрованный файл или ключ запрещены"]
    if path.startswith("secrets/") and path != README and not ENCRYPTED_PATH.fullmatch(path):
        return [f"{path}: в secrets/ разрешены только README.md и *.sops.yaml/*.sops.yml"]
    return []


def scalar_errors(node: object, location: str) -> list[str]:
    if isinstance(node, dict):
        errors = []
        for key, value in node.items():
            errors.extend(scalar_errors(value, f"{location}.{key}"))
        return errors
    if isinstance(node, list):
        errors = []
        for index, value in enumerate(node):
            errors.extend(scalar_errors(value, f"{location}[{index}]"))
        return errors
    if isinstance(node, str) and ENC_VALUE.fullmatch(node):
        return []
    return [f"значение {location} не зашифровано (ожидается ENC[...])"]


def encrypted_errors(text: str) -> list[str]:
    """Ошибки структуры зашифрованного SOPS YAML; без расшифровки."""
    for line in text.splitlines():
        # Комментарии теряются при разборе YAML, поэтому проверяются по строкам:
        # SOPS сохраняет их только как #ENC[...].
        if "#" in line and not ENC_COMMENT.fullmatch(line):
            return ["незашифрованный комментарий или символ # вне ENC[...]"]
    try:
        document = yaml.safe_load(text)
    except yaml.YAMLError:
        return ["не удалось разобрать YAML"]
    if not isinstance(document, dict):
        return ["файл должен быть YAML mapping"]

    errors = []
    metadata = document.get("sops")
    if not isinstance(metadata, dict):
        return ["нет mapping sops: файл не зашифрован SOPS"]
    age = metadata.get("age")
    if not isinstance(age, list) or not age:
        errors.append("sops.age должен быть непустым списком")
    else:
        for index, entry in enumerate(age):
            where = f"sops.age[{index}]"
            if not isinstance(entry, dict):
                errors.append(f"{where}: ожидается mapping с recipient и enc")
                continue
            errors.extend(recipient_errors(entry.get("recipient"), where))
            enc = entry.get("enc")
            if not isinstance(enc, str) or "BEGIN AGE ENCRYPTED FILE" not in enc:
                errors.append(f"{where}: enc должен содержать зашифрованный age-блок")
    mac = metadata.get("mac")
    if not isinstance(mac, str) or not ENC_VALUE.fullmatch(mac):
        errors.append("sops.mac должен быть непустой строкой ENC[...]")
    version = metadata.get("version")
    if not isinstance(version, str) or not version:
        errors.append("sops.version должен быть непустой строкой")

    data_keys = [key for key in document if key != "sops"]
    if not data_keys:
        errors.append("нет зашифрованных данных вне sops")
    for key in data_keys:
        errors.extend(scalar_errors(document[key], str(key)))
    return errors


def config_errors(text: str | None) -> list[str]:
    if text is None:
        return [f"{SOPS_CONFIG}: файл отсутствует в индексе Git"]
    try:
        config = yaml.safe_load(text)
    except yaml.YAMLError:
        return [f"{SOPS_CONFIG}: не удалось разобрать YAML"]
    rules = config.get("creation_rules") if isinstance(config, dict) else None
    if not isinstance(rules, list) or not rules:
        return [f"{SOPS_CONFIG}: нет списка creation_rules"]

    def first_rule(path: str) -> dict | None:
        # SOPS применяет первое подходящее правило.
        for rule in rules:
            if isinstance(rule, dict) and isinstance(rule.get("path_regex"), str):
                try:
                    if re.search(rule["path_regex"], path):
                        return rule
                except re.error:
                    continue
        return None

    errors = []
    selected = [first_rule(path) for path in RULE_MATCHES]
    if any(rule is None for rule in selected):
        errors.append(f"{SOPS_CONFIG}: нет creation_rules.path_regex для secrets/**/*.sops.y*ml")
    for path in RULE_REJECTS:
        rule = first_rule(path)
        if rule is not None and rule in selected:
            errors.append(f"{SOPS_CONFIG}: path_regex шире secrets/**/*.sops.y*ml (совпадает с {path})")
    for rule in selected:
        if rule is None:
            continue
        recipients = rule.get("age")
        if recipients is not None:
            values = recipients if isinstance(recipients, list) else str(recipients).split(",")
            for value in values:
                errors.extend(
                    f"{SOPS_CONFIG}: {error}"
                    for error in recipient_errors(str(value).strip(), "creation_rules.age")
                )
    return list(dict.fromkeys(errors))


def content_errors(path: str, data: bytes) -> list[str]:
    if AGE_PRIVATE_KEY.search(data):
        return [f"{path}: содержит приватный ключ age"]
    if not ENCRYPTED_PATH.fullmatch(path):
        return []
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return [f"{path}: файл не в UTF-8"]
    return [f"{path}: {error}" for error in encrypted_errors(text)]


def git(*args: str) -> bytes:
    return subprocess.check_output(["git", *args], stderr=subprocess.DEVNULL)


def check_index() -> tuple[list[str], int]:
    paths = sorted({p.decode("utf-8", "surrogateescape") for p in git("ls-files", "-z").split(b"\0") if p})
    errors = []
    encrypted = 0
    config = None
    for path in paths:
        name_errors = path_errors(path)
        if name_errors:
            errors.extend(name_errors)
            continue
        try:
            data = git("cat-file", "blob", f":{path}")
        except subprocess.CalledProcessError:
            errors.append(f"{path}: не удалось прочитать файл из индекса (конфликт?)")
            continue
        if path == SOPS_CONFIG:
            config = data.decode("utf-8", "replace")
        if ENCRYPTED_PATH.fullmatch(path):
            encrypted += 1
        errors.extend(content_errors(path, data))
    errors.extend(config_errors(config))
    return errors, encrypted


def check_files(arguments: list[str], root: Path) -> tuple[list[str], int]:
    errors = []
    for argument in arguments:
        absolute = Path(argument).resolve()
        try:
            path = absolute.relative_to(root).as_posix()
        except ValueError:
            errors.append(f"{argument}: файл вне репозитория")
            continue
        if not ENCRYPTED_PATH.fullmatch(path):
            errors.append(f"{path}: ожидается путь secrets/**/*.sops.y*ml")
            continue
        try:
            data = absolute.read_bytes()
        except OSError:
            errors.append(f"{path}: не удалось прочитать файл")
            continue
        errors.extend(path_errors(path) or content_errors(path, data))
    try:
        config = (root / SOPS_CONFIG).read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        config = None
    errors.extend(config_errors(config))
    return errors, len(arguments)


def main(arguments: list[str]) -> int:
    try:
        root = Path(git("rev-parse", "--show-toplevel").decode().strip()).resolve()
    except (OSError, subprocess.CalledProcessError):
        print("Не удалось определить корень репозитория Git.", file=sys.stderr)
        return 1
    if arguments:
        errors, count = check_files(arguments, root)
    else:
        os.chdir(root)
        try:
            errors, count = check_index()
        except (OSError, subprocess.CalledProcessError):
            print("Не удалось прочитать индекс Git.", file=sys.stderr)
            return 1
    for error in errors:
        print(f"SOPS policy: {error}", file=sys.stderr)
    if errors:
        return 1
    print(f"SOPS policy: проверено зашифрованных файлов: {count}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
