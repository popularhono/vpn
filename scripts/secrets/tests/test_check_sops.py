"""Тесты политики SOPS на синтетических данных без сети и без ключей age."""

from __future__ import annotations

import os
from pathlib import Path, PurePosixPath
import subprocess
import sys
import tempfile
import unittest


REPO = Path(__file__).resolve().parents[3]
CHECK_SOPS = REPO / "scripts" / "secrets" / "check_sops.py"
CHECK_REPOSITORY = REPO / "scripts" / "check_repository.py"
sys.path.insert(0, str(REPO / "scripts"))

import check_repository  # noqa: E402


# Синтетические значения: не шифротекст реального ключа.
FAKE_ENC = "ENC[AES256_GCM,data:ZmFrZQ==,iv:ZmFrZQ==,tag:ZmFrZQ==,type:str]"
FAKE_RECIPIENT = "age1" + "qpzry9x8gf2tvdw0s3jn54khce6mua7l" + "qpzry9x8gf2tvdw0s3jn54khce"
FAKE_AGE_BLOCK = "-----BEGIN AGE ENCRYPTED FILE-----\nZmFrZQ==\n-----END AGE ENCRYPTED FILE-----\n"


def encrypted_yaml(
    *,
    data: str = f"database:\n  password: {FAKE_ENC}\n  hosts:\n    - {FAKE_ENC}\n",
    recipient: str = FAKE_RECIPIENT,
    age: bool = True,
    mac: bool = True,
    version: bool = True,
) -> str:
    lines = [data.rstrip("\n"), "sops:"]
    if age:
        lines += ["  age:", f"    - recipient: {recipient}", "      enc: |"]
        lines += [f"        {line}" for line in FAKE_AGE_BLOCK.splitlines()]
    lines.append('  lastmodified: "2026-01-01T00:00:00Z"')
    if mac:
        lines.append(f"  mac: {FAKE_ENC}")
    if version:
        lines.append("  version: 3.13.3")
    return "\n".join(lines) + "\n"


class TemporaryRepository:
    def __init__(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.env = {
            **os.environ,
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
        }
        self.git("init", "-q")
        self.write(".sops.yaml", (REPO / ".sops.yaml").read_text(encoding="utf-8"))
        self.write("secrets/README.md", "# Секреты\n")

    def git(self, *args: str) -> None:
        subprocess.run(["git", *args], cwd=self.root, env=self.env, check=True, capture_output=True)

    def write(self, path: str, content: str) -> None:
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        self.git("add", "--force", "--", path)

    def remove(self, path: str) -> None:
        self.git("rm", "-q", "--cached", "--", path)

    def run(self, script: Path, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(script), *args],
            cwd=self.root,
            env=self.env,
            capture_output=True,
            text=True,
            check=False,
        )


class CheckSopsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.repo = TemporaryRepository()
        self.addCleanup(self.repo.directory.cleanup)

    def assert_passes(self) -> None:
        result = self.repo.run(CHECK_SOPS)
        self.assertEqual(result.returncode, 0, result.stderr)

    def assert_fails(self, *fragments: str) -> str:
        result = self.repo.run(CHECK_SOPS)
        self.assertEqual(result.returncode, 1, result.stdout)
        for fragment in fragments:
            self.assertIn(fragment, result.stderr)
        return result.stderr

    def test_readme_and_config_only(self) -> None:
        self.assert_passes()

    def test_valid_encrypted_yaml(self) -> None:
        self.repo.write("secrets/app.sops.yaml", encrypted_yaml())
        self.repo.write("secrets/nested/app.sops.yml", encrypted_yaml())
        self.assert_passes()

    def test_encrypted_comment_allowed(self) -> None:
        self.repo.write("secrets/app.sops.yaml", f"#{FAKE_ENC}\n" + encrypted_yaml())
        self.assert_passes()

    def test_plaintext_yaml_under_secrets(self) -> None:
        self.repo.write("secrets/app.yaml", "password: plain-text-value\n")
        self.assert_fails("secrets/app.yaml", "только README.md")

    def test_plaintext_content_with_sops_name(self) -> None:
        self.repo.write("secrets/app.sops.yaml", "password: plain-text-value\n")
        self.assert_fails("secrets/app.sops.yaml", "нет mapping sops")

    def test_missing_mac(self) -> None:
        self.repo.write("secrets/app.sops.yaml", encrypted_yaml(mac=False))
        self.assert_fails("sops.mac")

    def test_missing_age(self) -> None:
        self.repo.write("secrets/app.sops.yaml", encrypted_yaml(age=False))
        self.assert_fails("sops.age")

    def test_missing_version(self) -> None:
        self.repo.write("secrets/app.sops.yaml", encrypted_yaml(version=False))
        self.assert_fails("sops.version")

    def test_non_enc_scalar(self) -> None:
        data = f"database:\n  password: {FAKE_ENC}\n  port: 5432\n  user: plain-user-value\n"
        self.repo.write("secrets/app.sops.yaml", encrypted_yaml(data=data))
        stderr = self.assert_fails("database.port", "database.user")
        # Значения не попадают в вывод проверки.
        self.assertNotIn("plain-user-value", stderr)

    def test_plaintext_comment(self) -> None:
        self.repo.write("secrets/app.sops.yaml", "# password plain-text-value\n" + encrypted_yaml())
        self.assert_fails("комментарий")

    def test_placeholder_recipient(self) -> None:
        self.repo.write("secrets/app.sops.yaml", encrypted_yaml(recipient="age1placeholder"))
        self.assert_fails("placeholder")

    def test_zero_recipient_is_placeholder(self) -> None:
        self.repo.write("secrets/app.sops.yaml", encrypted_yaml(recipient="age1" + "q" * 58))
        self.assert_fails("placeholder")

    def test_private_key_in_metadata(self) -> None:
        # Собирается во время выполнения: в исходнике и .pyc нет полного литерала.
        key = "-".join(["AGE", "SECRET", "KEY", "1" + "Q" * 58])
        self.repo.write("secrets/app.sops.yaml", encrypted_yaml() + f"  note: {key}\n")
        stderr = self.assert_fails("приватный ключ age")
        self.assertNotIn(key, stderr)

    def test_other_path_under_secrets(self) -> None:
        self.repo.write("secrets/notes.txt", "x\n")
        self.assert_fails("secrets/notes.txt")

    def test_plaintext_extensions_anywhere(self) -> None:
        for path in (
            "config/app.plain",
            "config/app.decrypted",
            "config/app.decrypted.yaml",
            "keys/operator.agekey",
            "keys.txt",
            "tls/server.key",
            "tls/server.pem",
        ):
            self.repo.write(path, "x\n")
        stderr = self.assert_fails()
        self.assertEqual(len(stderr.strip().splitlines()), 7, stderr)

    def test_missing_config(self) -> None:
        self.repo.remove(".sops.yaml")
        self.assert_fails(".sops.yaml", "отсутствует")

    def test_config_without_matching_rule(self) -> None:
        self.repo.write(".sops.yaml", "creation_rules:\n  - path_regex: ^other/.*$\n")
        self.assert_fails("нет creation_rules.path_regex")

    def test_config_not_yaml_mapping(self) -> None:
        self.repo.write(".sops.yaml", "- just\n- a list\n")
        self.assert_fails("нет списка creation_rules")

    def test_config_rule_too_broad(self) -> None:
        self.repo.write(".sops.yaml", "creation_rules:\n  - path_regex: .*\n")
        self.assert_fails("шире")

    def test_config_placeholder_recipient(self) -> None:
        config = (
            "creation_rules:\n"
            "  - path_regex: ^secrets/(?:[^/]+/)*[^/]+\\.sops\\.ya?ml$\n"
            "    age: age1replacewithoperatorrecipient\n"
        )
        self.repo.write(".sops.yaml", config)
        self.assert_fails("placeholder")

    def test_explicit_file_mode(self) -> None:
        target = self.repo.root / "secrets" / "draft.sops.yaml"
        target.write_text(encrypted_yaml(mac=False), encoding="utf-8")
        result = self.repo.run(CHECK_SOPS, str(target))
        self.assertEqual(result.returncode, 1)
        self.assertIn("sops.mac", result.stderr)
        target.write_text(encrypted_yaml(), encoding="utf-8")
        result = self.repo.run(CHECK_SOPS, str(target))
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_untracked_files_ignored(self) -> None:
        (self.repo.root / "secrets" / "local.yaml").write_text("password: x\n", encoding="utf-8")
        self.assert_passes()


class RepositoryPolicyTest(unittest.TestCase):
    def test_encrypted_paths_allowed(self) -> None:
        for path in (
            "secrets/README.md",
            "secrets/app.sops.yaml",
            "secrets/nested/app.sops.yml",
            ".sops.yaml",
            "scripts/secrets/check_sops.py",
            "scripts/secrets/tests/test_check_sops.py",
        ):
            self.assertFalse(check_repository.private_path(PurePosixPath(path)), path)

    def test_plaintext_paths_blocked(self) -> None:
        for path in (
            "secrets/foo.yaml",
            "secrets/app.sops.json",
            "secrets/notes.txt",
            "secrets/nested/README.md",
            "secrets/.sops.yaml",
            "secrets/app.sops.yaml.bak",
            "secrets/server.key",
            "secrets/production/app.sops.yaml",
            "Secrets/app.sops.yaml",
            "config/secrets/app.sops.yaml",
            "scripts/secrets/server.pem",
            "scripts/secrets/private/tool.py",
            "credentials/app.sops.yaml",
        ):
            self.assertTrue(check_repository.private_path(PurePosixPath(path)), path)

    def test_end_to_end(self) -> None:
        repo = TemporaryRepository()
        self.addCleanup(repo.directory.cleanup)
        repo.write("secrets/app.sops.yaml", encrypted_yaml())
        result = repo.run(CHECK_REPOSITORY)
        self.assertEqual(result.returncode, 0, result.stderr)
        repo.write("secrets/foo.yaml", "a: b\n")
        result = repo.run(CHECK_REPOSITORY)
        self.assertEqual(result.returncode, 1)
        self.assertIn("secrets/foo.yaml", result.stderr)


if __name__ == "__main__":
    unittest.main()
