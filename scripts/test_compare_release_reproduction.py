from __future__ import annotations

import copy
import contextlib
import hashlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock

from scripts import compare_release_reproduction


VERSION = "0.9.0-test.1"
COMMIT = "0123456789abcdef0123456789abcdef01234567"


class ReleaseReproductionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.repository_root = Path(__file__).resolve().parent.parent

    def write_candidate(
        self,
        directory: Path,
        *,
        binary_marker: bytes = b"same",
        metadata_updates: dict[str, object] | None = None,
        tar_kind: str = "safe",
    ) -> None:
        directory.mkdir(mode=0o700)
        prefix = f"palisade-{VERSION}"
        source = directory / f"{prefix}-source.tar"
        with tarfile.open(source, mode="w:") as archive:
            if tar_kind == "safe":
                payload = b"synthetic release source\n"
                member = tarfile.TarInfo(f"{prefix}/README.txt")
                member.size = len(payload)
                archive.addfile(member, io.BytesIO(payload))
            elif tar_kind == "duplicate":
                for payload in (b"first\n", b"second\n"):
                    member = tarfile.TarInfo(f"{prefix}/README.txt")
                    member.size = len(payload)
                    archive.addfile(member, io.BytesIO(payload))
            elif tar_kind == "link":
                member = tarfile.TarInfo(f"{prefix}/link")
                member.type = tarfile.SYMTYPE
                member.linkname = "/private/synthetic"
                archive.addfile(member)
            else:
                payload = b"escape\n"
                member = tarfile.TarInfo(f"{prefix}/../escape")
                member.size = len(payload)
                archive.addfile(member, io.BytesIO(payload))

        for name in compare_release_reproduction.artifact_names(VERSION):
            if name.endswith("-source.tar") or name == "RELEASE-METADATA.json":
                continue
            (directory / name).write_bytes(b"synthetic static binary:" + binary_marker + b":" + name.encode("ascii"))

        metadata = {
            "schema_version": "palisade.local-release.v1",
            "version": VERSION,
            "git_commit": COMMIT,
            "source_date_epoch": 1_777_777_777,
            "go_version": "go1.27.0",
        }
        if metadata_updates:
            metadata.update(metadata_updates)
        (directory / "RELEASE-METADATA.json").write_text(
            json.dumps(metadata, separators=(",", ":")) + "\n", encoding="utf-8"
        )
        self.rewrite_manifest(directory)

    def rewrite_manifest(self, directory: Path) -> None:
        lines = []
        for name in compare_release_reproduction.artifact_names(VERSION):
            digest = hashlib.sha256((directory / name).read_bytes()).hexdigest()
            lines.append(f"{digest}  {name}\n")
        (directory / "SHA256SUMS").write_text("".join(lines), encoding="ascii")

    def build_matching_report(self, parent: Path) -> dict[str, object]:
        preparer = parent / "preparer"
        reproducer = parent / "reproducer"
        self.write_candidate(preparer)
        self.write_candidate(reproducer)
        return compare_release_reproduction.build_attestation(VERSION, preparer, reproducer)

    def test_matching_candidates_produce_a_closed_valid_attestation(self):
        with tempfile.TemporaryDirectory() as directory:
            report = self.build_matching_report(Path(directory))
        compare_release_reproduction.validate_attestation(report)
        self.assertEqual(report["source_commit"], COMMIT)
        self.assertEqual(report["candidates_compared"], 2)
        self.assertIs(report["identical"], True)
        self.assertEqual(len(report["artifacts"]), 7)

    def test_tampered_file_without_manifest_update_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            candidate = Path(directory) / "candidate"
            self.write_candidate(candidate)
            binary = candidate / f"palisade-{VERSION}-linux-amd64"
            binary.write_bytes(binary.read_bytes() + b"tampered")
            with self.assertRaisesRegex(compare_release_reproduction.ReproductionError, "checksum mismatch"):
                compare_release_reproduction.inspect_candidate(candidate, VERSION)

    def test_two_internally_valid_but_different_candidates_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            self.write_candidate(parent / "preparer", binary_marker=b"one")
            self.write_candidate(parent / "reproducer", binary_marker=b"two")
            with self.assertRaisesRegex(compare_release_reproduction.ReproductionError, "not byte-for-byte"):
                compare_release_reproduction.build_attestation(
                    VERSION, parent / "preparer", parent / "reproducer"
                )

    def test_candidate_mutation_during_inspection_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            candidate = Path(directory) / "candidate"
            self.write_candidate(candidate)
            binary = candidate / f"palisade-{VERSION}-linux-amd64"
            original_hash = compare_release_reproduction._hash_file

            def mutate_after_hash(path, expected):
                result = original_hash(path, expected)
                if path == binary:
                    path.write_bytes(path.read_bytes() + b"concurrent mutation")
                return result

            with mock.patch.object(
                compare_release_reproduction, "_hash_file", side_effect=mutate_after_hash
            ):
                with self.assertRaisesRegex(compare_release_reproduction.ReproductionError, "changed during comparison"):
                    compare_release_reproduction.inspect_candidate(candidate, VERSION)

    def test_metadata_mismatch_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            self.write_candidate(parent / "preparer")
            self.write_candidate(
                parent / "reproducer",
                metadata_updates={"source_date_epoch": 1_777_777_778},
            )
            with self.assertRaisesRegex(compare_release_reproduction.ReproductionError, "metadata differs"):
                compare_release_reproduction.build_attestation(
                    VERSION, parent / "preparer", parent / "reproducer"
                )

    def test_extra_entry_and_symlink_entry_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            extra = parent / "extra"
            self.write_candidate(extra)
            (extra / "unexpected.txt").write_text("synthetic\n", encoding="utf-8")
            with self.assertRaisesRegex(compare_release_reproduction.ReproductionError, "unexpected entry"):
                compare_release_reproduction.inspect_candidate(extra, VERSION)

            linked = parent / "linked"
            self.write_candidate(linked)
            binary = linked / f"palisade-{VERSION}-linux-amd64"
            binary.unlink()
            binary.symlink_to(linked / f"palisade-{VERSION}-linux-arm64")
            with self.assertRaisesRegex(compare_release_reproduction.ReproductionError, "non-symlink"):
                compare_release_reproduction.inspect_candidate(linked, VERSION)

    def test_unsafe_duplicate_and_link_tar_members_are_rejected(self):
        for kind, message in (("escape", "unsafe path"), ("duplicate", "duplicate path"), ("link", "link or special")):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                candidate = Path(directory) / "candidate"
                self.write_candidate(candidate, tar_kind=kind)
                with self.assertRaisesRegex(compare_release_reproduction.ReproductionError, message):
                    compare_release_reproduction.inspect_candidate(candidate, VERSION)

    def test_invalid_metadata_types_and_duplicate_keys_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            boolean_epoch = parent / "boolean"
            self.write_candidate(boolean_epoch, metadata_updates={"source_date_epoch": True})
            with self.assertRaisesRegex(compare_release_reproduction.ReproductionError, "epoch or Go version"):
                compare_release_reproduction.inspect_candidate(boolean_epoch, VERSION)

            duplicate = parent / "duplicate"
            self.write_candidate(duplicate)
            (duplicate / "RELEASE-METADATA.json").write_text(
                '{"schema_version":"palisade.local-release.v1","version":"0.9.0-test.1",'
                '"git_commit":"0123456789abcdef0123456789abcdef01234567",'
                '"source_date_epoch":1777777777,"source_date_epoch":1777777778,"go_version":"go1.27.0"}\n',
                encoding="utf-8",
            )
            self.rewrite_manifest(duplicate)
            with self.assertRaisesRegex(compare_release_reproduction.ReproductionError, "duplicate JSON key"):
                compare_release_reproduction.inspect_candidate(duplicate, VERSION)

    def test_attestation_limitations_counts_and_manifest_are_tamper_evident(self):
        with tempfile.TemporaryDirectory() as directory:
            report = self.build_matching_report(Path(directory))
        cases = []
        changed_limitations = copy.deepcopy(report)
        changed_limitations["limitations"].pop()
        cases.append(changed_limitations)
        boolean_count = copy.deepcopy(report)
        boolean_count["candidates_compared"] = True
        cases.append(boolean_count)
        changed_manifest = copy.deepcopy(report)
        changed_manifest["manifest_sha256"] = "0" * 64
        cases.append(changed_manifest)
        for changed in cases:
            with self.assertRaises(compare_release_reproduction.ReproductionError):
                compare_release_reproduction.validate_attestation(changed)

    def test_create_only_output_is_owner_only_and_not_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            parent.chmod(0o700)
            report = self.build_matching_report(parent)
            output = parent / "reproduction.json"
            compare_release_reproduction.write_attestation_create_only(output, report)
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            self.assertEqual(compare_release_reproduction.load_attestation(output), report)
            with self.assertRaisesRegex(compare_release_reproduction.ReproductionError, "must not already exist"):
                compare_release_reproduction.write_attestation_create_only(output, report)

    def test_output_inside_git_worktree_is_rejected(self):
        with tempfile.TemporaryDirectory(dir=self.repository_root) as directory:
            parent = Path(directory)
            parent.chmod(0o700)
            with tempfile.TemporaryDirectory() as candidates:
                report = self.build_matching_report(Path(candidates))
            with self.assertRaisesRegex(compare_release_reproduction.ReproductionError, "outside every Git worktree"):
                compare_release_reproduction.write_attestation_create_only(
                    parent / "reproduction.json", report
                )

    def test_concurrent_creator_is_not_deleted(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            parent.chmod(0o700)
            report = self.build_matching_report(parent)
            output = parent / "reproduction.json"

            def create_competing_output(_source, target, **_kwargs):
                Path(target).write_text("operator-owned\n", encoding="utf-8")
                raise FileExistsError("synthetic publication race")

            with mock.patch.object(
                compare_release_reproduction.os, "link", side_effect=create_competing_output
            ):
                with self.assertRaisesRegex(compare_release_reproduction.ReproductionError, "cannot publish"):
                    compare_release_reproduction.write_attestation_create_only(output, report)
            self.assertEqual(output.read_text(encoding="utf-8"), "operator-owned\n")

    def test_signed_tag_must_verify_point_to_commit_and_be_reachable(self):
        successful = [
            subprocess.CompletedProcess([], 0, "tag\n"),
            subprocess.CompletedProcess([], 0, COMMIT + "\n"),
            subprocess.CompletedProcess([], 0),
            subprocess.CompletedProcess([], 0),
        ]
        with mock.patch.object(compare_release_reproduction.subprocess, "run", side_effect=successful):
            compare_release_reproduction.validate_signed_source_tag(
                self.repository_root, VERSION, COMMIT
            )
        unreachable = successful[:-1] + [subprocess.CompletedProcess([], 1)]
        with mock.patch.object(compare_release_reproduction.subprocess, "run", side_effect=unreachable):
            with self.assertRaisesRegex(compare_release_reproduction.ReproductionError, "not reachable"):
                compare_release_reproduction.validate_signed_source_tag(
                    self.repository_root, VERSION, COMMIT
                )

    @unittest.skipUnless(shutil.which("ssh-keygen") and shutil.which("git"), "Git and OpenSSH are required")
    def test_real_annotated_ssh_signed_tag_is_verified_offline(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = root / "repository"
            repository.mkdir()
            key = root / "release-test-key"
            subprocess.run(
                ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "release-test", "-f", str(key)],
                check=True,
            )
            public_key = (key.with_suffix(".pub")).read_text(encoding="ascii").strip()
            allowed_signers = root / "allowed-signers"
            allowed_signers.write_text(
                f'release-test@example.invalid namespaces="git" {public_key}\n', encoding="ascii"
            )
            subprocess.run(["git", "init", "-q"], cwd=repository, check=True)
            settings = {
                "user.name": "PALISADE release test",
                "user.email": "release-test@example.invalid",
                "gpg.format": "ssh",
                "user.signingkey": str(key),
                "gpg.ssh.allowedSignersFile": str(allowed_signers),
            }
            for setting, value in settings.items():
                subprocess.run(["git", "config", setting, value], cwd=repository, check=True)
            (repository / "README.txt").write_text("synthetic signed tag fixture\n", encoding="utf-8")
            subprocess.run(["git", "add", "README.txt"], cwd=repository, check=True)
            subprocess.run(["git", "commit", "-q", "-m", "synthetic source"], cwd=repository, check=True)
            commit = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=repository,
                check=True,
                stdout=subprocess.PIPE,
                text=True,
                encoding="utf-8",
            ).stdout.strip()
            subprocess.run(
                ["git", "tag", "-s", f"v{VERSION}", "-m", "synthetic signed release"],
                cwd=repository,
                check=True,
            )
            compare_release_reproduction.validate_signed_source_tag(repository, VERSION, commit)

    def test_duplicate_attestation_key_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            path.write_text(
                '{"schema_version":"one","schema_version":"two"}\n', encoding="utf-8"
            )
            with self.assertRaisesRegex(compare_release_reproduction.ReproductionError, "duplicate JSON key"):
                compare_release_reproduction.load_attestation(path)

    def test_partial_or_mixed_cli_modes_are_rejected(self):
        for arguments in (
            ["--version", VERSION],
            ["--verify", "report.json", "--version", VERSION],
        ):
            with self.subTest(arguments=arguments), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
                compare_release_reproduction.main(arguments)
            self.assertEqual(raised.exception.code, 2)

    def test_schema_matches_runtime_contract(self):
        schema = json.loads(
            (self.repository_root / "schemas/release-reproduction-v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(
            schema["properties"]["schema_version"]["const"],
            compare_release_reproduction.SCHEMA_VERSION,
        )
        self.assertEqual(set(schema["required"]), compare_release_reproduction.TOP_LEVEL_FIELDS)
        self.assertEqual(
            schema["properties"]["limitations"]["prefixItems"],
            [{"const": value} for value in compare_release_reproduction.LIMITATIONS],
        )


if __name__ == "__main__":
    unittest.main()
