#!/usr/bin/env python3
"""Compare two PALISADE unsigned release candidates and emit a closed local attestation."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tarfile
import tempfile
import stat


SCHEMA_VERSION = "palisade.release-reproduction.v1"
LIMITATIONS = (
    "proves byte identity of two supplied candidates; does not prove independent people, hosts or custody",
    "signed-tag trust depends on the checkout's reviewed Git signature configuration",
    "covers the source archive and static binaries; excludes container images and deployment configuration",
    "uses no deployment, customer or production traffic records",
    "requires owner-controlled immutable candidate directories during comparison",
)
TOP_LEVEL_FIELDS = {
    "schema_version",
    "version",
    "source_tag",
    "source_commit",
    "source_date_epoch",
    "go_version",
    "candidates_compared",
    "identical",
    "manifest_sha256",
    "artifacts",
    "limitations",
}
ARTIFACT_FIELDS = {"name", "sha256", "size_bytes"}
SEMVER = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
GO_VERSION = re.compile(r"^go1\.27\.[0-9]+$")
MAX_FILE_BYTES = 512 * 1024 * 1024
MAX_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
MAX_TAR_MEMBERS = 100_000


class ReproductionError(ValueError):
    """A candidate or attestation violated the closed reproduction contract."""


def artifact_names(version: str) -> list[str]:
    if SEMVER.fullmatch(version) is None:
        raise ReproductionError("version must be SemVer without a leading v")
    prefix = f"palisade-{version}"
    return sorted(
        [
            f"{prefix}-source.tar",
            f"{prefix}-linux-amd64",
            f"{prefix}-linux-arm64",
            f"{prefix}-darwin-amd64",
            f"{prefix}-darwin-arm64",
            f"{prefix}-windows-amd64.exe",
            "RELEASE-METADATA.json",
        ]
    )


def _closed_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ReproductionError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _stat_identity(info: os.stat_result) -> tuple[int, int, int, int, int, int, int]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _open_regular(path: Path, expected: tuple[int, ...]) -> int:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ReproductionError(f"cannot open stable release artifact: {path.name}") from error
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or _stat_identity(info) != expected:
            raise ReproductionError(f"release artifact changed during comparison: {path.name}")
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _read_bounded(path: Path, expected: tuple[int, ...], maximum: int, label: str) -> bytes:
    descriptor = _open_regular(path, expected)
    with os.fdopen(descriptor, "rb", closefd=True) as handle:
        payload = handle.read(maximum + 1)
        if len(payload) > maximum:
            raise ReproductionError(f"{label} exceeds its {maximum}-byte budget")
        if _stat_identity(os.fstat(handle.fileno())) != expected:
            raise ReproductionError(f"release artifact changed during comparison: {path.name}")
        return payload


def _hash_file(path: Path, expected: tuple[int, ...]) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    descriptor = _open_regular(path, expected)
    with os.fdopen(descriptor, "rb", closefd=True) as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            if size > MAX_FILE_BYTES:
                raise ReproductionError(f"release artifact exceeds the 512 MiB budget: {path.name}")
            digest.update(chunk)
        if _stat_identity(os.fstat(handle.fileno())) != expected:
            raise ReproductionError(f"release artifact changed during comparison: {path.name}")
    return digest.hexdigest(), size


def _load_metadata(path: Path, version: str, expected: tuple[int, ...]) -> dict[str, object]:
    try:
        payload = _read_bounded(path, expected, 64 * 1024, "release metadata")
        document = json.loads(payload.decode("utf-8"), object_pairs_hook=_closed_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReproductionError(f"release metadata is invalid: {error}") from error
    fields = {"schema_version", "version", "git_commit", "source_date_epoch", "go_version"}
    if not isinstance(document, dict) or set(document) != fields:
        raise ReproductionError("release metadata fields are not closed")
    if document["schema_version"] != "palisade.local-release.v1" or document["version"] != version:
        raise ReproductionError("release metadata version mismatch")
    if not isinstance(document["git_commit"], str) or COMMIT.fullmatch(document["git_commit"]) is None:
        raise ReproductionError("release metadata commit is invalid")
    if (
        type(document["source_date_epoch"]) is not int
        or document["source_date_epoch"] < 1
        or not isinstance(document["go_version"], str)
        or GO_VERSION.fullmatch(document["go_version"]) is None
    ):
        raise ReproductionError("release metadata epoch or Go version is invalid")
    return document


def _parse_manifest(
    path: Path, expected_names: list[str], expected: tuple[int, ...]
) -> tuple[dict[str, str], bytes]:
    try:
        payload = _read_bounded(path, expected, 64 * 1024, "SHA256SUMS")
        text = payload.decode("ascii")
    except UnicodeDecodeError as error:
        raise ReproductionError("SHA256SUMS must be bounded ASCII") from error
    if not payload.endswith(b"\n") or b"\r" in payload:
        raise ReproductionError("SHA256SUMS must use canonical LF lines")
    values: dict[str, str] = {}
    for line in text.splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9._-]+)", line)
        if match is None:
            raise ReproductionError("SHA256SUMS contains a malformed line")
        digest, name = match.groups()
        if name in values:
            raise ReproductionError("SHA256SUMS contains a duplicate artifact")
        values[name] = digest
    if list(values) != expected_names or set(values) != set(expected_names):
        raise ReproductionError("SHA256SUMS does not cover the exact sorted artifact set")
    return values, payload


def _validate_source_archive(path: Path, version: str, expected: tuple[int, ...]) -> None:
    prefix = f"palisade-{version}"
    total_members = 0
    total_payload = 0
    seen_names: set[str] = set()
    try:
        descriptor = _open_regular(path, expected)
        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            with tarfile.open(fileobj=handle, mode="r:") as archive:
                for member in archive:
                    total_members += 1
                    if total_members > MAX_TAR_MEMBERS:
                        raise ReproductionError("source archive exceeds the member budget")
                    name = PurePosixPath(member.name)
                    if name.is_absolute() or ".." in name.parts or not (
                        member.name == prefix or member.name.startswith(prefix + "/")
                    ):
                        raise ReproductionError("source archive contains an unsafe path")
                    if member.name in seen_names:
                        raise ReproductionError("source archive contains a duplicate path")
                    seen_names.add(member.name)
                    if not (member.isfile() or member.isdir()):
                        raise ReproductionError("source archive contains a link or special file")
                    if member.isfile():
                        total_payload += member.size
                        if total_payload > MAX_FILE_BYTES:
                            raise ReproductionError("source archive payload exceeds the 512 MiB budget")
            if _stat_identity(os.fstat(handle.fileno())) != expected:
                raise ReproductionError(f"release artifact changed during comparison: {path.name}")
    except (tarfile.TarError, OSError) as error:
        raise ReproductionError(f"source archive is invalid: {error}") from error
    if total_members == 0:
        raise ReproductionError("source archive is empty")


def inspect_candidate(directory: Path, version: str) -> dict[str, object]:
    if directory.is_symlink() or not directory.is_dir():
        raise ReproductionError("candidate must be a real directory")
    expected_artifacts = artifact_names(version)
    expected_entries = set(expected_artifacts) | {"SHA256SUMS"}
    entries = list(directory.iterdir())
    if {entry.name for entry in entries} != expected_entries:
        raise ReproductionError("candidate has a missing or unexpected entry")
    total_bytes = 0
    snapshots: dict[str, tuple[int, ...]] = {}
    for entry in entries:
        try:
            info = entry.lstat()
        except OSError as error:
            raise ReproductionError(f"candidate entry is unavailable: {entry.name}") from error
        if entry.is_symlink() or not stat.S_ISREG(info.st_mode):
            raise ReproductionError(f"candidate entry is not a regular non-symlink file: {entry.name}")
        snapshots[entry.name] = _stat_identity(info)
        total_bytes += info.st_size
        if total_bytes > MAX_TOTAL_BYTES:
            raise ReproductionError("candidate exceeds the 2 GiB aggregate budget")

    manifest, manifest_payload = _parse_manifest(
        directory / "SHA256SUMS", expected_artifacts, snapshots["SHA256SUMS"]
    )
    artifacts = []
    for name in expected_artifacts:
        digest, size = _hash_file(directory / name, snapshots[name])
        if digest != manifest[name]:
            raise ReproductionError(f"candidate checksum mismatch: {name}")
        artifacts.append({"name": name, "sha256": digest, "size_bytes": size})
    _validate_source_archive(
        directory / f"palisade-{version}-source.tar",
        version,
        snapshots[f"palisade-{version}-source.tar"],
    )
    metadata = _load_metadata(
        directory / "RELEASE-METADATA.json", version, snapshots["RELEASE-METADATA.json"]
    )
    for name, expected in snapshots.items():
        try:
            current = (directory / name).lstat()
        except OSError as error:
            raise ReproductionError(f"candidate changed during comparison: {name}") from error
        if _stat_identity(current) != expected:
            raise ReproductionError(f"candidate changed during comparison: {name}")
    return {
        "metadata": metadata,
        "manifest": manifest_payload,
        "manifest_sha256": hashlib.sha256(manifest_payload).hexdigest(),
        "artifacts": artifacts,
    }


def validate_signed_source_tag(repository_root: Path, version: str, commit: str) -> None:
    tag = "v" + version
    commands = (
        (["git", "cat-file", "-t", f"{tag}^{{tag}}"], "tag"),
        (["git", "rev-list", "-n", "1", tag], commit),
    )
    for command, expected in commands:
        completed = subprocess.run(
            command,
            cwd=repository_root,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
        )
        if completed.returncode != 0 or completed.stdout.strip() != expected:
            raise ReproductionError("signed source tag is missing, lightweight or points elsewhere")
    verified = subprocess.run(
        ["git", "tag", "-v", tag],
        cwd=repository_root,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if verified.returncode != 0:
        raise ReproductionError("signed source tag verification failed")
    reachable = subprocess.run(
        ["git", "merge-base", "--is-ancestor", commit, "HEAD"],
        cwd=repository_root,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if reachable.returncode != 0:
        raise ReproductionError("signed source tag commit is not reachable from this checkout")


def build_attestation(
    version: str,
    preparer: Path,
    reproducer: Path,
    repository_root: Path | None = None,
) -> dict[str, object]:
    first = inspect_candidate(preparer, version)
    second = inspect_candidate(reproducer, version)
    if first["metadata"] != second["metadata"]:
        raise ReproductionError("candidate release metadata differs")
    if first["manifest"] != second["manifest"] or first["artifacts"] != second["artifacts"]:
        raise ReproductionError("candidate artifacts are not byte-for-byte reproducible")
    metadata = first["metadata"]
    commit = metadata["git_commit"]
    if repository_root is not None:
        validate_signed_source_tag(repository_root, version, commit)
    report = {
        "schema_version": SCHEMA_VERSION,
        "version": version,
        "source_tag": "v" + version,
        "source_commit": commit,
        "source_date_epoch": metadata["source_date_epoch"],
        "go_version": metadata["go_version"],
        "candidates_compared": 2,
        "identical": True,
        "manifest_sha256": first["manifest_sha256"],
        "artifacts": first["artifacts"],
        "limitations": list(LIMITATIONS),
    }
    validate_attestation(report, repository_root)
    return report


def validate_attestation(document: dict[str, object], repository_root: Path | None = None) -> None:
    if not isinstance(document, dict) or set(document) != TOP_LEVEL_FIELDS:
        raise ReproductionError("attestation top-level fields are not closed")
    version = document["version"]
    if document["schema_version"] != SCHEMA_VERSION or not isinstance(version, str) or SEMVER.fullmatch(version) is None:
        raise ReproductionError("attestation version is invalid")
    commit = document["source_commit"]
    if (
        document["source_tag"] != "v" + version
        or not isinstance(commit, str)
        or COMMIT.fullmatch(commit) is None
        or type(document["source_date_epoch"]) is not int
        or document["source_date_epoch"] < 1
        or not isinstance(document["go_version"], str)
        or GO_VERSION.fullmatch(document["go_version"]) is None
        or type(document["candidates_compared"]) is not int
        or document["candidates_compared"] != 2
        or document["identical"] is not True
    ):
        raise ReproductionError("attestation provenance or result is invalid")
    if document["limitations"] != list(LIMITATIONS):
        raise ReproductionError("attestation limitations are missing, reordered or changed")
    artifacts = document["artifacts"]
    names = artifact_names(version)
    if not isinstance(artifacts, list) or len(artifacts) != len(names):
        raise ReproductionError("attestation artifact count changed")
    manifest_lines = []
    for artifact, expected_name in zip(artifacts, names):
        if (
            not isinstance(artifact, dict)
            or set(artifact) != ARTIFACT_FIELDS
            or artifact["name"] != expected_name
            or not isinstance(artifact["sha256"], str)
            or SHA256.fullmatch(artifact["sha256"]) is None
            or type(artifact["size_bytes"]) is not int
            or not 0 < artifact["size_bytes"] <= MAX_FILE_BYTES
        ):
            raise ReproductionError("attestation artifact is malformed or out of order")
        manifest_lines.append(f"{artifact['sha256']}  {artifact['name']}\n")
    expected_manifest_hash = hashlib.sha256("".join(manifest_lines).encode("ascii")).hexdigest()
    if document["manifest_sha256"] != expected_manifest_hash:
        raise ReproductionError("attestation manifest digest does not match its artifacts")
    if repository_root is not None:
        validate_signed_source_tag(repository_root, version, commit)


def load_attestation(path: Path) -> dict[str, object]:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 128 * 1024:
        raise ReproductionError("attestation must be a regular bounded non-symlink file")
    try:
        document = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_closed_object)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReproductionError(f"attestation JSON is invalid: {error}") from error
    if not isinstance(document, dict):
        raise ReproductionError("attestation root must be an object")
    return document


def _inside_git_worktree(path: Path) -> bool:
    completed = subprocess.run(
        ["git", "-C", os.fspath(path), "rev-parse", "--is-inside-work-tree"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        encoding="utf-8",
    )
    return completed.returncode == 0 and completed.stdout.strip() == "true"


def write_attestation_create_only(output: Path, report: dict[str, object]) -> None:
    if output.name in {"", ".", ".."}:
        raise ReproductionError("output must name a new attestation file")
    if output.exists() or output.is_symlink():
        raise ReproductionError("output must not already exist")
    try:
        parent = output.parent.resolve(strict=True)
        info = parent.stat()
    except OSError as error:
        raise ReproductionError(f"output parent is unavailable: {error}") from error
    if not parent.is_dir() or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ReproductionError("output parent must be an owner-only directory")
    if _inside_git_worktree(parent):
        raise ReproductionError("output must remain outside every Git worktree")
    payload = (json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + "\n").encode("utf-8")
    descriptor = -1
    temporary_name = ""
    published: Path | None = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(prefix=".palisade-reproduction-", dir=parent)
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            descriptor = -1
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        target = parent / output.name
        os.link(temporary_name, target, follow_symlinks=False)
        published = target
        os.unlink(temporary_name)
        temporary_name = ""
        directory_descriptor = os.open(parent, os.O_RDONLY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    except (OSError, TypeError, ValueError) as error:
        if published is not None:
            try:
                os.unlink(published)
            except FileNotFoundError:
                pass
        raise ReproductionError(f"cannot publish reproduction attestation: {error}") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary_name:
            try:
                os.unlink(temporary_name)
            except FileNotFoundError:
                pass


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version")
    parser.add_argument("--preparer", type=Path)
    parser.add_argument("--reproducer", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--verify", type=Path)
    arguments = parser.parse_args(argv)
    comparison_values = (
        arguments.version,
        arguments.preparer,
        arguments.reproducer,
        arguments.output,
    )
    any_comparison = any(value is not None for value in comparison_values)
    all_comparison = all(value is not None for value in comparison_values)
    if arguments.verify is not None:
        invalid_mode = any_comparison
    else:
        invalid_mode = not all_comparison
    if invalid_mode:
        parser.error("choose either --verify or all of --version, --preparer, --reproducer and --output")
    repository_root = Path(__file__).resolve().parent.parent
    try:
        if arguments.verify is not None:
            report = load_attestation(arguments.verify)
            validate_attestation(report, repository_root)
        else:
            report = build_attestation(
                arguments.version, arguments.preparer, arguments.reproducer, repository_root
            )
            write_attestation_create_only(arguments.output, report)
    except (ReproductionError, OSError, subprocess.SubprocessError) as error:
        print(f"release-reproduction: failed: {error}", file=sys.stderr)
        return 1
    if arguments.verify is not None:
        print("release-reproduction: verified signed-tag attestation for 7 byte-identical artifacts")
    else:
        print("release-reproduction: wrote signed-tag attestation for 7 byte-identical artifacts")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
