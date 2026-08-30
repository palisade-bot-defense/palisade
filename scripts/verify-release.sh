#!/bin/sh
set -eu

usage() {
	echo "usage: scripts/verify-release.sh VERSION RELEASE_DIR ALLOWED_SIGNERS" >&2
}

if [ "$#" -ne 3 ]; then
	usage
	exit 2
fi

version=$1
release_dir=$2
allowed_signers=$3

if ! printf '%s\n' "$version" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$'; then
	echo "verify-release: VERSION must be SemVer without a leading v" >&2
	exit 2
fi
for command_name in python3 ssh-keygen; do
	command -v "$command_name" >/dev/null 2>&1 || {
		echo "verify-release: required command not found: $command_name" >&2
		exit 1
	}
done
if [ ! -d "$release_dir" ] || [ -L "$release_dir" ]; then
	echo "verify-release: release directory must be a real directory" >&2
	exit 1
fi
if [ ! -f "$allowed_signers" ] || [ -L "$allowed_signers" ]; then
	echo "verify-release: allowed-signers file must be a regular non-symlink file" >&2
	exit 1
fi

for required_file in SHA256SUMS SHA256SUMS.sig RELEASE-SIGNER RELEASE-METADATA.json; do
	if [ ! -f "$release_dir/$required_file" ] || [ -L "$release_dir/$required_file" ]; then
		echo "verify-release: required file is missing or unsafe: $required_file" >&2
		exit 1
	fi
done

signer_id=$(sed -n '1p' "$release_dir/RELEASE-SIGNER")
if ! printf '%s\n' "$signer_id" | grep -Eq '^[A-Za-z0-9][A-Za-z0-9._@+-]{0,127}$'; then
	echo "verify-release: invalid signer identity" >&2
	exit 1
fi
if [ "$(wc -l <"$release_dir/RELEASE-SIGNER" | tr -d ' ')" -ne 1 ]; then
	echo "verify-release: RELEASE-SIGNER must contain exactly one line" >&2
	exit 1
fi

if ! ssh-keygen -Y verify \
	-f "$allowed_signers" \
	-I "$signer_id" \
	-n palisade-release \
	-s "$release_dir/SHA256SUMS.sig" \
	<"$release_dir/SHA256SUMS"; then
	echo "verify-release: checksum signature verification failed" >&2
	exit 1
fi

python3 - "$version" "$release_dir" <<'PY'
import hashlib
import json
import pathlib
import re
import sys
import tarfile

version = sys.argv[1]
release_dir = pathlib.Path(sys.argv[2])
prefix = f"palisade-{version}"
artifacts = {
    f"{prefix}-source.tar",
    f"{prefix}-linux-amd64",
    f"{prefix}-linux-arm64",
    f"{prefix}-darwin-amd64",
    f"{prefix}-darwin-arm64",
    f"{prefix}-windows-amd64.exe",
    "RELEASE-METADATA.json",
}
control_files = {"SHA256SUMS", "SHA256SUMS.sig", "RELEASE-SIGNER"}
actual = {path.name for path in release_dir.iterdir()}
if actual != artifacts | control_files:
    missing = sorted((artifacts | control_files) - actual)
    extra = sorted(actual - (artifacts | control_files))
    raise SystemExit(f"verify-release: unexpected release contents: missing={missing} extra={extra}")
for name in actual:
    path = release_dir / name
    if path.is_symlink() or not path.is_file():
        raise SystemExit(f"verify-release: unsafe release entry: {name}")

checksum_lines = (release_dir / "SHA256SUMS").read_text(encoding="ascii").splitlines()
checksums = {}
for line in checksum_lines:
    match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9._-]+)", line)
    if match is None:
        raise SystemExit("verify-release: malformed SHA256SUMS line")
    digest, name = match.groups()
    if name in checksums:
        raise SystemExit(f"verify-release: duplicate checksum entry: {name}")
    checksums[name] = digest
if set(checksums) != artifacts:
    raise SystemExit("verify-release: checksum manifest does not cover the exact artifact set")
for name, expected in checksums.items():
    actual_digest = hashlib.sha256((release_dir / name).read_bytes()).hexdigest()
    if actual_digest != expected:
        raise SystemExit(f"verify-release: checksum mismatch: {name}")

def reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result

try:
    metadata = json.loads(
        (release_dir / "RELEASE-METADATA.json").read_text(encoding="utf-8"),
        object_pairs_hook=reject_duplicate_keys,
    )
except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
    raise SystemExit(f"verify-release: invalid release metadata: {error}")
required_keys = {"schema_version", "version", "git_commit", "source_date_epoch", "go_version"}
if set(metadata) != required_keys:
    raise SystemExit("verify-release: release metadata is not closed")
if metadata["schema_version"] != "palisade.local-release.v1":
    raise SystemExit("verify-release: unsupported metadata schema")
if metadata["version"] != version:
    raise SystemExit("verify-release: metadata version mismatch")
if not isinstance(metadata["git_commit"], str) or re.fullmatch(r"[0-9a-f]{40}", metadata["git_commit"]) is None:
    raise SystemExit("verify-release: invalid metadata commit")
if not isinstance(metadata["source_date_epoch"], int) or isinstance(metadata["source_date_epoch"], bool) or metadata["source_date_epoch"] < 1:
    raise SystemExit("verify-release: invalid source epoch")
if not isinstance(metadata["go_version"], str) or re.fullmatch(r"go1\.27\.[0-9]+", metadata["go_version"]) is None:
    raise SystemExit("verify-release: unsupported Go version")

source_archive = release_dir / f"{prefix}-source.tar"
with tarfile.open(source_archive, mode="r:") as archive:
    members = archive.getmembers()
    if not members:
        raise SystemExit("verify-release: source archive is empty")
    for member in members:
        path = pathlib.PurePosixPath(member.name)
        if path.is_absolute() or ".." in path.parts or not (
            member.name == prefix or member.name.startswith(f"{prefix}/")
        ):
            raise SystemExit("verify-release: unsafe source archive path")
        if not (member.isfile() or member.isdir()):
            raise SystemExit("verify-release: source archive contains a link or special file")

print(f"verify-release: verified {len(artifacts)} artifacts signed by the pinned release identity")
PY
