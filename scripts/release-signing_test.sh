#!/bin/sh
set -eu

repository_root=$(git rev-parse --show-toplevel)
cd "$repository_root"

temporary_root=$(mktemp -d "${TMPDIR:-/tmp}/palisade-release-signing.XXXXXX")
trap 'rm -rf "$temporary_root"' EXIT HUP INT TERM

version=0.0.0-test.1
release_dir="$temporary_root/release"
source_root="$temporary_root/source/palisade-$version"
mkdir -p "$release_dir" "$source_root"
printf 'synthetic source fixture\n' >"$source_root/README.txt"
tar -cf "$release_dir/palisade-$version-source.tar" -C "$temporary_root/source" "palisade-$version"
for target in linux-amd64 linux-arm64 darwin-amd64 darwin-arm64 windows-amd64.exe; do
	printf 'synthetic binary fixture: %s\n' "$target" >"$release_dir/palisade-$version-$target"
done
printf '%s\n' \
	'{"schema_version":"palisade.local-release.v1","version":"0.0.0-test.1","git_commit":"0123456789abcdef0123456789abcdef01234567","source_date_epoch":1,"go_version":"go1.27.0"}' \
	>"$release_dir/RELEASE-METADATA.json"

python3 - "$release_dir" <<'PY'
import hashlib
import pathlib
import sys

release_dir = pathlib.Path(sys.argv[1])
with (release_dir / "SHA256SUMS").open("w", encoding="ascii", newline="\n") as output:
    for path in sorted(release_dir.iterdir(), key=lambda candidate: candidate.name):
        if path.name == "SHA256SUMS":
            continue
        output.write(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n")
PY

ssh-keygen -q -t ed25519 -N '' -C palisade-release-test -f "$temporary_root/release-key"
chmod 0644 "$temporary_root/release-key"
if ./scripts/sign-release-checksums.sh release-test "$temporary_root/release-key" "$release_dir" >/dev/null 2>&1; then
	echo "release-signing-test: group-readable private key was accepted" >&2
	exit 1
fi
chmod 0600 "$temporary_root/release-key"

git init -q "$temporary_root/key-worktree"
ssh-keygen -q -t ed25519 -N '' -C palisade-release-worktree -f "$temporary_root/key-worktree/release-key"
chmod 0600 "$temporary_root/key-worktree/release-key"
if ./scripts/sign-release-checksums.sh release-test "$temporary_root/key-worktree/release-key" "$release_dir" >/dev/null 2>&1; then
	echo "release-signing-test: private key inside a Git worktree was accepted" >&2
	exit 1
fi

printf 'release-test namespaces="palisade-release" %s\n' "$(cat "$temporary_root/release-key.pub")" >"$temporary_root/allowed-signers"
./scripts/sign-release-checksums.sh release-test "$temporary_root/release-key" "$release_dir"
./scripts/verify-release.sh "$version" "$release_dir" "$temporary_root/allowed-signers"

cp "$release_dir/palisade-$version-linux-amd64" "$temporary_root/original-linux-amd64"
printf 'tampered\n' >>"$release_dir/palisade-$version-linux-amd64"
if ./scripts/verify-release.sh "$version" "$release_dir" "$temporary_root/allowed-signers" >/dev/null 2>&1; then
	echo "release-signing-test: tampered artifact was accepted" >&2
	exit 1
fi
cp "$temporary_root/original-linux-amd64" "$release_dir/palisade-$version-linux-amd64"

ssh-keygen -q -t ed25519 -N '' -C palisade-release-rogue -f "$temporary_root/rogue-key"
chmod 0600 "$temporary_root/rogue-key"
printf 'release-test namespaces="palisade-release" %s\n' "$(cat "$temporary_root/rogue-key.pub")" >"$temporary_root/rogue-signers"
if ./scripts/verify-release.sh "$version" "$release_dir" "$temporary_root/rogue-signers" >/dev/null 2>&1; then
	echo "release-signing-test: unpinned signer was accepted" >&2
	exit 1
fi

echo "release-signing-test: signature, exact manifest, tamper and signer-pin checks passed"
