#!/bin/sh
set -eu

usage() {
	echo "usage: scripts/sign-release-checksums.sh SIGNER_ID PRIVATE_KEY RELEASE_DIR" >&2
}

if [ "$#" -ne 3 ]; then
	usage
	exit 2
fi

signer_id=$1
private_key=$2
release_dir=$3

if ! printf '%s\n' "$signer_id" | grep -Eq '^[A-Za-z0-9][A-Za-z0-9._@+-]{0,127}$'; then
	echo "sign-release-checksums: invalid signer identity" >&2
	exit 2
fi
for command_name in git python3 ssh-keygen; do
	command -v "$command_name" >/dev/null 2>&1 || {
		echo "sign-release-checksums: required command not found: $command_name" >&2
		exit 1
	}
done
if [ ! -d "$release_dir" ] || [ -L "$release_dir" ]; then
	echo "sign-release-checksums: release directory must be a real directory" >&2
	exit 1
fi
if [ ! -f "$private_key" ] || [ -L "$private_key" ]; then
	echo "sign-release-checksums: private key must be a regular non-symlink file" >&2
	exit 1
fi
canonical_private_key=$(python3 - "$private_key" <<'PY'
import os
import pathlib
import stat
import sys

path = pathlib.Path(sys.argv[1])
try:
    info = path.lstat()
    canonical = path.resolve(strict=True)
except OSError:
    raise SystemExit("sign-release-checksums: private key cannot be resolved")
if stat.S_ISLNK(info.st_mode) or not canonical.is_file():
    raise SystemExit("sign-release-checksums: private key must be a regular non-symlink file")
if canonical.stat().st_mode & 0o077:
    raise SystemExit("sign-release-checksums: private key must not grant group or world permissions")
print(os.fspath(canonical))
PY
)
private_key_dir=$(dirname "$canonical_private_key")
inside_worktree=$(git -C "$private_key_dir" rev-parse --is-inside-work-tree 2>/dev/null || true)
inside_git_dir=$(git -C "$private_key_dir" rev-parse --is-inside-git-dir 2>/dev/null || true)
if [ "$inside_worktree" = "true" ] || [ "$inside_git_dir" = "true" ]; then
	echo "sign-release-checksums: private key must remain outside every Git worktree" >&2
	exit 1
fi
if [ ! -f "$release_dir/SHA256SUMS" ] || [ -L "$release_dir/SHA256SUMS" ]; then
	echo "sign-release-checksums: SHA256SUMS is missing or unsafe" >&2
	exit 1
fi
if [ -e "$release_dir/SHA256SUMS.sig" ] || [ -e "$release_dir/RELEASE-SIGNER" ]; then
	echo "sign-release-checksums: signature output already exists" >&2
	exit 1
fi

ssh-keygen -Y sign -q -f "$canonical_private_key" -n palisade-release "$release_dir/SHA256SUMS"
umask 022
printf '%s\n' "$signer_id" >"$release_dir/RELEASE-SIGNER"

echo "sign-release-checksums: signed SHA256SUMS as $signer_id"
