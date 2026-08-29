#!/bin/sh
set -eu

usage() {
	echo "usage: scripts/release-local.sh [--plan] VERSION [OUTPUT_DIR]" >&2
}

plan_only=false
if [ "${1:-}" = "--plan" ]; then
	plan_only=true
	shift
fi
version=${1:-}
output_dir=${2:-}
if [ -z "$version" ] || [ "$#" -gt 2 ]; then
	usage
	exit 2
fi
if ! printf '%s\n' "$version" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$'; then
	echo "release-local: VERSION must be SemVer without a leading v" >&2
	exit 2
fi

targets='linux/amd64
linux/arm64
darwin/amd64
darwin/arm64
windows/amd64'

if [ "$plan_only" = true ]; then
	echo "PALISADE local release plan"
	echo "version: $version"
	echo "required tag: v$version"
	echo "artifacts: source archive, metadata, checksums and binaries for:"
	printf '%s\n' "$targets" | sed 's/^/  - /'
	exit 0
fi

repository_root=$(git rev-parse --show-toplevel)
cd "$repository_root"
if [ -z "$output_dir" ]; then
	output_dir="dist/release/$version"
fi
case "$output_dir" in
	/|.|..)
		echo "release-local: unsafe output directory" >&2
		exit 2
		;;
esac
if [ -e "$output_dir" ]; then
	echo "release-local: output directory already exists: $output_dir" >&2
	exit 1
fi
if [ -n "$(git status --porcelain --untracked-files=normal)" ]; then
	echo "release-local: worktree and index must be clean" >&2
	exit 1
fi

head_commit=$(git rev-parse HEAD)
tag_commit=$(git rev-list -n 1 "v$version" 2>/dev/null || true)
if [ -z "$tag_commit" ] || [ "$tag_commit" != "$head_commit" ]; then
	echo "release-local: signed release tag v$version must point at HEAD" >&2
	exit 1
fi
tag_type=$(git cat-file -t "v$version^{tag}" 2>/dev/null || true)
if [ "$tag_type" != "tag" ]; then
	echo "release-local: v$version must be a signed tag" >&2
	exit 1
fi
if ! git tag -v "v$version" >/dev/null 2>&1; then
	echo "release-local: signature verification failed for v$version" >&2
	exit 1
fi

./scripts/verify-local.sh

source_date_epoch=$(git show -s --format=%ct HEAD)
export SOURCE_DATE_EPOCH="$source_date_epoch"
umask 022
mkdir -p "$output_dir"

prefix="palisade-$version"
git archive --format=tar --prefix="$prefix/" --output="$output_dir/$prefix-source.tar" HEAD

printf '%s\n' "$targets" | while IFS=/ read -r target_os target_arch; do
	extension=
	if [ "$target_os" = "windows" ]; then
		extension=.exe
	fi
	artifact="$output_dir/$prefix-$target_os-$target_arch$extension"
	echo "release-local: building $target_os/$target_arch"
	CGO_ENABLED=0 GOOS="$target_os" GOARCH="$target_arch" GOFLAGS=-mod=readonly \
		go build -trimpath -buildvcs=true \
		-ldflags="-s -w -X main.version=$version" \
		-o "$artifact" ./cmd/palisade
done

go_version=$(go env GOVERSION)
printf '{\n  "schema_version": "palisade.local-release.v1",\n  "version": "%s",\n  "git_commit": "%s",\n  "source_date_epoch": %s,\n  "go_version": "%s"\n}\n' \
	"$version" "$head_commit" "$source_date_epoch" "$go_version" >"$output_dir/RELEASE-METADATA.json"

hash_artifact() {
	artifact_path=$1
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$artifact_path" | sed "s#  .*#  $(basename "$artifact_path")#"
	else
		shasum -a 256 "$artifact_path" | sed "s#  .*#  $(basename "$artifact_path")#"
	fi
}

for artifact_path in "$output_dir"/*; do
	[ "$(basename "$artifact_path")" = "SHA256SUMS" ] && continue
	hash_artifact "$artifact_path"
done | LC_ALL=C sort -k2 >"$output_dir/SHA256SUMS"

echo "release-local: artifacts written to $output_dir"
echo "release-local: compare SHA256SUMS across independent clean builds before publication"
