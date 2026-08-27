#!/bin/sh
set -eu

repository_root=$(git rev-parse --show-toplevel)
cd "$repository_root"

index_list=$(mktemp "${TMPDIR:-/tmp}/palisade-privacy-index.XXXXXX")
blob_file=$(mktemp "${TMPDIR:-/tmp}/palisade-privacy-blob.XXXXXX")
trap 'rm -f "$index_list" "$blob_file"' EXIT HUP INT TERM

# The index is the exact set of Git blobs a commit would consume. Never follow
# or read a worktree path: a hostile symlink or concurrent replacement must not
# change what this guard inspected.
git ls-files -s >"$index_list"

failed=0
max_blob_bytes=5242880
tab=$(printf '\t')

while IFS="$tab" read -r metadata path; do
	[ -n "$path" ] || continue
	set -- $metadata
	mode=$1
	object=$2
	stage=$3
	if [ "$stage" != "0" ]; then
		echo "privacy-check: unresolved index stage: $path" >&2
		failed=1
		continue
	fi
	if [ "$mode" = "120000" ]; then
		echo "privacy-check: tracked symlink is not allowed: $path" >&2
		failed=1
		continue
	fi
	case "$mode" in
		100644|100755) ;;
		*) continue ;;
	esac

	base=${path##*/}
	case "$base" in
		access.log.gz|anubis-strain.jsonl.gz|crowdsec-alerts.json|crowdsec-decisions.json|error.log.gz)
			echo "privacy-check: forbidden raw bundle filename: $path" >&2
			failed=1
			;;
		events-[0-9][0-9][0-9][0-9][0-9][0-9].jsonl|manifest.json|COMPLETE)
			echo "privacy-check: normalized offline artifact filename: $path" >&2
			failed=1
			;;
	esac

	case "$path" in
		examples/replay/synthetic.jsonl) ;;
		*.gz|*.jsonl|*.csv|*.parquet|*.sql|*.sqlite|*.sqlite3|*.db|*.plog)
			echo "privacy-check: data-artifact extension is not allowed: $path" >&2
			failed=1
			;;
	esac

	blob_size=$(git cat-file -s "$object")
	if [ "$blob_size" -gt "$max_blob_bytes" ]; then
		echo "privacy-check: Git blob exceeds 5 MiB: $path" >&2
		failed=1
	fi

	git cat-file blob "$object" >"$blob_file"
	blob_magic=$(LC_ALL=C od -An -tx1 -N4 "$blob_file" | tr -d '[:space:]')
	case "$blob_magic" in
		1f8b*)
			echo "privacy-check: renamed gzip data content: $path" >&2
			failed=1
			;;
		50415231)
			echo "privacy-check: renamed parquet data content: $path" >&2
			failed=1
			;;
		504c5348)
			echo "privacy-check: renamed PALISADE shadow log content: $path" >&2
			failed=1
			;;
	esac
	if LC_ALL=C head -c 15 "$blob_file" | grep -a -q '^SQLite format 3$'; then
		echo "privacy-check: renamed SQLite data content: $path" >&2
		failed=1
	fi
	first_nonspace=$(LC_ALL=C awk 'match($0, /[^[:space:]]/) { print substr($0, RSTART, 1); exit }' "$blob_file")
	is_json_document=0
	case "$first_nonspace" in
		'{'|'[') is_json_document=1 ;;
	esac

	credential_marker='-----BEGIN ([A-Z0-9 ]+ )?PRIVATE KEY-----|[Aa]uthorization:[[:space:]]*[Bb]earer[[:space:]]+[A-Za-z0-9_./+=-]{12,}|([Pp]assword|[Aa]pi[_-]?[Kk]ey)[=:][[:space:]]*[A-Za-z0-9_./+=-]{16,}'
	if [ "$path" != "scripts/privacy-check.sh" ] && grep -I -q -E -- "$credential_marker" "$blob_file"; then
		echo "privacy-check: possible private key or credential marker: $path" >&2
		failed=1
	fi
	if [ "$path" != "scripts/privacy-check.sh" ] && grep -I -q -E -- '^[A-Za-z0-9_-]{86}$' "$blob_file"; then
		echo "privacy-check: possible raw Ed25519 private key: $path" >&2
		failed=1
	fi

	if [ "$is_json_document" -eq 1 ] && grep -I -q -E -- '"schema_version"[[:space:]]*:[[:space:]]*"palisade\.offline-(event|manifest)\.v1"' "$blob_file"; then
		echo "privacy-check: normalized offline data content: $path" >&2
		failed=1
	fi
	if [ "$is_json_document" -eq 1 ] && grep -I -q -E -- '"schema_version"[[:space:]]*:[[:space:]]*"palisade\.shadow-analysis\.v(1|2)"' "$blob_file"; then
		echo "privacy-check: generated shadow analysis report: $path" >&2
		failed=1
	fi
	if [ "$is_json_document" -eq 1 ] && grep -I -q -E -- '"schema_version"[[:space:]]*:[[:space:]]*"palisade\.rollout-plan\.v1"' "$blob_file"; then
		echo "privacy-check: signed deployment rollout plan: $path" >&2
		failed=1
	fi
	if [ "$is_json_document" -eq 1 ] && grep -I -q -E -- '"schema_version"[[:space:]]*:[[:space:]]*"palisade\.rollout-review\.v(1|2)"' "$blob_file"; then
		echo "privacy-check: generated rollout review proposal: $path" >&2
		failed=1
	fi
	if grep -I -q -E -- '^[0-9A-Fa-f:.]+ - - \[[0-9]{2}/[A-Za-z]{3}/[0-9]{4}:[0-9]{2}:[0-9]{2}:[0-9]{2} [+-][0-9]{4}\] "[A-Z]+ ' "$blob_file"; then
		echo "privacy-check: renamed access-log data content: $path" >&2
		failed=1
	fi
	if [ "$is_json_document" -eq 1 ] && grep -I -q -E -- '"(x-real-ip|x_real_ip|source_ip|request_uri|scenario)"[[:space:]]*:' "$blob_file"; then
		echo "privacy-check: renamed raw JSON data content: $path" >&2
		failed=1
	fi
	if [ "$is_json_document" -eq 1 ] && grep -I -q -E -- '"(remote_addr|remote_address|peer_ip)"[[:space:]]*:' "$blob_file" && grep -I -q -E -- '"(request|path|uri|request_uri|user_agent|challenge|check_result|observed_at|timestamp)"[[:space:]]*:' "$blob_file"; then
		echo "privacy-check: renamed direct-peer JSON data content: $path" >&2
		failed=1
	fi
	if [ "$is_json_document" -eq 1 ]; then
		crowdsec_nested=0
		if grep -I -q -E -- '"decision"[[:space:]]*:[[:space:]]*\{' "$blob_file" && grep -I -q -E -- '"type"[[:space:]]*:[[:space:]]*"ip"' "$blob_file" && grep -I -q -E -- '"value"[[:space:]]*:' "$blob_file" && grep -I -q -E -- '"(start_at|created_at|observed_at)"[[:space:]]*:' "$blob_file"; then
			crowdsec_nested=1
		elif grep -I -q -E -- '"alert"[[:space:]]*:[[:space:]]*\{' "$blob_file" && grep -I -q -E -- '"(start_at|created_at|observed_at)"[[:space:]]*:' "$blob_file" && grep -I -q -E -- '"source"[[:space:]]*:[[:space:]]*\{' "$blob_file" && grep -I -q -E -- '"ip"[[:space:]]*:' "$blob_file"; then
			crowdsec_nested=1
		fi
		if [ "$crowdsec_nested" -eq 1 ]; then
			echo "privacy-check: renamed nested policy JSON data content: $path" >&2
			failed=1
		fi
		if grep -I -q -E -- '"type"[[:space:]]*:[[:space:]]*"ip"' "$blob_file" && grep -I -q -E -- '"value"[[:space:]]*:[[:space:]]*"[0-9A-Fa-f:.]+"' "$blob_file" && grep -I -q -E -- '"(start_at|created_at|observed_at)"[[:space:]]*:' "$blob_file"; then
			echo "privacy-check: renamed IP policy JSON data content: $path" >&2
			failed=1
		fi
	fi
done <"$index_list"

if [ "$failed" -ne 0 ]; then
	exit 1
fi

echo "privacy-check: Git index blobs passed"
