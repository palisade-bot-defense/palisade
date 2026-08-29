#!/bin/sh
set -eu

guard=$(cd "$(dirname "$0")" && pwd)/privacy-check.sh
test_root=$(mktemp -d "${TMPDIR:-/tmp}/palisade-privacy-test.XXXXXX")
trap 'rm -rf "$test_root"' EXIT HUP INT TERM

new_repo() {
	case_dir=$1
	mkdir "$case_dir"
	git -C "$case_dir" init -q
	git -C "$case_dir" config user.email synthetic@example.invalid
	git -C "$case_dir" config user.name Synthetic
}

clean="$test_root/clean"
new_repo "$clean"
printf '%s\n' 'synthetic source' >"$clean/source.txt"
git -C "$clean" add source.txt
(cd "$clean" && "$guard") >/dev/null

source_fixture="$test_root/source-fixture"
new_repo "$source_fixture"
mkdir -p "$source_fixture/internal/offlineimport"
printf '%s\n' 'package offlineimport' 'var syntheticFixture = `{"schema_version":"palisade.offline-event.v1","scenario":"synthetic/example"}`' >"$source_fixture/internal/offlineimport/importer_test.go"
git -C "$source_fixture" add internal/offlineimport/importer_test.go
(cd "$source_fixture" && "$guard") >/dev/null

exact_path_bypass="$test_root/exact-path-bypass"
new_repo "$exact_path_bypass"
mkdir -p "$exact_path_bypass/internal/offlineimport"
printf '%s\n' '{"schema_version":"palisade.offline-event.v1","scenario":"synthetic/example"}' >"$exact_path_bypass/internal/offlineimport/importer_test.go"
git -C "$exact_path_bypass" add internal/offlineimport/importer_test.go
if (cd "$exact_path_bypass" && "$guard") >/dev/null 2>&1; then
	echo "privacy-check test: data artifact bypassed checks at an exact fixture-source path" >&2
	exit 1
fi

raw="$test_root/raw"
new_repo "$raw"
printf '%s\n' '192.0.2.10 - - [12/Jan/2026:01:02:03 +0000] "GET /synthetic HTTP/1.1" 200 1' >"$raw/renamed.txt"
git -C "$raw" add renamed.txt
if (cd "$raw" && "$guard") >/dev/null 2>&1; then
	echo "privacy-check test: renamed access data was accepted" >&2
	exit 1
fi

raw_json="$test_root/raw-json"
new_repo "$raw_json"
printf '%s\n' '[{"scenario":"synthetic/example","source_ip":"192.0.2.10"}]' >"$raw_json/renamed.txt"
git -C "$raw_json" add renamed.txt
if (cd "$raw_json" && "$guard") >/dev/null 2>&1; then
	echo "privacy-check test: renamed raw JSON data was accepted" >&2
	exit 1
fi

renamed_anubis="$test_root/renamed-anubis"
new_repo "$renamed_anubis"
printf '%s\n' '{"observed_at":"2026-01-12T01:01:00Z","request":{"remote_addr":"192.0.2.10","path":"/synthetic","user_agent":"SyntheticFixture/1.0"}}' >"$renamed_anubis/renamed.txt"
git -C "$renamed_anubis" add renamed.txt
if (cd "$renamed_anubis" && "$guard") >/dev/null 2>&1; then
	echo "privacy-check test: renamed direct-peer JSON data was accepted" >&2
	exit 1
fi

renamed_decision="$test_root/renamed-decision"
new_repo "$renamed_decision"
printf '%s\n' '{"decision":{"type":"ip","value":"192.0.2.10","start_at":"2026-01-12T01:03:00Z"}}' >"$renamed_decision/renamed.txt"
git -C "$renamed_decision" add renamed.txt
if (cd "$renamed_decision" && "$guard") >/dev/null 2>&1; then
	echo "privacy-check test: renamed nested decision JSON data was accepted" >&2
	exit 1
fi

renamed_top_level_decision="$test_root/renamed-top-level-decision"
new_repo "$renamed_top_level_decision"
printf '%s\n' '[{"created_at":"2026-01-12T01:03:00Z","type":"ip","value":"192.0.2.10"}]' >"$renamed_top_level_decision/renamed.txt"
git -C "$renamed_top_level_decision" add renamed.txt
if (cd "$renamed_top_level_decision" && "$guard") >/dev/null 2>&1; then
	echo "privacy-check test: renamed top-level IP decision JSON data was accepted" >&2
	exit 1
fi

renamed_gzip="$test_root/renamed-gzip"
new_repo "$renamed_gzip"
printf '\037\213synthetic' >"$renamed_gzip/renamed.txt"
git -C "$renamed_gzip" add renamed.txt
if (cd "$renamed_gzip" && "$guard") >/dev/null 2>&1; then
	echo "privacy-check test: renamed gzip data was accepted" >&2
	exit 1
fi

shadow_extension="$test_root/shadow-extension"
new_repo "$shadow_extension"
printf '%s\n' 'synthetic encrypted shadow fixture' >"$shadow_extension/captured.plog"
git -C "$shadow_extension" add captured.plog
if (cd "$shadow_extension" && "$guard") >/dev/null 2>&1; then
	echo "privacy-check test: shadow log extension was accepted" >&2
	exit 1
fi

renamed_shadow="$test_root/renamed-shadow"
new_repo "$renamed_shadow"
printf 'PLSHDW1\nsynthetic' >"$renamed_shadow/renamed.bin"
git -C "$renamed_shadow" add renamed.bin
if (cd "$renamed_shadow" && "$guard") >/dev/null 2>&1; then
	echo "privacy-check test: renamed shadow log content was accepted" >&2
	exit 1
fi

normalized="$test_root/normalized"
new_repo "$normalized"
printf '%s\n' '{"schema_version":"palisade.offline-manifest.v1"}' >"$normalized/innocent.txt"
git -C "$normalized" add innocent.txt
if (cd "$normalized" && "$guard") >/dev/null 2>&1; then
	echo "privacy-check test: renamed normalized data was accepted" >&2
	exit 1
fi

local_evidence="$test_root/local-evidence"
new_repo "$local_evidence"
printf '%s\n' '{"schema_version":"palisade.local-evidence-event.v1","subject_id":"synthetic"}' >"$local_evidence/renamed.txt"
git -C "$local_evidence" add renamed.txt
if (cd "$local_evidence" && "$guard") >/dev/null 2>&1; then
	echo "privacy-check test: renamed local evidence data was accepted" >&2
	exit 1
fi

local_evidence_input="$test_root/local-evidence-input"
new_repo "$local_evidence_input"
printf '%s\n' '{"schema_version":"palisade.local-evidence-input.v1","subject_ref":"synthetic-personal-reference"}' >"$local_evidence_input/renamed.txt"
git -C "$local_evidence_input" add renamed.txt
if (cd "$local_evidence_input" && "$guard") >/dev/null 2>&1; then
	echo "privacy-check test: renamed local evidence input was accepted" >&2
	exit 1
fi

local_sequence_report="$test_root/local-sequence-report"
new_repo "$local_sequence_report"
printf '%s\n' '{"schema_version":"palisade.local-sequence-report.v1","source":{"events":42}}' >"$local_sequence_report/renamed.txt"
git -C "$local_sequence_report" add renamed.txt
if (cd "$local_sequence_report" && "$guard") >/dev/null 2>&1; then
	echo "privacy-check test: generated local sequence report was accepted" >&2
	exit 1
fi

local_holdout_report="$test_root/local-holdout-report"
new_repo "$local_holdout_report"
printf '%s\n' '{"schema_version":"palisade.local-holdout-report.v1","source":{"events":42}}' >"$local_holdout_report/renamed.txt"
git -C "$local_holdout_report" add renamed.txt
if (cd "$local_holdout_report" && "$guard") >/dev/null 2>&1; then
	echo "privacy-check test: generated local holdout report was accepted" >&2
	exit 1
fi

local_family_annotation="$test_root/local-family-annotation"
new_repo "$local_family_annotation"
printf '%s\n' '{"schema_version":"palisade.local-family-annotation.v1","sequence_kind":"session","sequence_id":"synthetic","family_ref":"synthetic-family"}' >"$local_family_annotation/renamed.txt"
git -C "$local_family_annotation" add renamed.txt
if (cd "$local_family_annotation" && "$guard") >/dev/null 2>&1; then
	echo "privacy-check test: renamed local family annotation was accepted" >&2
	exit 1
fi

shadow_analysis="$test_root/shadow-analysis"
new_repo "$shadow_analysis"
printf '%s\n' '{"schema_version":"palisade.shadow-analysis.v1","source":{"records":42}}' >"$shadow_analysis/renamed.txt"
git -C "$shadow_analysis" add renamed.txt
if (cd "$shadow_analysis" && "$guard") >/dev/null 2>&1; then
	echo "privacy-check test: generated shadow analysis report was accepted" >&2
	exit 1
fi

shadow_analysis_v2="$test_root/shadow-analysis-v2"
new_repo "$shadow_analysis_v2"
printf '%s\n' '{"schema_version":"palisade.shadow-analysis.v2","source":{"records":42}}' >"$shadow_analysis_v2/renamed.txt"
git -C "$shadow_analysis_v2" add renamed.txt
if (cd "$shadow_analysis_v2" && "$guard") >/dev/null 2>&1; then
	echo "privacy-check test: generated v2 shadow analysis report was accepted" >&2
	exit 1
fi

shadow_analysis_v3="$test_root/shadow-analysis-v3"
new_repo "$shadow_analysis_v3"
printf '%s\n' '{"schema_version":"palisade.shadow-analysis.v3","source":{"records":42}}' >"$shadow_analysis_v3/renamed.txt"
git -C "$shadow_analysis_v3" add renamed.txt
if (cd "$shadow_analysis_v3" && "$guard") >/dev/null 2>&1; then
	echo "privacy-check test: generated v3 shadow analysis report was accepted" >&2
	exit 1
fi

rollout_plan="$test_root/rollout-plan"
new_repo "$rollout_plan"
printf '%s\n' '{"plan":{"schema_version":"palisade.rollout-plan.v1"},"signature":"synthetic"}' >"$rollout_plan/renamed.txt"
git -C "$rollout_plan" add renamed.txt
if (cd "$rollout_plan" && "$guard") >/dev/null 2>&1; then
	echo "privacy-check test: signed rollout plan was accepted" >&2
	exit 1
fi

rollout_review="$test_root/rollout-review"
new_repo "$rollout_review"
printf '%s\n' '{"schema_version":"palisade.rollout-review.v1","source_report_sha256":"synthetic"}' >"$rollout_review/renamed.txt"
git -C "$rollout_review" add renamed.txt
if (cd "$rollout_review" && "$guard") >/dev/null 2>&1; then
	echo "privacy-check test: generated rollout review proposal was accepted" >&2
	exit 1
fi

rollout_review_v2="$test_root/rollout-review-v2"
new_repo "$rollout_review_v2"
printf '%s\n' '{"schema_version":"palisade.rollout-review.v2","source_report_sha256":"synthetic"}' >"$rollout_review_v2/renamed.txt"
git -C "$rollout_review_v2" add renamed.txt
if (cd "$rollout_review_v2" && "$guard") >/dev/null 2>&1; then
	echo "privacy-check test: generated v2 rollout review proposal was accepted" >&2
	exit 1
fi

rollout_review_v3="$test_root/rollout-review-v3"
new_repo "$rollout_review_v3"
printf '%s\n' '{"schema_version":"palisade.rollout-review.v3","source_report_sha256":"synthetic"}' >"$rollout_review_v3/renamed.txt"
git -C "$rollout_review_v3" add renamed.txt
if (cd "$rollout_review_v3" && "$guard") >/dev/null 2>&1; then
	echo "privacy-check test: generated v3 rollout review proposal was accepted" >&2
	exit 1
fi

private_key="$test_root/private-key"
new_repo "$private_key"
printf '%s\n' 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' >"$private_key/renamed.txt"
git -C "$private_key" add renamed.txt
if (cd "$private_key" && "$guard") >/dev/null 2>&1; then
	echo "privacy-check test: raw Ed25519 private key was accepted" >&2
	exit 1
fi

symlink="$test_root/symlink"
new_repo "$symlink"
printf '%s\n' 'synthetic' >"$symlink/target.txt"
git -C "$symlink" add target.txt
link_object=$(printf '%s' 'target.txt' | git -C "$symlink" hash-object -w --stdin)
git -C "$symlink" update-index --add --cacheinfo "120000,$link_object,link.txt"
if (cd "$symlink" && "$guard") >/dev/null 2>&1; then
	echo "privacy-check test: tracked symlink was accepted" >&2
	exit 1
fi

echo "privacy-check tests passed"
