package sovereignty

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
)

type runtimeEgressManifest struct {
	SchemaVersion  string `json:"schema_version"`
	Scope          string `json:"scope"`
	DefaultPosture string `json:"default_posture"`
	Entries        []struct {
		ID                           string   `json:"id"`
		SourcePaths                  []string `json:"source_paths"`
		MandatoryVendorService       bool     `json:"mandatory_vendor_service"`
		DataClasses                  []string `json:"data_classes"`
		RawNetworkIdentifiersAllowed bool     `json:"raw_network_identifiers_allowed"`
	} `json:"entries"`
	ExplicitlyAbsent []string `json:"explicitly_absent"`
}

type dataMapManifest struct {
	SchemaVersion string `json:"schema_version"`
	Scope         string `json:"scope"`
	DefaultRules  struct {
		ExternalExport        bool   `json:"external_export"`
		RawNetworkIdentifiers string `json:"raw_network_identifiers"`
		ContentCollection     string `json:"content_collection"`
		MissingBrowserSensor  string `json:"missing_browser_sensor"`
	} `json:"default_rules"`
	TransientLocalInputClasses []string `json:"transient_local_input_classes"`
	Flows                      []struct {
		ID                   string   `json:"id"`
		DataClasses          []string `json:"data_classes"`
		TransientDataClasses []string `json:"transient_data_classes"`
		NetworkScope         string   `json:"network_scope"`
		Persistence          string   `json:"persistence"`
		ExternalExport       bool     `json:"external_export"`
	} `json:"flows"`
	RawClassesExcluded []string `json:"raw_classes_excluded"`
}

func TestRuntimeEgressManifestMatchesReviewedSourceCallsites(t *testing.T) {
	root := repositoryRoot(t)
	var manifest runtimeEgressManifest
	readRepositoryJSON(t, root, "manifests/runtime-egress-v1.json", &manifest)
	if manifest.SchemaVersion != "palisade.runtime-egress.v1" || manifest.Scope != "reference_repository_runtime" || manifest.DefaultPosture != "no_mandatory_vendor_egress" {
		t.Fatalf("unexpected runtime egress header: %+v", manifest)
	}

	wantGo := map[string][]string{
		"pkg/palisadehttp/challenge.go": {"client_do", "http_new_request_with_context"},
		"pkg/palisadehttp/client.go":    {"client_do", "http_default_client", "http_new_request_with_context"},
		"pkg/palisadeproxy/proxy.go":    {"client_do", "http_default_client", "http_new_request_with_context"},
	}
	if got := scanGoOutboundCallsites(t, root); !reflect.DeepEqual(got, wantGo) {
		t.Fatalf("review runtime egress and update manifest/test allowlist:\ngot  %#v\nwant %#v", got, wantGo)
	}
	wantBrowser := map[string][]string{
		"dashboard/src/App.tsx":         {"fetch"},
		"pkg/palisadehttp/challenge.go": {"fetch"},
		"sensor/src/index.ts":           {"fetch_binding", "send_beacon"},
	}
	if got := scanBrowserOutboundCallsites(t, root); !reflect.DeepEqual(got, wantBrowser) {
		t.Fatalf("review browser egress and update manifest/test allowlist:\ngot  %#v\nwant %#v", got, wantBrowser)
	}

	wantPathSet := map[string]bool{}
	for path := range wantGo {
		wantPathSet[path] = true
	}
	for path := range wantBrowser {
		wantPathSet[path] = true
	}
	wantPaths := sortedKeys(wantPathSet)
	manifestPathSet := map[string]bool{}
	seenIDs := map[string]bool{}
	for _, entry := range manifest.Entries {
		if entry.ID == "" || seenIDs[entry.ID] {
			t.Fatalf("empty or duplicate runtime egress id %q", entry.ID)
		}
		seenIDs[entry.ID] = true
		if entry.MandatoryVendorService || entry.RawNetworkIdentifiersAllowed || len(entry.DataClasses) == 0 {
			t.Fatalf("unsafe runtime egress entry: %+v", entry)
		}
		if entry.ID == "origin_adapter_to_palisade" && !slices.Contains(entry.DataClasses, "one_time_origin_flow_binding") {
			t.Fatalf("origin adapter egress omits the challenge flow binding: %+v", entry)
		}
		for _, path := range entry.SourcePaths {
			manifestPathSet[path] = true
		}
	}
	manifestPaths := sortedKeys(manifestPathSet)
	if !reflect.DeepEqual(manifestPaths, wantPaths) {
		t.Fatalf("manifest source_paths = %#v, want reviewed callsites %#v", manifestPaths, wantPaths)
	}
	for _, absent := range []string{"reference_decision_service_outbound_runtime_client", "mandatory_palisade_control_plane", "mandatory_telemetry_export"} {
		if !slices.Contains(manifest.ExplicitlyAbsent, absent) {
			t.Fatalf("manifest no longer declares %q absent", absent)
		}
	}
}

func TestDataMapIsClosedAndContainsNoRawAcceptedClass(t *testing.T) {
	root := repositoryRoot(t)
	var manifest dataMapManifest
	readRepositoryJSON(t, root, "manifests/data-map-v6.json", &manifest)
	if manifest.SchemaVersion != "palisade.data-map.v6" || manifest.Scope != "reference_product_data_flows" ||
		manifest.DefaultRules.ExternalExport || manifest.DefaultRules.RawNetworkIdentifiers != "excluded_from_runtime_and_persisted_output" ||
		manifest.DefaultRules.ContentCollection != "excluded" || manifest.DefaultRules.MissingBrowserSensor != "neutral" {
		t.Fatalf("unexpected data map defaults: %+v", manifest.DefaultRules)
	}
	wantFlowIDs := []string{
		"aggregate_analysis", "browser_event_ingest", "continuity_cookie", "decision_request",
		"delayed_outcome", "local_evidence_import", "local_holdout_evaluation", "local_sequence_analysis", "native_challenge_lifecycle", "native_decoy_lifecycle", "operator_console_summary", "origin_challenge_binding", "shadow_measurement", "sovereignty_report",
	}
	wantDirectReferences := []string{"operator_session_reference_may_be_personal_data", "operator_subject_reference_may_include_network_identifier"}
	wantSequenceLinkage := []string{"daily_rotating_pseudonym_for_sequence_linkage"}
	wantHoldoutInputs := []string{"daily_rotating_pseudonym_for_sequence_linkage", "operator_attack_family_reference"}
	wantTransient := append(append(append([]string(nil), wantSequenceLinkage...), "operator_attack_family_reference"), wantDirectReferences...)
	slices.Sort(manifest.TransientLocalInputClasses)
	slices.Sort(wantTransient)
	if !reflect.DeepEqual(manifest.TransientLocalInputClasses, wantTransient) {
		t.Fatalf("transient local input classes = %#v, want %#v", manifest.TransientLocalInputClasses, wantTransient)
	}
	seen := map[string]bool{}
	for _, flow := range manifest.Flows {
		if flow.ID == "" || seen[flow.ID] || flow.ExternalExport || flow.NetworkScope == "" || flow.Persistence == "" || len(flow.DataClasses) == 0 {
			t.Fatalf("invalid or duplicate data flow: %+v", flow)
		}
		seen[flow.ID] = true
		for _, class := range flow.DataClasses {
			if slices.Contains(manifest.RawClassesExcluded, class) {
				t.Fatalf("flow %q accepts excluded raw class %q", flow.ID, class)
			}
		}
		if flow.ID == "local_evidence_import" {
			slices.Sort(flow.TransientDataClasses)
			if !reflect.DeepEqual(flow.TransientDataClasses, wantDirectReferences) || flow.NetworkScope != "local_filesystem_only" {
				t.Fatalf("local import transient boundary is incomplete: %+v", flow)
			}
		} else if flow.ID == "local_sequence_analysis" {
			if !reflect.DeepEqual(flow.TransientDataClasses, wantSequenceLinkage) || flow.NetworkScope != "local_filesystem_only" || flow.Persistence != "operator_controlled_owner_only_artifact" {
				t.Fatalf("local sequence-analysis boundary is incomplete: %+v", flow)
			}
		} else if flow.ID == "local_holdout_evaluation" {
			if !reflect.DeepEqual(flow.TransientDataClasses, wantHoldoutInputs) || flow.NetworkScope != "local_filesystem_only" || flow.Persistence != "operator_controlled_owner_only_artifact" {
				t.Fatalf("local holdout boundary is incomplete: %+v", flow)
			}
		} else if flow.ID == "origin_challenge_binding" {
			if !reflect.DeepEqual(flow.DataClasses, []string{"one_time_origin_flow_binding"}) || flow.NetworkScope != "operator_configured_internal_endpoint" || flow.Persistence != "bounded_memory_fifteen_minutes" {
				t.Fatalf("origin challenge binding boundary is incomplete: %+v", flow)
			}
		} else if len(flow.TransientDataClasses) != 0 {
			t.Fatalf("unexpected transient input classes on flow %q: %#v", flow.ID, flow.TransientDataClasses)
		}
	}
	if got := sortedKeys(seen); !reflect.DeepEqual(got, wantFlowIDs) {
		t.Fatalf("data map flow ids = %#v, want %#v", got, wantFlowIDs)
	}
	for _, required := range []string{"ip_address", "request_body", "request_url", "user_agent", "vendor_payload"} {
		if !slices.Contains(manifest.RawClassesExcluded, required) {
			t.Fatalf("raw exclusion %q is missing", required)
		}
	}
}

func TestSovereigntyRepositorySchemasAreValidJSON(t *testing.T) {
	root := repositoryRoot(t)
	for _, path := range []string{
		"schemas/adversarial-suite-v1.schema.json",
		"schemas/compatibility-freeze-v1.schema.json",
		"schemas/adversarial-holdout-suite-v1.schema.json",
		"schemas/data-map-v1.schema.json",
		"schemas/data-map-v2.schema.json",
		"schemas/data-map-v3.schema.json",
		"schemas/data-map-v4.schema.json",
		"schemas/data-map-v5.schema.json",
		"schemas/data-map-v6.schema.json",
		"schemas/edge-signal-envelope-v1.schema.json",
		"schemas/local-evidence-event-v1.schema.json",
		"schemas/local-family-annotation-v1.schema.json",
		"schemas/local-evidence-input-v1.schema.json",
		"schemas/local-evidence-manifest-v1.schema.json",
		"schemas/local-holdout-report-v1.schema.json",
		"schemas/local-sequence-report-v1.schema.json",
		"schemas/local-release-v1.schema.json",
		"schemas/normalized-signal-contract-v1.schema.json",
		"schemas/origin-adapter-conformance-v1.schema.json",
		"schemas/red-team-suite-v1.schema.json",
		"schemas/release-reproduction-v1.schema.json",
		"schemas/runtime-egress-v1.schema.json",
		"schemas/rollout-plan-v2.schema.json",
		"schemas/rollout-review-v4.schema.json",
		"schemas/shadow-analysis-report-v4.schema.json",
		"schemas/shadow-holdout-report-v1.schema.json",
		"schemas/sovereignty-report-v1.schema.json",
		"schemas/synthetic-benchmark-report-v1.schema.json",
		"schemas/synthetic-red-team-findings-v1.schema.json",
	} {
		var schema map[string]any
		readRepositoryJSON(t, root, path, &schema)
		if schema["$schema"] != "https://json-schema.org/draft/2020-12/schema" || schema["$id"] == "" {
			t.Fatalf("schema %s has no closed draft/id declaration", path)
		}
	}
}

func scanGoOutboundCallsites(t *testing.T, root string) map[string][]string {
	t.Helper()
	result := map[string]map[string]bool{}
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if entry.Name() == ".git" || entry.Name() == "node_modules" || entry.Name() == "dist" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		parsed, parseErr := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if parseErr != nil {
			return parseErr
		}
		imports := map[string]string{}
		for _, spec := range parsed.Imports {
			importPath, unquoteErr := strconv.Unquote(spec.Path.Value)
			if unquoteErr != nil {
				return unquoteErr
			}
			name := filepath.Base(importPath)
			if spec.Name != nil {
				name = spec.Name.Name
			}
			imports[name] = importPath
		}
		relative, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		relative = filepath.ToSlash(relative)
		add := func(kind string) {
			if result[relative] == nil {
				result[relative] = map[string]bool{}
			}
			result[relative][kind] = true
		}
		ast.Inspect(parsed, func(node ast.Node) bool {
			if composite, ok := node.(*ast.CompositeLit); ok {
				if selector, selected := composite.Type.(*ast.SelectorExpr); selected {
					if identifier, direct := selector.X.(*ast.Ident); direct {
						switch imports[identifier.Name] {
						case "net/http":
							if selector.Sel.Name == "Client" || selector.Sel.Name == "Transport" {
								add("http_" + snakeCase(selector.Sel.Name) + "_literal")
							}
						case "net":
							if selector.Sel.Name == "Dialer" {
								add("net_dialer_literal")
							}
						}
					}
				}
			}
			selector, ok := node.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if identifier, direct := selector.X.(*ast.Ident); direct {
				switch imports[identifier.Name] {
				case "net/http":
					switch selector.Sel.Name {
					case "DefaultClient", "DefaultTransport":
						add("http_default_client")
					case "Get", "Head", "Post", "PostForm", "NewRequest", "NewRequestWithContext":
						add("http_" + snakeCase(selector.Sel.Name))
					}
				case "net":
					if selector.Sel.Name == "Dial" || selector.Sel.Name == "DialTimeout" {
						add("net_" + snakeCase(selector.Sel.Name))
					}
				case "crypto/tls":
					if selector.Sel.Name == "Dial" || selector.Sel.Name == "DialWithDialer" {
						add("tls_" + snakeCase(selector.Sel.Name))
					}
				}
			}
			if selector.Sel.Name == "Do" || selector.Sel.Name == "RoundTrip" {
				add("client_" + snakeCase(selector.Sel.Name))
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return flattenSets(result)
}

func scanBrowserOutboundCallsites(t *testing.T, root string) map[string][]string {
	t.Helper()
	patterns := map[string]*regexp.Regexp{
		"fetch":         regexp.MustCompile(`\bfetch\s*\(`),
		"fetch_binding": regexp.MustCompile(`fetchImpl\s*\?\?\s*fetch\b`),
		"send_beacon":   regexp.MustCompile(`\bsendBeacon\s*\?\.?\s*\(`),
		"xml_http":      regexp.MustCompile(`\bXMLHttpRequest\b`),
		"web_socket":    regexp.MustCompile(`\bWebSocket\s*\(`),
		"event_source":  regexp.MustCompile(`\bEventSource\s*\(`),
	}
	result := map[string]map[string]bool{}
	for _, directory := range []string{"sensor/src", "dashboard/src", "website/src"} {
		err := filepath.WalkDir(filepath.Join(root, filepath.FromSlash(directory)), func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() || strings.Contains(entry.Name(), ".test.") || strings.Contains(entry.Name(), ".spec.") ||
				(!strings.HasSuffix(path, ".ts") && !strings.HasSuffix(path, ".tsx")) {
				return nil
			}
			content, readErr := os.ReadFile(path)
			if readErr != nil {
				return readErr
			}
			relative, relErr := filepath.Rel(root, path)
			if relErr != nil {
				return relErr
			}
			relative = filepath.ToSlash(relative)
			for kind, pattern := range patterns {
				if pattern.Match(content) {
					if result[relative] == nil {
						result[relative] = map[string]bool{}
					}
					result[relative][kind] = true
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	embeddedPath := filepath.Join(root, "pkg", "palisadehttp", "challenge.go")
	embedded, err := os.ReadFile(embeddedPath)
	if err != nil {
		t.Fatal(err)
	}
	if patterns["fetch"].Match(embedded) {
		result["pkg/palisadehttp/challenge.go"] = map[string]bool{"fetch": true}
	}
	return flattenSets(result)
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, current, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate sovereignty test source")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(current), "..", ".."))
}

func readRepositoryJSON(t *testing.T, root, relative string, destination any) {
	t.Helper()
	encoded, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(relative)))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(encoded, destination); err != nil {
		t.Fatalf("decode %s: %v", relative, err)
	}
}

func flattenSets(input map[string]map[string]bool) map[string][]string {
	output := make(map[string][]string, len(input))
	for path, kinds := range input {
		output[path] = sortedKeys(kinds)
	}
	return output
}

func sortedKeys[T any](input map[string]T) []string {
	output := make([]string, 0, len(input))
	for key := range input {
		output = append(output, key)
	}
	slices.Sort(output)
	return output
}

func snakeCase(value string) string {
	var builder strings.Builder
	for index, character := range value {
		if index > 0 && character >= 'A' && character <= 'Z' {
			builder.WriteByte('_')
		}
		builder.WriteRune(character)
	}
	return strings.ToLower(builder.String())
}
