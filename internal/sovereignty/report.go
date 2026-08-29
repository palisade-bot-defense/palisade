// Package sovereignty exposes PALISADE's product-level data-sovereignty
// contract separately from deployment facts that only an operator can attest.
package sovereignty

import (
	"fmt"
	"slices"
)

const (
	SchemaVersion = "palisade.sovereignty-report.v1"

	NotDeclared = "not_declared"
)

var (
	processingLocations = []string{NotDeclared, "on_prem_eu", "eu_region", "on_prem_non_eu", "non_eu_region", "mixed"}
	storageLocations    = []string{NotDeclared, "none", "same_as_processing", "eu_only", "non_eu_or_mixed"}
	externalServices    = []string{NotDeclared, "none", "present"}
	operatorHeldKeys    = []string{NotDeclared, "yes", "no"}
)

// Declaration contains only closed, non-identifying operator attestations. It
// deliberately excludes free-form deployment names, provider names and paths.
type Declaration struct {
	ProcessingLocation      string `json:"processing_location"`
	StorageLocation         string `json:"storage_location"`
	ExternalRuntimeServices string `json:"external_runtime_services"`
	OperatorHeldKeys        string `json:"operator_held_keys"`
}

type Product struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type ProductInvariants struct {
	MandatoryVendorControlPlane  bool   `json:"mandatory_vendor_control_plane"`
	MandatoryTelemetryExport     bool   `json:"mandatory_telemetry_export"`
	MandatoryExternalRuntimeCall bool   `json:"mandatory_external_runtime_call"`
	DecisionAPIInput             string `json:"decision_api_input"`
	RawNetworkIdentifiers        string `json:"raw_network_identifiers"`
	BrowserCollection            string `json:"browser_collection"`
	Evaluation                   string `json:"evaluation"`
	DecisionExplanation          string `json:"decision_explanation"`
	EnforcementPromotion         string `json:"enforcement_promotion"`
}

type DeploymentDeclaration struct {
	Status string `json:"status"`
	Declaration
}

type Assessment struct {
	ProductHasNoMandatoryVendorEgress bool     `json:"product_has_no_mandatory_vendor_egress"`
	DeploymentPosture                 string   `json:"deployment_posture"`
	Reasons                           []string `json:"reasons"`
}

type Report struct {
	SchemaVersion         string                `json:"schema_version"`
	Product               Product               `json:"product"`
	ProductInvariants     ProductInvariants     `json:"product_invariants"`
	DeploymentDeclaration DeploymentDeclaration `json:"deployment_declaration"`
	Assessment            Assessment            `json:"assessment"`
	Limitations           []string              `json:"limitations"`
}

// NewReport validates the closed declaration and returns a deterministic
// report. No timestamp or environment metadata is included so identical input
// and software versions produce byte-stable JSON.
func NewReport(version string, declaration Declaration) (Report, error) {
	if err := validateDeclaration(declaration); err != nil {
		return Report{}, err
	}

	status := "complete"
	if declaration.ProcessingLocation == NotDeclared ||
		declaration.StorageLocation == NotDeclared ||
		declaration.ExternalRuntimeServices == NotDeclared ||
		declaration.OperatorHeldKeys == NotDeclared {
		status = "incomplete"
	}

	posture, reasons := assess(declaration, status)
	return Report{
		SchemaVersion: SchemaVersion,
		Product:       Product{Name: "PALISADE", Version: version},
		ProductInvariants: ProductInvariants{
			MandatoryVendorControlPlane:  false,
			MandatoryTelemetryExport:     false,
			MandatoryExternalRuntimeCall: false,
			DecisionAPIInput:             "closed_normalized_signals",
			RawNetworkIdentifiers:        "rejected_by_public_decision_api",
			BrowserCollection:            "bounded_counts_without_content_or_exact_coordinates",
			Evaluation:                   "optional_local_encrypted",
			DecisionExplanation:          "stable_reason_codes_and_versions",
			EnforcementPromotion:         "signed_scoped_expiring_rollout",
		},
		DeploymentDeclaration: DeploymentDeclaration{Status: status, Declaration: declaration},
		Assessment: Assessment{
			ProductHasNoMandatoryVendorEgress: true,
			DeploymentPosture:                 posture,
			Reasons:                           reasons,
		},
		Limitations: []string{
			"deployment values are operator-declared and are not technically verified by this report",
			"this report is a product inventory, not network-capture evidence or a legal compliance certificate",
			"hosting, adapters, monitoring, reputation services and support arrangements require a separate assessment",
		},
	}, nil
}

func validateDeclaration(declaration Declaration) error {
	checks := []struct {
		name    string
		value   string
		allowed []string
	}{
		{"processing-location", declaration.ProcessingLocation, processingLocations},
		{"storage-location", declaration.StorageLocation, storageLocations},
		{"external-runtime-services", declaration.ExternalRuntimeServices, externalServices},
		{"operator-held-keys", declaration.OperatorHeldKeys, operatorHeldKeys},
	}
	for _, check := range checks {
		if !slices.Contains(check.allowed, check.value) {
			return fmt.Errorf("--%s must be one of %v", check.name, check.allowed)
		}
	}
	return nil
}

func assess(declaration Declaration, status string) (string, []string) {
	if status != "complete" {
		return "insufficient_declaration", []string{"one or more deployment fields are not declared"}
	}

	euProcessing := declaration.ProcessingLocation == "on_prem_eu" || declaration.ProcessingLocation == "eu_region"
	euStorage := declaration.StorageLocation == "none" || declaration.StorageLocation == "same_as_processing" || declaration.StorageLocation == "eu_only"
	noExternalRuntime := declaration.ExternalRuntimeServices == "none"
	localKeys := declaration.OperatorHeldKeys == "yes"
	if euProcessing && euStorage && noExternalRuntime && localKeys {
		return "operator_attested_eu_bound", []string{
			"processing is declared on operator-selected EU infrastructure",
			"storage is declared absent, colocated with EU processing or EU-only",
			"no external runtime service is declared",
			"keys are declared operator-held",
		}
	}

	reasons := make([]string, 0, 4)
	if !euProcessing {
		reasons = append(reasons, "processing is not declared EU-only")
	}
	if !euStorage {
		reasons = append(reasons, "storage is not declared absent or EU-only")
	}
	if !noExternalRuntime {
		reasons = append(reasons, "an external runtime service is declared")
	}
	if !localKeys {
		reasons = append(reasons, "keys are not declared operator-held")
	}
	return "operator_review_required", reasons
}
