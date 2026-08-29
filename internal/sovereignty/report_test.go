package sovereignty

import (
	"reflect"
	"strings"
	"testing"
)

func TestIncompleteDeclarationCannotClaimEUBoundPosture(t *testing.T) {
	report, err := NewReport("test", Declaration{
		ProcessingLocation:      NotDeclared,
		StorageLocation:         NotDeclared,
		ExternalRuntimeServices: NotDeclared,
		OperatorHeldKeys:        NotDeclared,
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.DeploymentDeclaration.Status != "incomplete" || report.Assessment.DeploymentPosture != "insufficient_declaration" {
		t.Fatalf("unexpected incomplete assessment: %+v", report.Assessment)
	}
	if report.ProductInvariants.MandatoryTelemetryExport || report.ProductInvariants.MandatoryVendorControlPlane {
		t.Fatalf("mandatory vendor dependency reported: %+v", report.ProductInvariants)
	}
}

func TestCompleteEUDeclarationProducesBoundedAttestation(t *testing.T) {
	report, err := NewReport("test", Declaration{
		ProcessingLocation:      "eu_region",
		StorageLocation:         "eu_only",
		ExternalRuntimeServices: "none",
		OperatorHeldKeys:        "yes",
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.DeploymentDeclaration.Status != "complete" || report.Assessment.DeploymentPosture != "operator_attested_eu_bound" {
		t.Fatalf("unexpected EU assessment: %+v", report.Assessment)
	}
	wantReasons := []string{
		"processing is declared on operator-selected EU infrastructure",
		"storage is declared absent, colocated with EU processing or EU-only",
		"no external runtime service is declared",
		"keys are declared operator-held",
	}
	if !reflect.DeepEqual(report.Assessment.Reasons, wantReasons) {
		t.Fatalf("reasons = %#v, want %#v", report.Assessment.Reasons, wantReasons)
	}
	for _, limitation := range report.Limitations {
		if strings.Contains(strings.ToLower(limitation), "certified") {
			t.Fatalf("report implies certification: %q", limitation)
		}
	}
}

func TestDeclarationVocabularyIsClosed(t *testing.T) {
	_, err := NewReport("test", Declaration{
		ProcessingLocation:      "customer-name-or-free-text",
		StorageLocation:         NotDeclared,
		ExternalRuntimeServices: NotDeclared,
		OperatorHeldKeys:        NotDeclared,
	})
	if err == nil || !strings.Contains(err.Error(), "--processing-location") {
		t.Fatalf("invalid declaration error = %v", err)
	}
}
