// Package agentprovenance classifies how an automated participant identified
// itself. It generalizes the existing verified-for-a-purpose crawler identity
// so that automation is described rather than merely blocked.
//
// The internet PALISADE serves contains people, people using AI tools,
// authorized autonomous agents, organisation-controlled agents, unattributed
// automation and hostile automation. Distinguishing those is the goal; blocking
// everything non-human is not, and would break the accessibility, indexing and
// integration cases the three-score model exists to protect.
//
// Identity is never authorization. A participant with the strongest provenance
// this package can report is still subject to intent, decoy and policy signals,
// and may still be challenged or blocked.
package agentprovenance

import (
	"github.com/palisade-human-trust/palisade/internal/core"
)

const (
	// None means nothing claimed an automated identity.
	None = "none"
	// Declared means an identity was claimed but nothing verified it. A claim
	// is spoofable by construction, so this must never earn an exception.
	Declared = "declared"
	// Authorized means the agent presented proof that a verified human
	// authorized it for a purpose, a scope and an expiry.
	//
	// Nothing in this repository can produce or verify such a grant: it depends
	// on an assurance level above the supported ceiling, since an authorizing
	// human must first be verified. Derive therefore never returns this value,
	// and a test enforces that.
	Authorized = "authorized"
	// VerifiedPurpose means the deployment verified the agent's identity for a
	// narrow declared purpose through the crawler trust chain: a purpose class,
	// a strong local verification method and an indexable public endpoint.
	VerifiedPurpose = "verified_purpose"

	// ReasonDeclaredOnly explains an unverified identity claim.
	ReasonDeclaredOnly = "agent_identity_declared_not_verified"
	// ReasonVerifiedPurpose explains a completed crawler trust chain.
	ReasonVerifiedPurpose = "agent_verified_for_declared_purpose"
	// ReasonPurposeNotPermittedHere explains an identity that verified but was
	// presented on an endpoint its purpose does not cover.
	ReasonPurposeNotPermittedHere = "agent_purpose_not_permitted_on_endpoint"
)

// Result is the derived provenance of one request.
type Result struct {
	// Provenance is one of the closed values above.
	Provenance string
	// Purpose is the declared crawler purpose class, or the empty string when
	// none was claimed. It is recorded for explanation and policy, never as an
	// authorization.
	Purpose string
	// ReasonCodes explain the classification in stable, closed terms.
	ReasonCodes []string
}

// Derive classifies the automated identity presented with one request.
//
// It deliberately reports what was established, not what should be allowed. A
// caller decides what a purpose may do; this function only says how well the
// claim is supported.
func Derive(observations core.Observations, endpointClass string) Result {
	class, classValid := core.NormalizeCrawlerClass(observations.CrawlerClass)
	if !observations.VerifiedBot && (!classValid || class == core.CrawlerClassUnknown) {
		return Result{Provenance: None, ReasonCodes: []string{}}
	}

	purpose := ""
	if classValid && class != core.CrawlerClassUnknown {
		purpose = string(class)
	}

	// The full trust chain is the existing crawler rule: a verified bot, a
	// beneficial purpose class, a strong verification method and a public
	// endpoint. Reusing it keeps one definition of "verified for a purpose"
	// rather than introducing a second, weaker one here.
	if core.VerifiedPublicCrawler(observations, endpointClass) {
		return Result{
			Provenance:  VerifiedPurpose,
			Purpose:     purpose,
			ReasonCodes: []string{ReasonVerifiedPurpose},
		}
	}

	reasons := []string{ReasonDeclaredOnly}
	// An identity that would otherwise verify, presented where its purpose does
	// not apply, is worth explaining separately: the operator sees a scope
	// mismatch rather than an apparently arbitrary refusal.
	if observations.VerifiedBot && beneficialPurpose(class) && !publicEndpoint(endpointClass) {
		reasons = append(reasons, ReasonPurposeNotPermittedHere)
	}
	return Result{Provenance: Declared, Purpose: purpose, ReasonCodes: reasons}
}

// Verified reports whether the identity was established for its declared
// purpose. It is a convenience for policy and never implies permission.
func (r Result) Verified() bool { return r.Provenance == VerifiedPurpose }

func beneficialPurpose(class core.CrawlerClass) bool {
	switch class {
	case core.CrawlerClassSearchIndexer, core.CrawlerClassAnswerEngine,
		core.CrawlerClassUserTriggeredAgent, core.CrawlerClassPreview:
		return true
	default:
		return false
	}
}

func publicEndpoint(value string) bool {
	switch value {
	case "public_content", "compare_index", "other_public":
		return true
	default:
		return false
	}
}
