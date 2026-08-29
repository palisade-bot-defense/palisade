package palisadehttp

import (
	"net/netip"
	"strings"
	"sync/atomic"
	"time"

	"github.com/palisade-bot-defense/palisade/pkg/palisadecontract"
)

const (
	CrawlerClassUnknown            = "unknown"
	CrawlerClassSearchIndexer      = "search_indexer"
	CrawlerClassAnswerEngine       = "answer_engine"
	CrawlerClassTrainingCrawler    = "training_crawler"
	CrawlerClassUserTriggeredAgent = "user_triggered_agent"
	CrawlerClassPreview            = "preview"
	CrawlerClassMonitoring         = "monitoring"
	CrawlerClassOther              = "other"

	CrawlerVerificationUnknown      = "unknown"
	CrawlerVerificationIPUARegistry = "ip_ua_registry"

	maxCrawlerIdentities = 128
	maxCrawlerPrefixes   = 4096
	maxCrawlerUATokens   = 8
)

// CrawlerIdentity is one locally maintained, purpose-specific registry entry.
// CIDRs must come from an authenticated vendor publication or an equivalent
// operator-approved source. PALISADE deliberately ships no stale universal
// list and never treats a user-agent token as identity by itself.
type CrawlerIdentity struct {
	Name            string   `json:"name"`
	Class           string   `json:"class"`
	UserAgentTokens []string `json:"user_agent_tokens"`
	CIDRs           []string `json:"cidrs"`
}

type crawlerIdentity struct {
	class    string
	tokens   []string
	prefixes []netip.Prefix
}

type crawlerSnapshot struct {
	identities  []crawlerIdentity
	revision    uint64
	issuedAt    time.Time
	expiresAt   time.Time
	digest      string
	prefixCount int
}

// CrawlerRegistry is safe for concurrent verification and signed updates. A
// registry built with NewCrawlerRegistry is immutable. A registry built with
// NewSignedCrawlerRegistry atomically swaps only fully verified snapshots.
type CrawlerRegistry struct {
	static          *crawlerSnapshot
	signed          atomic.Pointer[crawlerSnapshot]
	verificationKey []byte
}

func NewCrawlerRegistry(entries []CrawlerIdentity) (*CrawlerRegistry, error) {
	snapshot, err := buildCrawlerSnapshot(entries)
	if err != nil {
		return nil, ErrInvalidConfig
	}
	return &CrawlerRegistry{static: snapshot}, nil
}

func buildCrawlerSnapshot(entries []CrawlerIdentity) (*crawlerSnapshot, error) {
	if len(entries) == 0 || len(entries) > maxCrawlerIdentities {
		return nil, ErrInvalidCrawlerRegistry
	}
	snapshot := &crawlerSnapshot{identities: make([]crawlerIdentity, 0, len(entries))}
	totalPrefixes := 0
	for _, entry := range entries {
		if len(entry.Name) < 1 || len(entry.Name) > 64 || !stableCrawlerValue(entry.Name) ||
			!validCrawlerClass(entry.Class) || entry.Class == CrawlerClassUnknown ||
			len(entry.UserAgentTokens) == 0 || len(entry.UserAgentTokens) > maxCrawlerUATokens || len(entry.CIDRs) == 0 {
			return nil, ErrInvalidCrawlerRegistry
		}
		identity := crawlerIdentity{class: entry.Class}
		for _, rawToken := range entry.UserAgentTokens {
			token := strings.ToLower(strings.TrimSpace(rawToken))
			if len(token) < 5 || len(token) > 64 || !stableCrawlerValue(token) {
				return nil, ErrInvalidCrawlerRegistry
			}
			for _, existing := range identity.tokens {
				if token == existing {
					return nil, ErrInvalidCrawlerRegistry
				}
			}
			identity.tokens = append(identity.tokens, token)
		}
		for _, rawPrefix := range entry.CIDRs {
			prefix, err := netip.ParsePrefix(strings.TrimSpace(rawPrefix))
			if err != nil || prefix != prefix.Masked() || !validCrawlerPrefix(prefix) {
				return nil, ErrInvalidCrawlerRegistry
			}
			identity.prefixes = append(identity.prefixes, prefix)
			totalPrefixes++
			if totalPrefixes > maxCrawlerPrefixes {
				return nil, ErrInvalidCrawlerRegistry
			}
		}
		snapshot.identities = append(snapshot.identities, identity)
	}
	snapshot.prefixCount = totalPrefixes
	return snapshot, nil
}

func (r *CrawlerRegistry) verify(userAgent string, address netip.Addr) (bool, string, string) {
	return r.verifyAt(userAgent, address, time.Now().UTC())
}

func (r *CrawlerRegistry) verifyAt(userAgent string, address netip.Addr, now time.Time) (bool, string, string) {
	if r == nil || !address.IsValid() || address.Zone() != "" {
		return false, CrawlerClassUnknown, CrawlerVerificationUnknown
	}
	snapshot := r.static
	if len(r.verificationKey) > 0 {
		snapshot = r.signed.Load()
	}
	if snapshot == nil || (!snapshot.expiresAt.IsZero() && !now.Before(snapshot.expiresAt)) {
		return false, CrawlerClassUnknown, CrawlerVerificationUnknown
	}
	address = address.Unmap()
	userAgent = strings.ToLower(userAgent)
	matchedClass := ""
	for _, identity := range snapshot.identities {
		if !matchesCrawlerToken(userAgent, identity.tokens) || !matchesCrawlerPrefix(address, identity.prefixes) {
			continue
		}
		if matchedClass != "" {
			// Ambiguous local configuration is never resolved by entry order.
			return false, CrawlerClassUnknown, CrawlerVerificationUnknown
		}
		matchedClass = identity.class
	}
	if matchedClass == "" {
		return false, CrawlerClassUnknown, CrawlerVerificationUnknown
	}
	return true, matchedClass, CrawlerVerificationIPUARegistry
}

func matchesCrawlerToken(userAgent string, tokens []string) bool {
	for _, token := range tokens {
		remaining := userAgent
		offset := 0
		for {
			index := strings.Index(remaining, token)
			if index < 0 {
				break
			}
			start := offset + index
			end := start + len(token)
			leftBoundary := start == 0 || !crawlerTokenCharacter(userAgent[start-1])
			rightBoundary := end == len(userAgent) || !crawlerTokenCharacter(userAgent[end])
			if leftBoundary && rightBoundary {
				return true
			}
			offset = start + 1
			remaining = userAgent[offset:]
		}
	}
	return false
}

func crawlerTokenCharacter(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= '0' && value <= '9' || value == '-' || value == '_'
}

func matchesCrawlerPrefix(address netip.Addr, prefixes []netip.Prefix) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func validCrawlerPrefix(prefix netip.Prefix) bool {
	address := prefix.Addr()
	return prefix.IsValid() && address.Zone() == "" && !address.Is4In6() && !address.IsUnspecified() &&
		!address.IsMulticast() && !address.IsLoopback() && !address.IsPrivate()
}

func validCrawlerClass(value string) bool {
	return palisadecontract.ValidCrawlerClass(value)
}

func stableCrawlerValue(value string) bool {
	for _, character := range value {
		if character < 0x21 || character > 0x7e {
			return false
		}
	}
	return true
}
