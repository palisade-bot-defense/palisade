package palisadehttp

import (
	"net/netip"
	"strings"
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
	Name            string
	Class           string
	UserAgentTokens []string
	CIDRs           []string
}

type crawlerIdentity struct {
	class    string
	tokens   []string
	prefixes []netip.Prefix
}

// CrawlerRegistry is immutable after construction and safe for concurrent use.
type CrawlerRegistry struct {
	identities []crawlerIdentity
}

func NewCrawlerRegistry(entries []CrawlerIdentity) (*CrawlerRegistry, error) {
	if len(entries) == 0 || len(entries) > maxCrawlerIdentities {
		return nil, ErrInvalidConfig
	}
	registry := &CrawlerRegistry{identities: make([]crawlerIdentity, 0, len(entries))}
	totalPrefixes := 0
	for _, entry := range entries {
		if len(entry.Name) < 1 || len(entry.Name) > 64 || !stableCrawlerValue(entry.Name) ||
			!validCrawlerClass(entry.Class) || entry.Class == CrawlerClassUnknown ||
			len(entry.UserAgentTokens) == 0 || len(entry.UserAgentTokens) > maxCrawlerUATokens || len(entry.CIDRs) == 0 {
			return nil, ErrInvalidConfig
		}
		identity := crawlerIdentity{class: entry.Class}
		for _, rawToken := range entry.UserAgentTokens {
			token := strings.ToLower(strings.TrimSpace(rawToken))
			if len(token) < 5 || len(token) > 64 || !stableCrawlerValue(token) {
				return nil, ErrInvalidConfig
			}
			for _, existing := range identity.tokens {
				if token == existing {
					return nil, ErrInvalidConfig
				}
			}
			identity.tokens = append(identity.tokens, token)
		}
		for _, rawPrefix := range entry.CIDRs {
			prefix, err := netip.ParsePrefix(strings.TrimSpace(rawPrefix))
			if err != nil || prefix != prefix.Masked() || !validCrawlerPrefix(prefix) {
				return nil, ErrInvalidConfig
			}
			identity.prefixes = append(identity.prefixes, prefix)
			totalPrefixes++
			if totalPrefixes > maxCrawlerPrefixes {
				return nil, ErrInvalidConfig
			}
		}
		registry.identities = append(registry.identities, identity)
	}
	return registry, nil
}

func (r *CrawlerRegistry) verify(userAgent string, address netip.Addr) (bool, string, string) {
	if r == nil || !address.IsValid() || address.Zone() != "" {
		return false, CrawlerClassUnknown, CrawlerVerificationUnknown
	}
	address = address.Unmap()
	userAgent = strings.ToLower(userAgent)
	matchedClass := ""
	for _, identity := range r.identities {
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
	switch value {
	case CrawlerClassUnknown, CrawlerClassSearchIndexer, CrawlerClassAnswerEngine,
		CrawlerClassTrainingCrawler, CrawlerClassUserTriggeredAgent,
		CrawlerClassPreview, CrawlerClassMonitoring, CrawlerClassOther:
		return true
	default:
		return false
	}
}

func validCrawlerVerification(value string) bool {
	switch value {
	case CrawlerVerificationUnknown, CrawlerVerificationIPUARegistry:
		return true
	default:
		return false
	}
}

func stableCrawlerValue(value string) bool {
	for _, character := range value {
		if character < 0x21 || character > 0x7e {
			return false
		}
	}
	return true
}
