package offlineimport

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var accessPattern = regexp.MustCompile(`^(\S+) \S+ \S+ \[([^\]]+)\] "([A-Z]+) ([^"]*) [^"]+" ([0-9]{3}) (\S+) "[^"]*" "([^"]*)" "[^"]*"\s*$`)

func processAccess(file io.Reader, stats *InputStats, sink eventSink, pseudonyms *pseudonymizer, maxLineBytes int, budget *budgets) (returnErr error) {
	scanner, gzipReader, err := gzipScanner(file, maxLineBytes, budget)
	if err != nil {
		return err
	}
	defer func() { returnErr = errors.Join(returnErr, gzipReader.Close()) }()
	for scanner.Scan() {
		if err := budget.addRecord(); err != nil {
			return err
		}
		stats.Records++
		matches := accessPattern.FindStringSubmatch(scanner.Text())
		if len(matches) != 8 {
			stats.Invalid++
			continue
		}
		observedAt, err := time.Parse("02/Jan/2006:15:04:05 -0700", matches[2])
		if err != nil {
			stats.Invalid++
			continue
		}
		updateObservedRange(stats, observedAt)
		subject, ok := normalizePeer(matches[1])
		if !ok {
			stats.Skipped++
			continue
		}
		userAgent := matches[7]
		if userAgent == "-" {
			userAgent = ""
		}
		size, _ := strconv.ParseInt(matches[6], 10, 64)
		event := baseEvent("access", observedAt, subject, userAgent, pseudonyms)
		event.EndpointClass = endpointClass(matches[4])
		event.ActionClass = actionClass(matches[3])
		event.StatusClass = statusClass(parseStatus(matches[5]))
		event.Features.SizeBucket = sizeBucket(size)
		if err := sink.Write(event); err != nil {
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		if errors.Is(err, ErrDecompressedBudget) {
			return err
		}
		return errors.New("gzip line exceeds limit or stream is corrupt")
	}
	return nil
}

func processAnubis(file io.Reader, stats *InputStats, sink eventSink, pseudonyms *pseudonymizer, peerSource string, maxLineBytes int, budget *budgets) (returnErr error) {
	scanner, gzipReader, err := gzipScanner(file, maxLineBytes, budget)
	if err != nil {
		return err
	}
	defer func() { returnErr = errors.Join(returnErr, gzipReader.Close()) }()
	for scanner.Scan() {
		if err := budget.addRecord(); err != nil {
			return err
		}
		stats.Records++
		line := scanner.Bytes()
		if len(strings.TrimSpace(string(line))) == 0 {
			stats.Skipped++
			continue
		}
		var record map[string]json.RawMessage
		if err := json.Unmarshal(line, &record); err != nil {
			stats.Invalid++
			continue
		}
		observedAt, ok := knownTime(record, "observed_at", "timestamp", "time")
		if !ok {
			stats.Invalid++
			continue
		}
		updateObservedRange(stats, observedAt)
		request := knownObject(record, "request")
		subject := knownString(record, "remote_addr", "remote_address", "peer_ip")
		if subject == "" {
			subject = knownString(request, "remote_addr", "remote_address", "peer_ip")
		}
		if subject == "" {
			connection := knownObject(record, "connection")
			subject = knownString(connection, "remote_addr", "remote_address", "peer_ip")
		}
		if subject == "" && peerSource == AnubisPeerTrustedReal {
			// This field is accepted only after an operator explicitly asserts that
			// the reverse proxy overwrote it at a validated Cloudflare boundary.
			// Arbitrary header maps remain deliberately ignored.
			subject = knownString(record, "x-real-ip", "x_real_ip")
		}
		subject, ok = normalizePeer(subject)
		if !ok {
			stats.Skipped++
			continue
		}
		path := knownString(record, "path", "uri", "request_uri")
		if path == "" {
			path = knownString(request, "path", "uri", "request_uri")
		}
		userAgent := knownString(record, "user_agent", "user-agent", "ua")
		if userAgent == "" {
			userAgent = knownString(request, "user_agent", "user-agent", "ua")
		}
		if userAgent == "" {
			headers := knownObject(record, "headers")
			if headers == nil {
				headers = knownObject(request, "headers")
			}
			userAgent = knownString(headers, "user-agent", "User-Agent")
		}
		if userAgent == "-" {
			userAgent = ""
		}
		method := knownString(record, "method")
		if method == "" {
			method = knownString(request, "method")
		}
		status := knownInt(record, "status", "status_code")
		if status == 0 {
			status = knownInt(request, "status", "status_code")
		}
		challengePresent := knownPresent(record, "challenge")
		checkResultObject := knownObject(record, "check_result")
		checkResult := strings.ToLower(knownString(record, "check_result", "result"))
		if checkResult == "" {
			checkResult = strings.ToLower(knownString(checkResultObject, "result", "status", "verdict", "name"))
		}
		verdict, reason := normalizeAnubisVerdict(checkResult, challengePresent)
		event := baseEvent("anubis", observedAt, subject, userAgent, pseudonyms)
		event.EndpointClass = endpointClass(path)
		event.ActionClass = actionClass(method)
		event.StatusClass = statusClass(status)
		event.SourceVerdict = verdict
		event.ReasonCategory = reason
		event.Features.ChallengePresent = challengePresent
		weight := knownFloat(record, "weight", "score")
		if weight == 0 {
			weight = knownFloat(checkResultObject, "weight", "score")
		}
		event.Features.WeightBucket = weightBucket(weight)
		if err := sink.Write(event); err != nil {
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		if errors.Is(err, ErrDecompressedBudget) {
			return err
		}
		return errors.New("gzip line exceeds limit or stream is corrupt")
	}
	return nil
}

type crowdRecord struct {
	CreatedAt  string `json:"created_at"`
	StartAt    string `json:"start_at"`
	ObservedAt string `json:"observed_at"`
	Scenario   string `json:"scenario"`
	SourceIP   string `json:"source_ip"`
	Value      string `json:"value"`
	Type       string `json:"type"`
	Source     struct {
		IP string `json:"ip"`
	} `json:"source"`
	Alert struct {
		CreatedAt string `json:"created_at"`
		StartAt   string `json:"start_at"`
		Scenario  string `json:"scenario"`
		Source    struct {
			IP string `json:"ip"`
		} `json:"source"`
	} `json:"alert"`
	Decision struct {
		CreatedAt string `json:"created_at"`
		StartAt   string `json:"start_at"`
		Scenario  string `json:"scenario"`
		Value     string `json:"value"`
		Type      string `json:"type"`
		Source    struct {
			IP string `json:"ip"`
		} `json:"source"`
	} `json:"decision"`
}

func processCrowdSec(file io.Reader, stats *InputStats, sink eventSink, pseudonyms *pseudonymizer, source string, maxItemBytes int, budget *budgets) error {
	stream, err := newJSONArrayStream(&budgetReader{reader: file, budget: budget}, maxItemBytes)
	if err != nil {
		return err
	}
	for {
		encoded, more, err := stream.Next()
		if err != nil {
			return err
		}
		if !more {
			break
		}
		if err := budget.addRecord(); err != nil {
			return err
		}
		stats.Records++
		var record crowdRecord
		if err := json.Unmarshal(encoded, &record); err != nil {
			return errors.New("invalid CrowdSec array item")
		}
		if crowdRecordTooLarge(record) {
			stats.Invalid++
			continue
		}
		observedAt, ok := parseKnownTimestamp(firstNonEmpty(record.ObservedAt, record.CreatedAt, record.StartAt, record.Alert.CreatedAt, record.Alert.StartAt, record.Decision.CreatedAt, record.Decision.StartAt))
		if !ok {
			stats.Invalid++
			continue
		}
		updateObservedRange(stats, observedAt)
		subject := record.Source.IP
		if subject == "" {
			subject = record.SourceIP
		}
		if subject == "" && strings.EqualFold(record.Type, "ip") {
			subject = record.Value
		}
		if subject == "" {
			subject = firstNonEmpty(record.Alert.Source.IP, record.Decision.Source.IP)
		}
		if subject == "" && strings.EqualFold(record.Decision.Type, "ip") {
			subject = record.Decision.Value
		}
		subject, ok = normalizePeer(subject)
		if !ok {
			stats.Skipped++
			continue
		}
		event := baseEvent(source, observedAt, subject, "", pseudonyms)
		event.SourceVerdict = map[string]string{
			"crowdsec_alert":    "policy_alert",
			"crowdsec_decision": "policy_decision",
		}[source]
		event.ReasonCategory = crowdSecReason(firstNonEmpty(record.Scenario, record.Alert.Scenario, record.Decision.Scenario))
		event.LabelClass = "probable_abuse"
		event.LabelProvenance = "weak_policy_label"
		event.LabelTrust = "weak_policy_label"
		if err := sink.Write(event); err != nil {
			return err
		}
	}
	return nil
}

func processErrorLog(file io.Reader, stats *InputStats, maxLineBytes int, budget *budgets) (returnErr error) {
	scanner, gzipReader, err := gzipScanner(file, maxLineBytes, budget)
	if err != nil {
		return err
	}
	defer func() { returnErr = errors.Join(returnErr, gzipReader.Close()) }()
	for scanner.Scan() {
		if err := budget.addRecord(); err != nil {
			return err
		}
		stats.Records++
		stats.Skipped++
	}
	if err := scanner.Err(); err != nil {
		if errors.Is(err, ErrDecompressedBudget) {
			return err
		}
		return errors.New("gzip line exceeds limit or stream is corrupt")
	}
	return nil
}

func baseEvent(source string, observedAt time.Time, subject, userAgent string, pseudonyms *pseudonymizer) Event {
	observedAt = observedAt.UTC()
	event := Event{
		SchemaVersion:   EventSchemaVersion,
		Provenance:      ProvenanceOffline,
		Source:          source,
		ObservedAt:      observedAt.Format(time.RFC3339Nano),
		SubjectID:       pseudonyms.pseudonym("subject", observedAt, subject, ""),
		EndpointClass:   "other_public",
		ActionClass:     "other",
		StatusClass:     "unknown",
		SourceVerdict:   "unknown",
		ReasonCategory:  "none",
		LabelClass:      "unknown",
		LabelProvenance: "none",
		LabelTrust:      "untrusted",
		Features: Features{
			UAPresent: userAgent != "",
		},
	}
	if userAgent != "" {
		event.SessionID = pseudonyms.pseudonym("session", observedAt, subject, userAgent)
	}
	return event
}

func normalizeAnubisVerdict(result string, challengePresent bool) (string, string) {
	switch result {
	case "pass", "passed", "ok", "success":
		return "passed", "check_pass"
	case "fail", "failed", "deny", "denied", "reject", "rejected":
		return "failed", "check_fail"
	default:
		if challengePresent {
			return "suspected_automation", "challenge_signal"
		}
		return "unknown", "none"
	}
}

func knownObject(record map[string]json.RawMessage, name string) map[string]json.RawMessage {
	raw, ok := record[name]
	if !ok || len(raw) > 64<<10 {
		return nil
	}
	var object map[string]json.RawMessage
	if json.Unmarshal(raw, &object) != nil {
		return nil
	}
	return object
}

func knownString(record map[string]json.RawMessage, names ...string) string {
	for _, name := range names {
		raw, ok := record[name]
		if !ok || len(raw) > 4096 {
			continue
		}
		var value string
		if json.Unmarshal(raw, &value) == nil && len(value) <= 2048 {
			return value
		}
	}
	return ""
}

func knownPresent(record map[string]json.RawMessage, name string) bool {
	raw, ok := record[name]
	return ok && len(raw) > 0 && string(raw) != "null" && string(raw) != "false" && string(raw) != `""`
}

func knownInt(record map[string]json.RawMessage, names ...string) int {
	for _, name := range names {
		raw, ok := record[name]
		if !ok || len(raw) > 32 {
			continue
		}
		var value int
		if json.Unmarshal(raw, &value) == nil {
			return value
		}
	}
	return 0
}

func knownFloat(record map[string]json.RawMessage, names ...string) float64 {
	for _, name := range names {
		raw, ok := record[name]
		if !ok || len(raw) > 32 {
			continue
		}
		var value float64
		if json.Unmarshal(raw, &value) == nil {
			return value
		}
	}
	return 0
}

func knownTime(record map[string]json.RawMessage, names ...string) (time.Time, bool) {
	for _, name := range names {
		raw, ok := record[name]
		if !ok || len(raw) > 128 {
			continue
		}
		var value string
		if json.Unmarshal(raw, &value) == nil {
			if parsed, ok := parseKnownTimestamp(value); ok {
				return parsed, true
			}
		}
		var number json.Number
		if json.Unmarshal(raw, &number) == nil {
			if seconds, err := number.Int64(); err == nil {
				if seconds > 10_000_000_000 {
					seconds /= 1000
				}
				return time.Unix(seconds, 0).UTC(), true
			}
		}
	}
	return time.Time{}, false
}

func parseKnownTimestamp(value string) (time.Time, bool) {
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02 15:04:05"} {
		parsed, err := time.Parse(layout, value)
		if err == nil {
			return parsed.UTC(), true
		}
	}
	return time.Time{}, false
}

func updateObservedRange(stats *InputStats, observedAt time.Time) {
	value := observedAt.UTC().Format(time.RFC3339Nano)
	if stats.FirstObservedAt == "" {
		stats.FirstObservedAt = value
		stats.LastObservedAt = value
		return
	}
	first, _ := time.Parse(time.RFC3339Nano, stats.FirstObservedAt)
	last, _ := time.Parse(time.RFC3339Nano, stats.LastObservedAt)
	if observedAt.Before(first) {
		stats.FirstObservedAt = value
	}
	if observedAt.After(last) {
		stats.LastObservedAt = value
	}
}

func crowdRecordTooLarge(record crowdRecord) bool {
	for _, value := range []string{record.CreatedAt, record.StartAt, record.ObservedAt, record.Scenario, record.SourceIP, record.Value, record.Type, record.Source.IP, record.Alert.CreatedAt, record.Alert.StartAt, record.Alert.Scenario, record.Alert.Source.IP, record.Decision.CreatedAt, record.Decision.StartAt, record.Decision.Scenario, record.Decision.Value, record.Decision.Type, record.Decision.Source.IP} {
		if len(value) > 4096 {
			return true
		}
	}
	return false
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

// jsonArrayStream extracts one object at a time from a top-level JSON array.
// Unlike json.Decoder.Decode, it enforces a hard item-size limit before an
// entire item can be retained in memory.
type jsonArrayStream struct {
	reader       *bufio.Reader
	maxItemBytes int
	first        bool
	done         bool
}

func newJSONArrayStream(reader io.Reader, maxItemBytes int) (*jsonArrayStream, error) {
	stream := &jsonArrayStream{
		reader:       bufio.NewReaderSize(reader, 64<<10),
		maxItemBytes: maxItemBytes,
		first:        true,
	}
	start, err := stream.readNonSpace()
	if err != nil || start != '[' {
		if errors.Is(err, ErrDecompressedBudget) {
			return nil, err
		}
		return nil, errors.New("CrowdSec input must be a JSON array")
	}
	return stream, nil
}

func (stream *jsonArrayStream) Next() ([]byte, bool, error) {
	if stream.done {
		return nil, false, nil
	}
	current, err := stream.readNonSpace()
	if err != nil {
		if errors.Is(err, ErrDecompressedBudget) {
			return nil, false, err
		}
		return nil, false, errors.New("unterminated CrowdSec JSON array")
	}
	if stream.first {
		stream.first = false
		if current == ']' {
			return stream.finish()
		}
	} else {
		if current == ']' {
			return stream.finish()
		}
		if current != ',' {
			return nil, false, errors.New("invalid CrowdSec JSON array separator")
		}
		current, err = stream.readNonSpace()
		if err != nil || current == ']' {
			if errors.Is(err, ErrDecompressedBudget) {
				return nil, false, err
			}
			return nil, false, errors.New("invalid CrowdSec JSON array item")
		}
	}
	if current != '{' {
		return nil, false, errors.New("CrowdSec array items must be JSON objects")
	}

	encoded := make([]byte, 0, min(stream.maxItemBytes, 64<<10))
	encoded = append(encoded, current)
	depth := 1
	inString := false
	escaped := false
	for depth > 0 {
		current, err = stream.reader.ReadByte()
		if err != nil {
			if errors.Is(err, ErrDecompressedBudget) {
				return nil, false, err
			}
			return nil, false, errors.New("unterminated CrowdSec JSON array item")
		}
		if len(encoded) == stream.maxItemBytes {
			return nil, false, errors.New("CrowdSec JSON array item exceeds size limit")
		}
		encoded = append(encoded, current)
		if inString {
			if escaped {
				escaped = false
				continue
			}
			if current == '\\' {
				escaped = true
			} else if current == '"' {
				inString = false
			}
			continue
		}
		switch current {
		case '"':
			inString = true
		case '{', '[':
			depth++
		case '}', ']':
			depth--
		}
	}
	return encoded, true, nil
}

func (stream *jsonArrayStream) finish() ([]byte, bool, error) {
	for {
		current, err := stream.reader.ReadByte()
		if err == io.EOF {
			stream.done = true
			return nil, false, nil
		}
		if err != nil {
			if errors.Is(err, ErrDecompressedBudget) {
				return nil, false, err
			}
			return nil, false, errors.New("read CrowdSec JSON trailer")
		}
		if current != ' ' && current != '\t' && current != '\r' && current != '\n' {
			return nil, false, errors.New("unexpected data after CrowdSec JSON array")
		}
	}
}

func (stream *jsonArrayStream) readNonSpace() (byte, error) {
	for {
		current, err := stream.reader.ReadByte()
		if err != nil {
			return 0, err
		}
		if current != ' ' && current != '\t' && current != '\r' && current != '\n' {
			return current, nil
		}
	}
}

func validateEvent(event Event) error {
	allowed := func(value string, values ...string) bool {
		for _, candidate := range values {
			if value == candidate {
				return true
			}
		}
		return false
	}
	if event.SchemaVersion != EventSchemaVersion || event.Provenance != ProvenanceOffline ||
		!allowed(event.Source, "access", "anubis", "crowdsec_alert", "crowdsec_decision") ||
		!allowed(event.EndpointClass, "compare_index", "compare_noindex", "anubis_worker", "other_public") ||
		!allowed(event.ActionClass, "read", "write", "other") ||
		!allowed(event.StatusClass, "success", "redirect", "client_error", "server_error", "unknown") ||
		!allowed(event.SourceVerdict, "unknown", "suspected_automation", "passed", "failed", "policy_alert", "policy_decision") ||
		!allowed(event.ReasonCategory, "none", "challenge_signal", "check_pass", "check_fail", "crowdsec_http_abuse", "crowdsec_credential_abuse", "crowdsec_reputation", "crowdsec_other", "unknown") ||
		!allowed(event.LabelClass, "unknown", "probable_abuse") ||
		!allowed(event.LabelProvenance, "none", "weak_policy_label") ||
		!allowed(event.LabelTrust, "untrusted", "weak_policy_label") {
		return fmt.Errorf("normalized event violates a closed enum")
	}
	if observedAt, err := time.Parse(time.RFC3339Nano, event.ObservedAt); err != nil || observedAt.Location() != time.UTC {
		return errors.New("normalized event observation time must be UTC RFC3339")
	}
	if !validPseudonym(event.SubjectID) || (event.SessionID != "" && !validPseudonym(event.SessionID)) {
		return errors.New("normalized event contains an invalid pseudonym")
	}
	if event.Features.SizeBucket < 0 || event.Features.SizeBucket > 4 || event.Features.WeightBucket < 0 || event.Features.WeightBucket > 4 {
		return errors.New("normalized event feature is not quantized")
	}
	isCrowdSec := event.Source == "crowdsec_alert" || event.Source == "crowdsec_decision"
	isWeakLabel := event.LabelClass == "probable_abuse" && event.LabelProvenance == "weak_policy_label" && event.LabelTrust == "weak_policy_label"
	if isCrowdSec != isWeakLabel {
		return errors.New("normalized event violates weak-label semantics")
	}
	return nil
}

func validPseudonym(value string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == 32
}
