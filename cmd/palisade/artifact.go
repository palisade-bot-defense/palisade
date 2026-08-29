package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/palisade-bot-defense/palisade/internal/detector"
	"github.com/palisade-bot-defense/palisade/internal/localartifact"
	"github.com/palisade-bot-defense/palisade/internal/policy"
)

func artifactKeygen(args []string) error {
	flags := flag.NewFlagSet("artifact-keygen", flag.ContinueOnError)
	privatePath := flags.String("private-key", "", "new owner-only Ed25519 private key outside every Git worktree")
	publicPath := flags.String("public-key", "", "new owner-only Ed25519 public key outside every Git worktree")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *privatePath == "" || *publicPath == "" {
		return errors.New("artifact-keygen requires --private-key and --public-key")
	}
	return localartifact.GenerateKeyPair(*privatePath, *publicPath)
}

func prepareLocalArtifact(args []string) error {
	flags := flag.NewFlagSet("prepare-local-artifact", flag.ContinueOnError)
	artifactType := flags.String("type", "", "closed artifact type: policy_bundle or detector_bundle")
	payloadPath := flags.String("payload", "", "closed JSON payload to validate and sign")
	privateKeyPath := flags.String("private-key", "", "owner-only Ed25519 private key outside every Git worktree")
	outputPath := flags.String("output", "", "new owner-only signed artifact outside every Git worktree")
	revision := flags.Uint64("revision", 0, "strictly increasing deployment revision")
	lifetime := flags.Duration("lifetime", 7*24*time.Hour, "signed validity period, at most 31 days")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *payloadPath == "" || *privateKeyPath == "" || *outputPath == "" || *revision == 0 || *lifetime <= 0 || *lifetime > localartifact.MaximumLifetime {
		return errors.New("prepare-local-artifact requires valid --type, --payload, --private-key, --output, --revision and --lifetime")
	}
	payload, err := readBoundedPayload(*payloadPath)
	if err != nil {
		return err
	}
	artifactID, err := validateArtifactPayload(*artifactType, payload)
	if err != nil {
		return err
	}
	privateKey, err := localartifact.ReadPrivateKey(*privateKeyPath)
	if err != nil {
		return err
	}
	now := time.Now().UTC().Truncate(time.Second)
	encoded, err := localartifact.Sign(localartifact.Metadata{
		ArtifactType: *artifactType, ArtifactID: artifactID, Revision: *revision,
		IssuedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(*lifetime).Format(time.RFC3339),
	}, json.RawMessage(payload), privateKey)
	if err != nil {
		return err
	}
	if err := localartifact.WriteDocument(*outputPath, encoded); err != nil {
		return err
	}
	fmt.Printf("signed local artifact created: type=%s id=%s revision=%d expires_at=%s\n", *artifactType, artifactID, *revision, now.Add(*lifetime).Format(time.RFC3339))
	return nil
}

func verifyLocalArtifact(args []string) error {
	flags := flag.NewFlagSet("verify-local-artifact", flag.ContinueOnError)
	artifactType := flags.String("type", "", "closed artifact type: policy_bundle or detector_bundle")
	documentPath := flags.String("artifact", "", "owner-only signed artifact outside every Git worktree")
	publicKeyPath := flags.String("public-key", "", "owner-only Ed25519 public key outside every Git worktree")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *documentPath == "" || *publicKeyPath == "" {
		return errors.New("verify-local-artifact requires --type, --artifact and --public-key")
	}
	encoded, err := localartifact.ReadDocument(*documentPath)
	if err != nil {
		return err
	}
	publicKey, err := localartifact.ReadPublicKey(*publicKeyPath)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	var verified localartifact.Verified
	switch *artifactType {
	case localartifact.TypePolicy:
		_, verified, err = policy.NewSigned(encoded, publicKey, now)
	case localartifact.TypeDetector:
		_, verified, err = detector.NewSignedRegistry(encoded, publicKey, now)
	default:
		return errors.New("unsupported local artifact type")
	}
	if err != nil {
		return err
	}
	fmt.Printf("local artifact verified: type=%s id=%s revision=%d expires_at=%s\n", verified.Metadata.ArtifactType, verified.Metadata.ArtifactID, verified.Metadata.Revision, verified.Metadata.ExpiresAt)
	return nil
}

func readBoundedPayload(path string) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Size() < 1 || before.Size() > localartifact.MaximumDocumentBytes {
		return nil, errors.New("artifact payload must be a bounded regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return nil, errors.New("artifact payload changed while opening")
	}
	data, err := io.ReadAll(io.LimitReader(file, localartifact.MaximumDocumentBytes+1))
	if err != nil || len(data) > localartifact.MaximumDocumentBytes {
		return nil, errors.New("artifact payload exceeds its size limit")
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || after.Size() != int64(len(data)) || after.Mode() != before.Mode() || !after.ModTime().Equal(before.ModTime()) {
		return nil, errors.New("artifact payload changed while reading")
	}
	return data, nil
}

func validateArtifactPayload(artifactType string, payload []byte) (string, error) {
	switch artifactType {
	case localartifact.TypePolicy:
		var bundle policy.Bundle
		if err := decodeClosedPayload(payload, &bundle); err != nil || bundle.Validate() != nil {
			return "", errors.New("invalid closed policy bundle")
		}
		return bundle.PolicyVersion, nil
	case localartifact.TypeDetector:
		var bundle detector.Bundle
		if err := decodeClosedPayload(payload, &bundle); err != nil || bundle.Validate() != nil {
			return "", errors.New("invalid closed detector bundle")
		}
		return bundle.ModelVersion, nil
	default:
		return "", errors.New("unsupported local artifact type")
	}
}

func decodeClosedPayload(payload []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("payload contains multiple JSON values")
	}
	return nil
}
