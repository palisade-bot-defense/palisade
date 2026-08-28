package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/palisade-bot-defense/palisade/internal/crawlerregistryops"
)

func crawlerRegistryKeygen(args []string) error {
	flags := flag.NewFlagSet("crawler-registry-keygen", flag.ContinueOnError)
	privatePath := flags.String("private-key", "", "new owner-only Ed25519 publisher private key outside every Git worktree")
	publicPath := flags.String("public-key", "", "new owner-only Ed25519 verifier public key outside every Git worktree")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *privatePath == "" || *publicPath == "" {
		return errors.New("crawler-registry-keygen requires --private-key and --public-key")
	}
	if err := crawlerregistryops.GenerateKeyPair(*privatePath, *publicPath); err != nil {
		return err
	}
	fmt.Println("crawler registry publisher key pair created")
	return nil
}

func crawlerRegistrySign(args []string) error {
	flags := flag.NewFlagSet("crawler-registry-sign", flag.ContinueOnError)
	entriesPath := flags.String("entries", "", "owner-only reviewed closed registry entries JSON outside every Git worktree")
	privatePath := flags.String("private-key", "", "owner-only Ed25519 publisher private key outside every Git worktree")
	outputPath := flags.String("output", "", "new or atomically replaced owner-only signed registry outside every Git worktree")
	revision := flags.Uint64("revision", 0, "strictly increasing registry revision")
	lifetime := flags.Duration("valid-for", 7*24*time.Hour, "signed lifetime from 10m through 744h")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *entriesPath == "" || *privatePath == "" || *outputPath == "" || *revision == 0 {
		return errors.New("crawler-registry-sign requires --entries, --private-key, --output and --revision")
	}
	status, err := crawlerregistryops.SignAndPublish(crawlerregistryops.SignConfig{
		EntriesPath: *entriesPath, PrivateKeyPath: *privatePath, OutputPath: *outputPath,
		Revision: *revision, Lifetime: *lifetime,
	}, time.Now().UTC())
	if err != nil {
		return err
	}
	fmt.Printf("crawler registry signed: revision=%d identities=%d prefixes=%d expires_at=%s digest_sha256=%s\n",
		status.Revision, status.IdentityCount, status.PrefixCount, status.ExpiresAt.Format(time.RFC3339), status.DigestSHA256)
	return nil
}

func crawlerRegistryInspect(args []string) error {
	flags := flag.NewFlagSet("crawler-registry-inspect", flag.ContinueOnError)
	registryPath := flags.String("registry", "", "owner-only signed crawler registry outside every Git worktree")
	publicPath := flags.String("public-key", "", "owner-only Ed25519 verifier public key outside every Git worktree")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *registryPath == "" || *publicPath == "" {
		return errors.New("crawler-registry-inspect requires --registry and --public-key")
	}
	status, err := crawlerregistryops.Inspect(*registryPath, *publicPath, time.Now().UTC())
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(status)
}
