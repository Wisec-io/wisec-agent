package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log"
	"os"
)

// loadOrGenerateKeys returns the agent's Ed25519 key pair. In CI the private key
// must be provided as a hex string in AGENT_PRIVATE_KEY_HEX. When it is absent a
// throwaway key is generated, which is only useful for local testing.
func loadOrGenerateKeys() (ed25519.PublicKey, ed25519.PrivateKey) {
	if hexKey := os.Getenv("AGENT_PRIVATE_KEY_HEX"); hexKey != "" {
		keyBytes, err := hex.DecodeString(hexKey)
		if err != nil {
			log.Fatalf("AGENT_PRIVATE_KEY_HEX is not valid hex: %v", err)
		}
		if len(keyBytes) != ed25519.PrivateKeySize {
			log.Fatalf("AGENT_PRIVATE_KEY_HEX has length %d, expected %d", len(keyBytes), ed25519.PrivateKeySize)
		}
		priv := ed25519.PrivateKey(keyBytes)
		pub := priv.Public().(ed25519.PublicKey)
		logInfo("Loaded signing key from environment")
		logVerbose("public key: %s", hex.EncodeToString(pub))
		return pub, priv
	}

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		log.Fatalf("could not generate key pair: %v", err)
	}
	logInfo("AGENT_PRIVATE_KEY_HEX not set; generated a temporary key (local testing only)")
	logVerbose("public key: %s", hex.EncodeToString(pub))
	return pub, priv
}

// fileSHA256 returns the hex-encoded SHA-256 of a file, streaming it so large
// artifacts are not held in memory.
func fileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
