package crypto

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"golang.org/x/crypto/sha3"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/curve25519"
)

// GenerateMnemonic creates a new mnemonic phrase.
func GenerateMnemonic() (string, error) {
	entropy := make([]byte, 32)
	_, err := rand.Read(entropy)
	if err != nil {
		return "", err
	}
	mnemonic := hex.EncodeToString(entropy)
	return mnemonic, nil
}

// ValidateMnemonic checks the validity of a given mnemonic.
func ValidateMnemonic(mnemonic string) error {
	if len(mnemonic) != 64 {
		return errors.New("invalid mnemonic length")
	}
	_, err := hex.DecodeString(mnemonic)
	if err != nil {
		return errors.New("invalid mnemonic format")
	}
	return nil
}