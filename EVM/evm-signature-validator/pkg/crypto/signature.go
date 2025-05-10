package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"math/big"

	"github.com/tyler-smith/go-bip39"
)

// SignMessage signs a message using the provided mnemonic.
func SignMessage(mnemonic string, message string) (string, error) {
	// Generate a seed from the mnemonic
	seed, err := bip39.NewSeed(mnemonic, "")
	if err != nil {
		return "", err
	}

	// Create a new ECDSA private key from the seed
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	privKey.D.SetBytes(seed[:32]) // Use the first 32 bytes of the seed

	// Hash the message
	hash := hashMessage(message)

	// Sign the hash
	r, s, err := ecdsa.Sign(rand.Reader, privKey, hash)
	if err != nil {
		return "", err
	}

	// Combine r and s into a single signature
	signature := append(r.Bytes(), s.Bytes()...)
	return hex.EncodeToString(signature), nil
}

// VerifySignature verifies a signature for a given message and mnemonic.
func VerifySignature(mnemonic string, message string, signature string) (bool, error) {
	// Generate a seed from the mnemonic
	seed, err := bip39.NewSeed(mnemonic, "")
	if err != nil {
		return false, err
	}

	// Create a new ECDSA public key from the seed
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	privKey.D.SetBytes(seed[:32]) // Use the first 32 bytes of the seed
	pubKey := privKey.PublicKey

	// Hash the message
	hash := hashMessage(message)

	// Decode the signature
	sigBytes, err := hex.DecodeString(signature)
	if err != nil {
		return false, err
	}

	// Split the signature into r and s
	half := len(sigBytes) / 2
	r := big.Int{}
	s := big.Int{}
	r.SetBytes(sigBytes[:half])
	s.SetBytes(sigBytes[half:])

	// Verify the signature
	valid := ecdsa.Verify(&pubKey, hash, &r, &s)
	return valid, nil
}

// hashMessage hashes the message using a suitable hashing algorithm.
func hashMessage(message string) []byte {
	// Implement your hashing logic here (e.g., SHA256)
	return []byte(message) // Placeholder for actual hashing
}
