package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"github.com/gagliardetto/solana-go"
	"github.com/tyler-smith/go-bip32"
	"github.com/tyler-smith/go-bip39"
)

// deriveSeedFromMnemonic derives a seed from a mnemonic phrase using BIP-39.
func deriveSeedFromMnemonic(mnemonic, passphrase string) ([]byte, error) {
	if !bip39.IsMnemonicValid(mnemonic) {
		return nil, fmt.Errorf("invalid mnemonic")
	}
	return bip39.NewSeed(mnemonic, passphrase), nil
}

// deriveKeypairFromSeed derives a Solana keypair from a seed using BIP-32 with Solana's derivation path.
func deriveKeypairFromSeed(seed []byte) (solana.PrivateKey, error) {
	masterKey, err := bip32.NewMasterKey(seed)
	if err != nil {
		return nil, fmt.Errorf("failed to create master key: %w", err)
	}

	// Derive key using Solana's path: m/44'/501'/0'/0'
	key, err := masterKey.NewChildKey(0x80000000 + 44) // 44'
	if err != nil {
		return nil, fmt.Errorf("failed to derive 44': %w", err)
	}
	key, err = key.NewChildKey(0x80000000 + 501) // 501'
	if err != nil {
		return nil, fmt.Errorf("failed to derive 501': %w", err)
	}
	key, err = key.NewChildKey(0x80000000 + 0) // 0'
	if err != nil {
		return nil, fmt.Errorf("failed to derive 0': %w", err)
	}
	key, err = key.NewChildKey(0x80000000 + 0) // 0'
	if err != nil {
		return nil, fmt.Errorf("failed to derive 0': %w", err)
	}

	// Use the derived key directly as the seed for ed25519
	ed25519Key := ed25519.NewKeyFromSeed(key.Key)
	if len(ed25519Key) != 64 { // 32-byte private key + 32-byte public key
		return nil, fmt.Errorf("invalid ed25519 key length")
	}
	return solana.PrivateKey(ed25519Key), nil
}

// CreateSignature creates a signature for a message using a mnemonic-derived keypair.
func CreateSignature(mnemonic, message, passphrase string) (signature, publicKey string, err error) {
	seed, err := deriveSeedFromMnemonic(mnemonic, passphrase)
	if err != nil {
		return "", "", fmt.Errorf("failed to derive seed: %w", err)
	}

	privateKey, err := deriveKeypairFromSeed(seed)
	if err != nil {
		return "", "", fmt.Errorf("failed to derive keypair: %w", err)
	}

	publicKey = privateKey.PublicKey().String()
	messageBytes := []byte(message)
	signatureBytes := ed25519.Sign(ed25519.PrivateKey(privateKey), messageBytes)
	signature = base64.StdEncoding.EncodeToString(signatureBytes)

	return signature, publicKey, nil
}

// VerifySignature verifies a signature for a message using the public key.
func VerifySignature(message, signature, publicKey string) (bool, error) {
	messageBytes := []byte(message)
	signatureBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return false, fmt.Errorf("failed to decode signature: %w", err)
	}

	pubKey, err := solana.PublicKeyFromBase58(publicKey)
	if err != nil {
		return false, fmt.Errorf("invalid public key: %w", err)
	}

	return ed25519.Verify(pubKey[:], messageBytes, signatureBytes), nil
}

