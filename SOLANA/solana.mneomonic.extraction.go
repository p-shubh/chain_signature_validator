package main

import (
	"fmt"
	"strings"

	"github.com/blocto/solana-go-sdk/types"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcutil/hdkeychain"
	"github.com/mr-tron/base58"
	"github.com/tyler-smith/go-bip39"
)

type Wallet struct {
	PrivateKey string
	Address    string
}

// GetSolanaWalletFromMnemonic generates a Solana wallet from a BIP-39 mnemonic phrase with a derivation path.
func GetSolanaWalletFromMnemonic(mnemonic, passphrase, derivationPath string) (*Wallet, error) {
	// Validate mnemonic
	if !bip39.IsMnemonicValid(mnemonic) {
		return nil, fmt.Errorf("invalid mnemonic phrase")
	}

	// Generate seed from mnemonic
	seed := bip39.NewSeed(mnemonic, passphrase)

	var account types.Account

	if derivationPath == "" {
		// Simplified derivation: use first 32 bytes of seed (common in some Solana wallets)
		var err error
		account, err = types.AccountFromSeed(seed[:32])
		if err != nil {
			return nil, fmt.Errorf("failed to create account from seed: %v", err)
		}
	} else {
		// Parse derivation path
		pathParts := strings.Split(derivationPath, "/")
		if len(pathParts) < 2 || pathParts[0] != "m" {
			return nil, fmt.Errorf("invalid derivation path")
		}

		masterKey, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
		// masterKey, err := hdkeychain.NewMaster(seed, &hdkeychain.MainNetParams)
		if err != nil {
			return nil, fmt.Errorf("failed to create master key: %v", err)
		}

		key := masterKey
		for _, part := range pathParts[1:] {
			var index uint32
			if strings.HasSuffix(part, "'") {
				part = strings.TrimSuffix(part, "'")
				index, err = parseUint32(part)
				if err != nil {
					return nil, fmt.Errorf("invalid derivation index: %v", err)
				}
				index += hdkeychain.HardenedKeyStart
			} else {
				index, err = parseUint32(part)
				if err != nil {
					return nil, fmt.Errorf("invalid derivation index: %v", err)
				}
			}
			key, err = key.Child(index)
			if err != nil {
				return nil, fmt.Errorf("failed to derive key: %v", err)
			}
		}

		// Get private key (32 bytes for ed25519 seed)
		privateKey, err := key.ECPrivKey()
		if err != nil {
			return nil, fmt.Errorf("failed to get private key: %v", err)
		}
		seedBytes := privateKey.Serialize()[:32]

		// Generate Solana keypair
		account, err = types.AccountFromSeed(seedBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to create account from seed: %v", err)
		}
	}

	// Convert public key to base58 for Solana address
	address := account.PublicKey.ToBase58()

	// Convert private key to base58
	privateKeyBase58 := base58.Encode(account.PrivateKey)

	return &Wallet{
		PrivateKey: privateKeyBase58,
		Address:    address,
	}, nil
}

// parseUint32 parses a string to uint32
func parseUint32(s string) (uint32, error) {
	var n uint32
	_, err := fmt.Sscanf(s, "%d", &n)
	return n, err
}

func testSolanaMneomonic() {
	// Provided mnemonic
	testMnemonic := "execute glory chest detect practice gadget lizard angle negative forward rely club"

	// Expected address
	expectedAddress := "87K32iBzEgbrMjY7JhehkmiKUUfZWKrfFhxdHu56Jz2v"

	wallet, err := GetSolanaWalletFromMnemonic(testMnemonic, "", "")
	if err != nil {
		fmt.Printf("Error for path %s: %v\n", "path", err)

	}
	fmt.Printf("Derivation Path: %s\n", "path")
	fmt.Printf("Private Key: %s\n", wallet.PrivateKey)
	fmt.Printf("Address: %s\n", wallet.Address)
	if wallet.Address == expectedAddress {
		fmt.Println("MATCH FOUND!")
	} else {
		fmt.Println("No match")
	}
	fmt.Println()
}
