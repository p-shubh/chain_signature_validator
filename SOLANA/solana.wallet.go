package main

// import (
// 	"fmt"
// 	"strings"

// 	"github.com/blocto/solana-go-sdk/types"
// 	"github.com/btcsuite/btcutil/hdkeychain"
// 	"github.com/mr-tron/base58"
// 	"github.com/tyler-smith/go-bip39"
// )

// type Wallet struct {
// 	Mnemonic   string
// 	PrivateKey string
// 	Address    string
// }

// // CreateSolanaWallet generates a new Solana wallet with a mnemonic phrase.
// func CreateSolanaWallet(passphrase, derivationPath string, wordCount int) (*Wallet, error) {
// 	// Generate entropy based on word count (12 or 24 words)
// 	var entropySize int
// 	switch wordCount {
// 	case 12:
// 		entropySize = 128 // 128 bits for 12 words
// 	case 24:
// 		entropySize = 256 // 256 bits for 24 words
// 	default:
// 		return nil, fmt.Errorf("invalid word count; use 12 or 24")
// 	}

// 	entropy, err := bip39.NewEntropy(entropySize)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to generate entropy: %v", err)
// 	}

// 	// Generate mnemonic from entropy
// 	mnemonic, err := bip39.NewMnemonic(entropy)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to generate mnemonic: %v", err)
// 	}

// 	// Generate seed from mnemonic
// 	seed := bip39.NewSeed(mnemonic, passphrase)

// 	// Default Solana derivation path
// 	if derivationPath == "" {
// 		derivationPath = "m/44'/501'/0'/0'"
// 	}

// 	// Parse derivation path
// 	pathParts := strings.Split(derivationPath, "/")
// 	if len(pathParts) < 2 || pathParts[0] != "m" {
// 		return nil, fmt.Errorf("invalid derivation path")
// 	}

// 	// Create master key from seed
// 	masterKey, err := hdkeychain.NewMaster(seed, &hdkeychain.MainNetParams)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to create master key: %v", err)
// 	}

// 	key := masterKey
// 	for _, part := range pathParts[1:] {
// 		var index uint32
// 		if strings.HasSuffix(part, "'") {
// 			part = strings.TrimSuffix(part, "'")
// 			index, err = parseUint32(part)
// 			if err != nil {
// 				return nil, fmt.Errorf("invalid derivation index: %v", err)
// 			}
// 			index += hdkeychain.HardenedKeyStart
// 		} else {
// 			index, err = parseUint32(part)
// 			if err != nil {
// 				return nil, fmt.Errorf("invalid derivation index: %v", err)
// 			}
// 		}
// 		key, err = key.Derive(index)
// 		if err != nil {
// 			return nil, fmt.Errorf("failed to derive key: %v", err)
// 		}
// 	}

// 	// Get private key (32 bytes for ed25519 seed)
// 	privateKey, err := key.ECPrivKey()
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to get private key: %v", err)
// 	}
// 	seedBytes := privateKey.Serialize()[:32]

// 	// Generate Solana keypair
// 	account := types.NewAccountFromSeed(seedBytes)

// 	// Convert public key to base58 for Solana address
// 	address := account.PublicKey.ToBase58()

// 	// Convert private key to base58
// 	privateKeyBase58 := base58.Encode(account.PrivateKey)

// 	return &Wallet{
// 		Mnemonic:   mnemonic,
// 		PrivateKey: privateKeyBase58,
// 		Address:    address,
// 	}, nil
// }

// // parseUint32 parses a string to uint32
// func parseUint32(s string) (uint32, error) {
// 	var n uint32
// 	_, err := fmt.Sscanf(s, "%d", &n)
// 	return n, err
// }

// func main() {
// 	// Create a new Solana wallet with a 12-word mnemonic
// 	wallet, err := CreateSolanaWallet("", "m/44'/501'/0'/0'", 12)
// 	if err != nil {
// 		fmt.Printf("Error: %v\n", err)
// 		return
// 	}

// 	fmt.Printf("Mnemonic: %s\n", wallet.Mnemonic)
// 	fmt.Printf("Private Key: %s\n", wallet.PrivateKey)
// 	fmt.Printf("Address: %s\n", wallet.Address)
// }
