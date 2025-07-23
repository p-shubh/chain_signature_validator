package main

import (
	"crypto/ecdsa"
	"fmt"
	"log"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/crypto"
)

// 1️⃣ Create a new Ethereum wallet
func CreateWallet() (*ecdsa.PrivateKey, string) {
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		log.Fatalf("Error generating key: %v", err)
	}

	publicKey := privateKey.Public().(*ecdsa.PublicKey)
	address := crypto.PubkeyToAddress(*publicKey).Hex()
	return privateKey, address
}

// 2️⃣ Sign a message using the private key
func SignMessage(message string, privateKey *ecdsa.PrivateKey) []byte {
	msgHash := accounts.TextHash([]byte(message)) // EIP-191

	signature, err := crypto.Sign(msgHash, privateKey)
	if err != nil {
		log.Fatalf("Error signing message: %v", err)
	}

	return signature
}

// 3️⃣ Verify the signature and return the recovered address
func VerifySignature(message string, signature []byte) string {
	msgHash := accounts.TextHash([]byte(message)) // Same hashing as signing

	// Recover public key from signature
	publicKey, err := crypto.SigToPub(msgHash, signature)
	if err != nil {
		log.Fatalf("Error recovering public key: %v", err)
	}

	address := crypto.PubkeyToAddress(*publicKey).Hex()
	return address
}

// 🚀 Main function to test everything
func main() {
	// Generate wallet
	privateKey, address := CreateWallet()
	fmt.Println("🔐 New Wallet Address:", address)
	fmt.Println("private key:", privateKey.Curve.Params())

	// Message to sign
	message := "Hello from Ethereum!"

	// Sign message
	signature := SignMessage(message, privateKey)
	fmt.Printf("✍️  Signature: 0x%x\n", signature)

	// Verify and recover address
	recoveredAddress := VerifySignature(message, signature)
	fmt.Println("🔎 Recovered Address:", recoveredAddress)

	// Final check
	if recoveredAddress == address {
		fmt.Println("✅ Signature is valid!")
	} else {
		fmt.Println("❌ Signature verification failed!")
	}
}
