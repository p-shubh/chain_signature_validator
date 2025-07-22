package main

import (
	"crypto/ecdsa"
	"fmt"
	"log"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

func main() {
	message := "Hello, Base!"

	// 1. Generate ECDSA private key (like an Ethereum wallet)
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		log.Fatalf("Failed to generate private key: %v", err)
	}
	publicKey := privateKey.Public().(*ecdsa.PublicKey)
	address := crypto.PubkeyToAddress(*publicKey)
	fmt.Println("🧾 Generated Ethereum Address:", address.Hex())

	// 2. Hash the message (Ethereum personal_sign format)
	prefixedMsg := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(message), message)
	msgHash := crypto.Keccak256Hash([]byte(prefixedMsg))

	// 3. Sign the message hash
	signatureBytes, err := crypto.Sign(msgHash.Bytes(), privateKey)
	if err != nil {
		log.Fatalf("Failed to sign message: %v", err)
	}
	fmt.Println("✍️ Signature (hex):", common.Bytes2Hex(signatureBytes))

	// 4. Verify signature
	// Note: crypto.Sign returns 65-byte sig: [R || S || V]
	sigCopy := make([]byte, len(signatureBytes))
	copy(sigCopy, signatureBytes)
	if sigCopy[64] >= 27 {
		sigCopy[64] -= 27
	}

	recoveredPubKey, err := crypto.SigToPub(msgHash.Bytes(), sigCopy)
	if err != nil {
		log.Fatalf("Failed to recover public key: %v", err)
	}
	recoveredAddr := crypto.PubkeyToAddress(*recoveredPubKey)
	fmt.Println("🔍 Recovered Address:", recoveredAddr.Hex())

	// 5. Compare
	if recoveredAddr.Hex() == address.Hex() {
		fmt.Println("✅ Signature is valid!")
	} else {
		fmt.Println("❌ Signature is invalid!")
	}
}
