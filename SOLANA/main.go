package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/mr-tron/base58"
)

// type Wallet struct {
// 	PrivateKey string
// 	Address    string
// }

// // GetSolanaWalletFromMnemonic generates a Solana wallet from a BIP-39 mnemonic phrase.
// func GetSolanaWalletFromMnemonic(mnemonic, passphrase string) (*Wallet, error) {
// 	// Validate mnemonic
// 	if !bip39.IsMnemonicValid(mnemonic) {
// 		return nil, fmt.Errorf("invalid mnemonic phrase")
// 	}

// 	// Generate seed from mnemonic
// 	seed := bip39.NewSeed(mnemonic, passphrase)

// 	// Derive Solana keypair using the seed
// 	// Solana uses the first 32 bytes of the seed for ed25519 key generation
// 	account := types.NewAccountFromSeed(seed[:32])

// 	// Convert public key to base58 for Solana address
// 	address := account.PublicKey.ToBase58()

// 	// Convert private key to base58
// 	privateKey := base58.Encode(account.PrivateKey)

// 	return &Wallet{
// 		PrivateKey: privateKey,
// 		Address:    address,
// 	}, nil
// }

// GenerateSignature creates a signature for a message using the mnemonic-derived private key.
func GenerateSignature(mnemonic, passphrase, message string) (string, error) {
	// Get wallet from mnemonic
	wallet, err := GetSolanaWalletFromMnemonic(mnemonic, passphrase, "")
	if err != nil {
		return "", fmt.Errorf("failed to get wallet: %v", err)
	}

	// Decode base58 private key
	privateKeyBytes, err := base58.Decode(wallet.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("failed to decode private key: %v", err)
	}

	// Ensure private key is 64 bytes (ed25519 private key)
	if len(privateKeyBytes) != 64 {
		return "", fmt.Errorf("invalid private key length")
	}

	// Sign the message using ed25519
	signature := ed25519.Sign(privateKeyBytes, []byte(message))

	// Encode signature to base58
	signatureBase58 := base58.Encode(signature)

	return signatureBase58, nil
}

// VerifySignature verifies a signature for a message using the wallet's public address.
func VerifySolanaSignature(address, message, signatureBase58 string) (bool, error) {
	// Decode base58 signature
	signature, err := base58.Decode(signatureBase58)
	if err != nil {
		return false, fmt.Errorf("failed to decode signature: %v", err)
	}

	// Decode base58 address to get public key
	publicKeyBytes, err := base58.Decode(address)
	if err != nil {
		return false, fmt.Errorf("failed to decode address: %v", err)
	}

	// Ensure public key is 32 bytes (ed25519 public key)
	if len(publicKeyBytes) != 32 {
		return false, fmt.Errorf("invalid public key length")
	}

	// Verify the signature using ed25519
	return ed25519.Verify(publicKeyBytes, []byte(message), signature), nil
}

// func main1() {
// 	// Provided mnemonic (from your working code)
// 	testMnemonic := "execute glory chest detect practice gadget lizard angle negative forward rely club"
// 	passphrase := "" // Empty passphrase
// 	message := "Hello, Solana!"

// 	// Expected address (from your working code)
// 	expectedAddress := "87K32iBzEgbrMjY7JhehkmiKUUfZWKrfFhxdHu56Jz2v"

// 	// Get wallet
// 	wallet, err := GetSolanaWalletFromMnemonic(testMnemonic, passphrase, "")
// 	if err != nil {
// 		fmt.Printf("Error getting wallet: %v\n", err)
// 		return
// 	}
// 	fmt.Printf("Address: %s\n", wallet.Address)
// 	if wallet.Address == expectedAddress {
// 		fmt.Println("Address MATCH FOUND!")
// 	} else {
// 		fmt.Println("Address No match")
// 	}

// 	// Generate signature
// 	signature, err := GenerateSignature(testMnemonic, passphrase, message)
// 	if err != nil {
// 		fmt.Printf("Error generating signature: %v\n", err)
// 		return
// 	}
// 	fmt.Printf("Message: %s\n", message)
// 	fmt.Printf("Signature: %s\n", signature)

// 	// Verify signature
// 	verified, err := VerifySolanaSignature(wallet.Address, message, signature)
// 	if err != nil {
// 		fmt.Printf("Error verifying signature: %v\n", err)
// 		return
// 	}
// 	if verified {
// 		fmt.Println("Signature verification: SUCCESS")
// 	} else {
// 		fmt.Println("Signature verification: FAILED")
// 	}
// }

func main() {
	testMnemonic := "execute glory chest detect practice gadget lizard angle negative forward rely club"

	passSolanaMneomonicGetTheToken(testMnemonic)
}

func GetSolanaFlowIdAndMessageByMneomonic(mnemonic string) (walletAddress, flowID string, message string, err error) {

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	// Get wallet from mnemonic
	wallet, err := GetSolanaWalletFromMnemonic(mnemonic, "", "")
	if err != nil {
		return "", "", "", fmt.Errorf("failed to get wallet: %v", err)
	}

	walletAddress = wallet.Address

	// Step 1: Get flowId
	flowIDURL := fmt.Sprintf("https://gateway.netsepio.com/api/v1.0/flowid?walletAddress=%s&chain=sol", wallet.Address)

	// flowIDURL := fmt.Sprintf("http://localhost:3000/api/v1.0/flowid?walletAddress=%s&chain=evm", walletAddress)

	fmt.Printf("Fetching flowId from: %s\n", flowIDURL)

	req, err := http.NewRequest("GET", flowIDURL, nil)
	if err != nil {
		fmt.Printf("Error creating request: %v\n", err)
		return
	}

	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Error getting flowId: %v\n", err)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading response: %v\n", err)
		return
	}

	fmt.Printf("FlowId Response Status: %d\n", resp.StatusCode)
	fmt.Printf("FlowId Response Body: %s\n", string(body))

	var flowIDResp FlowIDResponse
	if err = json.Unmarshal(body, &flowIDResp); err != nil {
		fmt.Printf("Error parsing response: %v\n", err)
		return
	}

	if flowIDResp.Status != 200 {
		fmt.Printf("Failed to get flowId: %s\n", flowIDResp.Message)
		return
	}

	flowID = flowIDResp.Payload.FlowID
	message = flowIDResp.Payload.Eula
	fmt.Printf("Received FlowId: %s\n", flowID)
	fmt.Printf("Received Message: %s\n", message)

	return

}

// FlowIDResponse represents the flowId response
type FlowIDResponse struct {
	Status  int    `json:"status"`
	Message string `json:"message"`
	Payload struct {
		FlowID string `json:"flowId"`
		Eula   string `json:"eula"`
	} `json:"payload"`
}

func passSolanaMneomonicGetTheToken(mnemonic string) {
	// Example usage
	walletAddress, flowId, message, err := GetSolanaFlowIdAndMessageByMneomonic(mnemonic)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Println("FlowId: ", flowId)

	eula := message

	message = fmt.Sprintf("%s%s", eula, flowId)
	// Generate signature

	fmt.Println("Message: ", message)

	signature, err := GenerateSignature(mnemonic, "", message)
	if err != nil {
		fmt.Printf("Error generating signature: %v\n", err)
		return
	}

	verified, err := VerifySolanaSignature(walletAddress, message, signature)
	if err != nil {
		fmt.Printf("Error verifying signature: %v\n", err)
		return
	}
	if verified {
		fmt.Println("Signature verification: SUCCESS")
	} else {
		fmt.Println("Signature verification: FAILED")
	}

	GetToken(flowId, signature, walletAddress)
}

func GetToken(flowID, sign, walletAddress string) {
	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 30 * time.Second,
	}
	// Step 3: Authenticate
	authData := map[string]string{
		"chainName":     "sol",
		"flowId":        flowID,
		"signature":     sign,
		"walletAddress": walletAddress,
		"pubKey":        walletAddress,
	}

	fmt.Printf("Auth data: %v\n", authData)

	authJSON, err := json.Marshal(authData)
	if err != nil {
		fmt.Printf("Error marshaling auth data: %v\n", err)
		return
	}

	fmt.Printf("Auth request data: %s\n", string(authJSON))

	// authReq, err := http.NewRequest("POST", "https://gateway.netsepio.com/api/v1.0/authenticate", bytes.NewBuffer(authJSON))
	authReq, err := http.NewRequest("POST", "http://localhost:3000/api/v1.0/authenticate", bytes.NewBuffer(authJSON))
	if err != nil {
		fmt.Printf("Error creating auth request: %v\n", err)
		return
	}

	authReq.Header.Set("Content-Type", "application/json")

	fmt.Println("Sending authentication request...")
	authResp, err := client.Do(authReq)
	if err != nil {
		fmt.Printf("Error sending auth request: %v\n", err)
		return
	}
	defer authResp.Body.Close()

	authBody, err := io.ReadAll(authResp.Body)
	if err != nil {
		fmt.Printf("Error reading auth response: %v\n", err)
		return
	}

	fmt.Printf("Auth Response Status: %d\n", authResp.StatusCode)
	fmt.Printf("Auth Response Body: %s\n", string(authBody))

	var authResponse AuthResponse
	if err := json.Unmarshal(authBody, &authResponse); err != nil {
		fmt.Printf("Error parsing auth response: %v\n", err)
		return
	}

	if authResponse.Status != 200 {
		fmt.Printf("Authentication failed: %s\n", authResponse.Message)
		return
	}

	fmt.Println("Authentication successful!")
	fmt.Printf("Token: %s\n", authResponse.Payload.Token)
	fmt.Printf("UserID: %s\n", authResponse.Payload.UserID)
}

// AuthResponse represents the authentication response
type AuthResponse struct {
	Status  int    `json:"status"`
	Message string `json:"message"`
	Payload struct {
		Token  string `json:"token"`
		UserID string `json:"userId"`
	} `json:"payload"`
}
