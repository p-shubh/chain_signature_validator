package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	hdwallet "github.com/miguelmota/go-ethereum-hdwallet"
)

func GetEvmFlowIdAndMessage(mnemonic string) (walletAddress string, wallet *hdwallet.Wallet, account accounts.Account, flowID string, message string, err error) {

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	// Generate wallet from mnemonic
	wallet, err = hdwallet.NewFromMnemonic(mnemonic)
	if err != nil {
		return "", wallet, account, "", "", fmt.Errorf("failed to create wallet: %v", err)
	}

	// Derive account using standard Ethereum path
	path := hdwallet.MustParseDerivationPath("m/44'/60'/0'/0/0")
	account, err = wallet.Derive(path, false)
	if err != nil {
		// return "", "", fmt.Errorf("failed to derive account: %v", err)
	}

	walletAddress = account.Address.Hex()
	fmt.Printf("Wallet Address: %s\n", walletAddress)

	// Step 1: Get flowId
	flowIDURL := fmt.Sprintf("https://gateway.netsepio.com/api/v1.0/flowid?walletAddress=%s&chain=evm", walletAddress)

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

func GetToken(flowID, sign, walletAddress string) {
	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 30 * time.Second,
	}
	// Step 3: Authenticate
	authData := map[string]string{
		"chainName": "evm",
		"flowId":    flowID,
		"signature": sign,
		// "walletAddress": walletAddress,
	}

	fmt.Printf("Auth data: %v\n", authData)

	authJSON, err := json.Marshal(authData)
	if err != nil {
		fmt.Printf("Error marshaling auth data: %v\n", err)
		return
	}

	fmt.Printf("Auth request data: %s\n", string(authJSON))

	authReq, err := http.NewRequest("POST", "https://gateway.netsepio.com/api/v1.0/authenticate", bytes.NewBuffer(authJSON))
	// authReq, err := http.NewRequest("POST", "http://localhost:3000/api/v1.0/authenticate", bytes.NewBuffer(authJSON))
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

// VerifySignature validates an EVM signature
func VerifySignature(message, signature, address string) (bool, error) {

	fmt.Println("len of signature", len(signature))

	// Decode signature
	sigBytes, err := hex.DecodeString(strings.TrimPrefix(signature, "0x"))
	if err != nil {
		return false, fmt.Errorf("invalid signature format: %v", err)
	}

	// Ensure signature length is correct
	if len(sigBytes) != 65 {
		return false, fmt.Errorf("invalid signature length: expected 65, got %d", len(sigBytes))
	}

	// Prepare message hash
	hash := crypto.Keccak256Hash([]byte(fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(message), message)))

	// Recover public key
	sigBytes[64] -= 27 // Adjust v value for recovery
	pubKey, err := crypto.SigToPub(hash.Bytes(), sigBytes)
	if err != nil {
		return false, fmt.Errorf("failed to recover public key: %v", err)
	}

	// Get recovered address
	recoveredAddr := crypto.PubkeyToAddress(*pubKey)

	// Compare addresses
	expectedAddr := common.HexToAddress(address)
	return recoveredAddr == expectedAddr, nil
}

// SignMessage generates an EVM signature for a message using a mnemonic
func SignMessage(mnemonic, message string) (signature, address string, err error) {
	// Generate wallet from mnemonic
	wallet, err := hdwallet.NewFromMnemonic(mnemonic)
	if err != nil {
		return "", "", fmt.Errorf("failed to create wallet: %v", err)
	}

	// Derive account using standard Ethereum path
	path := hdwallet.MustParseDerivationPath("m/44'/60'/0'/0/0")
	account, err := wallet.Derive(path, false)
	if err != nil {
		return "", "", fmt.Errorf("failed to derive account: %v", err)
	}

	// Get private key
	privateKey, err := wallet.PrivateKey(account)
	if err != nil {
		return "", "", fmt.Errorf("failed to get private key: %v", err)
	}

	// Prepare message for Ethereum signing
	hash := crypto.Keccak256Hash([]byte(fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(message), message)))

	// Sign the message
	sig, err := crypto.Sign(hash.Bytes(), privateKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to sign message: %v", err)
	}

	// Adjust v value (Ethereum expects 27 or 28)
	if sig[64] < 27 {
		sig[64] += 27
	}

	return hex.EncodeToString(sig), account.Address.Hex(), nil
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

func passMneomonicGetTheToken(mnemonic string) {
	// Example usage
	walletAddress, _, _, flowId, message, err := GetEvmFlowIdAndMessage(mnemonic)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Println("FlowId: ", flowId)

	eula := message

	message = fmt.Sprintf("%s%s", eula, flowId)
	// Generate signature

	fmt.Println("Message: ", message)

	signature, _, err := SignMessage(mnemonic, message)

	GetToken(flowId, signature, walletAddress)
}
