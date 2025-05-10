package main

func main() {
	// Example usage
	mnemonic := "clerk flower outer eagle special amount region charge remove voice sentence cream"

	passMneomonicGetTheToken(mnemonic)

	// walletAddress, _, _, flowId, message, err := GetEvmFlowIdAndMessage(mnemonic)
	// if err != nil {
	// 	fmt.Printf("Error: %v\n", err)
	// 	return
	// }

	// fmt.Println("FlowId: ", flowId)

	// message = fmt.Sprintf("%s%s", message, flowId)
	// // Generate signature

	// fmt.Println("Message: ", message)

	// signature, _, err := SignMessage(mnemonic, message)

	// // Message, _, _, signature, walletAddress, err := CreateSignature(mnemonic)

	// fmt.Printf("Address: %s\n", walletAddress)
	// fmt.Printf("Signature: %s\n", signature)

	// // // Verify signature
	// // valid, err := VerifySignature(message, signature, walletAddress)
	// // if err != nil {
	// // 	fmt.Printf("Error verifying signature: %v\n", err)
	// // 	return
	// // }

	// // fmt.Printf("Signature valid: %v\n", valid)

	// // fmt.Printf("Address1: %s\n", walletAddress)
	// // fmt.Printf("Signature2: %s\n", signature)
	// // fmt.Printf("Message2: %s\n", message)

	// GetToken(flowId, signature, walletAddress)
}
