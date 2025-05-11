package main

import "fmt"

func main() {

	/*
		Mnemonic: rate skate globe bitter reduce reward festival crowd engage conduct dash prize urge boil drop tired noodle relax leopard chest estate disagree tunnel youth
		Seed (hex): f4c333917a7fce83847160b4c8c94fd2b99af34ef5eca9cbb2f6d05cc9d6103bc8801428c5d85b68ec56d4cecbdbda2f14e3a3dbe5050524f5cfe25fc3abc71c
		Private Key (base58): 5tq2SW2hNZgNNiwHHvY9ZD9N4YArK3zVpjt1dmdXNR5e89BJZRDsqHL4iEzFsArWzoCQUotzrLoQaiBXktnZDRBy
		Public Key (base58): EVfpA5wC2UzJh1W37t2GYZxLYvmRhENmRR3BWz77F9z3
	*/
	mnemonic := "lobster order pen culture off fold fire brisk noble key organ chat private apple small cheap struggle intact phrase model blanket wagon throw enough"
	message := "Hello, Solana!"
	passphrase := ""

	// Create signature
	signature, publicKey, err := CreateSignature(mnemonic, message, passphrase)
	if err != nil {
		fmt.Printf("Error creating signature: %v\n", err)
		return
	}
	fmt.Println("Signature:", signature)
	fmt.Println("Public Key:", publicKey)

	// Verify signature
	isValid, err := VerifySignature(message, signature, publicKey)
	if err != nil {
		fmt.Printf("Error verifying signature: %v\n", err)
		return
	}
	fmt.Println("Signature Valid:", isValid)
}
