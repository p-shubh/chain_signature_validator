package main

import (
    "flag"
    "fmt"
    "log"

    "evm-signature-validator/pkg/crypto"
    "evm-signature-validator/pkg/validator"
)

func main() {
    mnemonicPtr := flag.String("mnemonic", "", "Mnemonic phrase for signing")
    messagePtr := flag.String("message", "", "Message to sign")
    signaturePtr := flag.String("signature", "", "Signature to validate")

    flag.Parse()

    if *mnemonicPtr == "" || *messagePtr == "" {
        log.Fatal("Mnemonic and message must be provided")
    }

    // Sign the message
    signature, err := crypto.SignMessage(*mnemonicPtr, *messagePtr)
    if err != nil {
        log.Fatalf("Error signing message: %v", err)
    }
    fmt.Printf("Generated Signature: %s\n", signature)

    // Validate the signature
    if *signaturePtr != "" {
        isValid := validator.ValidateSignature(*mnemonicPtr, *messagePtr, *signaturePtr)
        if isValid {
            fmt.Println("The signature is valid.")
        } else {
            fmt.Println("The signature is invalid.")
        }
    }
}