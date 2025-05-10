package validator

import (
    "github.com/yourusername/evm-signature-validator/pkg/crypto"
)

func ValidateSignature(mnemonic, message, signature string) (bool, error) {
    // Validate the mnemonic
    if err := crypto.ValidateMnemonic(mnemonic); err != nil {
        return false, err
    }

    // Verify the signature
    isValid, err := crypto.VerifySignature(mnemonic, message, signature)
    if err != nil {
        return false, err
    }

    return isValid, nil
}