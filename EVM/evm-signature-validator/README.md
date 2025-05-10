# EVM Signature Validator

This project is an Ethereum Virtual Machine (EVM) signature validator that allows users to generate mnemonics, sign messages, and validate signatures. It is designed to provide a simple interface for handling cryptographic operations related to EVM signatures.

## Project Structure

```
evm-signature-validator
├── cmd
│   └── main.go          # Entry point of the application
├── pkg
│   ├── crypto
│   │   ├── mnemonic.go  # Functions for mnemonic generation and handling
│   │   └── signature.go  # Functions for signing and verifying messages
│   ├── validator
│       └── validator.go  # Logic for validating signatures
├── go.mod               # Module definition and dependencies
└── README.md            # Project documentation
```

## Installation

To install the project, clone the repository and navigate to the project directory:

```bash
git clone <repository-url>
cd evm-signature-validator
```

Then, run the following command to download the necessary dependencies:

```bash
go mod tidy
```

## Usage

To run the application, use the following command:

```bash
go run cmd/main.go
```

### Functions

- **GenerateMnemonic**: Creates a new mnemonic phrase.
- **ValidateMnemonic**: Checks the validity of a given mnemonic.
- **SignMessage**: Signs a message using a mnemonic.
- **VerifySignature**: Verifies if a given signature is valid for a specific message and mnemonic.
- **ValidateSignature**: Validates a signature using the functions from the crypto package.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request for any improvements or bug fixes.

## License

This project is licensed under the MIT License. See the LICENSE file for more details.