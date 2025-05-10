
# Chain Signature Validator

This project provides utilities for interacting with Ethereum wallets, generating signatures, verifying signatures, and authenticating with a remote API. It is written in Go and uses the `go-ethereum` and `go-ethereum-hdwallet` libraries.

## Features

- Generate Ethereum wallet addresses from a mnemonic.
- Derive Ethereum accounts using the standard derivation path.
- Fetch `flowId` and `message` from a remote API.
- Sign messages using Ethereum private keys.
- Verify Ethereum signatures.
- Authenticate with a remote API using a signed message.

## Prerequisites

- Go 1.18 or later
- A valid Ethereum mnemonic phrase
- Internet connection to interact with the remote API

## Installation

1. Clone the repository:

   ```bash
   git clone <repository-url>
   cd chain_signature_validator
   ```
2. Install dependencies:

   ```bash
   go mod tidy
   ```

## Usage

### 1. Generate Wallet Address and Fetch Flow ID

The `GetEvmFlowIdAndMessage` function generates a wallet address from a mnemonic and fetches the `flowId` and `message` from the remote API.
