# Taproot Token Standard (TSB)

A Bitcoin native token standard implementation that leverages Taproot script path spending to reveal token data on-chain. This approach creates tokens directly on Bitcoin without using OP_RETURN, providing better privacy, efficiency, and flexibility.

## Key Features

- **Native Bitcoin Integration**: Uses Taproot script path spending instead of OP_RETURN outputs
- **Privacy-Preserving**: Token data remains hidden until spent via the script path
- **Timestamp Support**: Each token includes a timestamp for verification and tracking
- **Metadata Support**: Attach arbitrary metadata to your tokens
- **Simple Verification**: Tokens can be verified by anyone with blockchain access

## How It Works

1. **Token Creation**: Embeds token data (ID, amount, metadata, timestamp) in a Taproot script
2. **Script Path Spending**: Reveals token data on-chain during normal transaction validation
3. **On-chain Verification**: The revealed data becomes part of the blockchain's history

## Token Data Structure

Each token contains:
- **Token ID** (16 bytes): A unique identifier padded to fixed length
- **Amount** (8 bytes): Quantity of tokens represented
- **Metadata** (variable length): Arbitrary data attached to the token
- **Timestamp** (8 bytes): Creation time for verification purposes

## Requirements

- Go 1.18+
- Bitcoin Core 24.0+ running in regtest mode
- Required Go packages:
  ```
  github.com/btcsuite/btcd/btcec/v2
  github.com/btcsuite/btcd/btcutil
  github.com/btcsuite/btcd/chaincfg
  github.com/btcsuite/btcd/txscript
  github.com/btcsuite/btcd/wire
  ```

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/taproot-token-standard.git
cd taproot-token-standard

# Initialize Go module and get dependencies
go mod init taproottoken
go get github.com/btcsuite/btcd/btcec/v2
go get github.com/btcsuite/btcd/btcutil
go get github.com/btcsuite/btcd/chaincfg
go get github.com/btcsuite/btcd/txscript
go get github.com/btcsuite/btcd/wire

# Verify Bitcoin Core is running in regtest mode
bitcoin-cli -regtest getblockchaininfo

# Build the CLI tool
go build -o taproottoken
```

## Quick Start

Create, fund, and reveal a token in one step:

```bash
# Create and spend a token with custom parameters
./taproottoken --name "myToken" --amount 1000000 --metadata "My custom token data"
```

## Command Line Parameters

| Parameter    | Description                                    | Default Value       |
|--------------|------------------------------------------------|---------------------|
| `--name`     | Token identifier (will be padded to 16 bytes)  | "gobi-token"        |
| `--amount`   | Token amount as an integer                     | 1337                |
| `--metadata` | Custom metadata to store with the token        | "TSB reveal test"   |

## Under the Hood: Script Structure

The token data is embedded in a Taproot script with this format:

```
<"TSB"> <tokenID> <amount> <metadata> <timestamp> OP_DROP OP_DROP OP_DROP OP_DROP OP_DROP OP_TRUE
```

When spent via the script path, this reveals all token data on the blockchain while still allowing the transaction to validate.

## Full Usage Example

### Creating a Token

```go
// Create a new token with specified parameters
output, err := CreateToken("myToken", 1000000, "Custom metadata")
if err != nil {
    log.Fatal(err)
}

// The token address can now be funded
fmt.Println("Token address:", output.Address)
```

### Funding the Token Address

```go
// Send Bitcoin to the token address
funding, err := FundAddress(output.Address, 0.01)
if err != nil {
    log.Fatal(err)
}
```

### Spending and Revealing the Token

```go
// Generate a destination address for the BTC
destAddr, err := RunBitcoinCommand("getnewaddress")
if err != nil {
    log.Fatal(err)
}

// Spend the token to reveal its data on-chain
txid, err := SpendToken(destAddr)
if err != nil {
    log.Fatal(err)
}
fmt.Println("Token revealed in transaction:", txid)
```

### Extracting Token Data from a Transaction

```go
// Load the token private key
keyHex, _ := os.ReadFile("token_key.hex")
token, _ := LoadTaprootToken(string(keyHex))

// Extract token data from transaction hex
rawHex, _ := os.ReadFile("spending_tx.hex")
tokenData, err := token.RevealTokenDataFromHex(string(rawHex))
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Token ID: %s\n", tokenData.TokenID)
fmt.Printf("Amount: %d\n", tokenData.Amount)
fmt.Printf("Metadata: %s\n", tokenData.Metadata)
fmt.Printf("Timestamp: %d\n", tokenData.Timestamp)
```

## Security Considerations

- The current implementation uses `OP_TRUE` for simplicity, meaning anyone can spend the output
- For production use, implement proper authentication mechanisms like signatures or hash locks
- Consider multi-signature protection for high-value tokens
- Test thoroughly on testnet before deploying to mainnet

## Use Cases

- **Fungible Tokens**: Create tokens that represent assets, currencies, or utility tokens
- **NFTs**: Deploy non-fungible tokens with unique metadata
- **Document Timestamping**: Use the embedded timestamp for verifiable proof-of-existence
- **Supply Chain**: Track products or materials with timestamped on-chain data
- **Cross-Chain Bridges**: Create verifiable bridging tokens with detailed metadata

## Advanced Customization

For production applications, consider these enhancements:

1. **Custom Script Logic**: Add spending conditions beyond the simple `OP_TRUE`
2. **Multiple Token Operations**: Add different script paths for transfer, burning, minting, etc.
3. **Token Authentication**: Add owner signature requirements to prevent unauthorized spending

## License

MIT

## Resources

- [BIP341 (Taproot)](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki)
- [BIP342 (Tapscript)](https://github.com/bitcoin/bips/blob/master/bip-0342.mediawiki)