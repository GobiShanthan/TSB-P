# TSB-P: Token Standard for Bitcoin - Programmable

A Bitcoin-native token standard implementation that leverages Taproot script-path spending to securely embed token data on-chain.  
TSB-P tokens are fully verifiable without relying on OP_RETURN or off-chain storage, preserving Bitcoin's Layer 1 trust model.

## Key Features

- **Native Bitcoin Layer 1 Integration**: Tokens live entirely inside Taproot script-paths
- **Privacy-Preserving**: Token data remains hidden until spent via script-path reveal
- **Programmable**: Extendable via Taproot script branching and conditions
- **Metadata & Timestamp Support**: Embed flexible metadata and proof-of-existence timestamps
- **Simple Stateless Verification**: Anyone with blockchain access can validate tokens

## How It Works

1. **Token Creation**: A Taproot address is generated with a script embedding token metadata
2. **Funding**: Bitcoin is sent to the generated address, locking in the token
3. **Script-Path Spending**: Spending the UTXO reveals token data on-chain through the witness
4. **On-chain Verification**: Token authenticity and attributes are provable by decoding the witness

## Token Data Structure (Script Format)

The Taproot script path for a TSB-P token has the structure:

```
OP_TRUE
OP_IF
  <"TSB">
  <tokenID> (16 bytes)
  <amount> (8 bytes, big-endian)
  <typeCode> (1 byte)
  OP_DROP
  OP_DROP
  OP_DROP
  OP_DROP
  <metadata> (variable length)
  <timestamp> (8 bytes, big-endian)
  OP_DROP
  OP_DROP
  OP_TRUE
OP_ENDIF
```

### Fields Explained:

| Field | Description |
|-------|-------------|
| "TSB" | Marker to identify token scripts |
| tokenID | 16-byte unique identifier (padded if shorter) |
| amount | 8-byte unsigned integer (Big Endian) |
| typeCode | 1 byte (defines token type, e.g., 0 = fungible, 1 = NFT) |
| metadata | Flexible user-defined data |
| timestamp | 8-byte UNIX timestamp (Big Endian) |

## Token Type Codes

The `typeCode` field defines the purpose and logic of the token. Values range from 0-255, with these reserved values:

| typeCode | Meaning | Description |
|----------|---------|-------------|
| 0 | Fungible Token (FT) | Standard fungible asset (e.g., currency, shares) |
| 1 | Non-Fungible Token (NFT) | Unique asset (e.g., art, real estate) |
| 2 | Proof-of-Existence Token (PoE) | Timestamped document or hash proof |
| 3 | Smart Contract Trigger Token | Triggers on-chain programmable conditions |
| 4 | Oracle-Verified Token | Requires oracle-fed external validation |
| 5 | Compliance-Bound Token | Enforces KYC/AML or whitelisting rules |
| 6 | Vesting Token | Token subject to time-based vesting schedules |
| 7 | Multi-Sig Restricted Token | Spend requires multiple signatures |
| 8 | DAO Governance Token | Used for decentralized voting or governance |
| 9 | Fee Payment Token | Used for paying fees inside custom protocols |
| 10 | Wrapped Asset Token | Represents an asset from another blockchain or off-chain asset |
| 11 | Cross-Chain Bridge Token | Facilitates cross-chain asset movement |
| 12 | Royalty Token | Pays out a share of revenue or royalties |
| 13 | Subscription Access Token | Grants access to time-limited services |
| 14 | Identity Token | Verifiable claims about identity (e.g., KYC data) |
| 15 | Treasury Reserve Token | Held in reserves, often by treasuries or DAOs |

📢 **More types can be added as TSB-P evolves!** Values 16-255 are reserved for future upgrades.

## Requirements

- Go 1.18+
- Bitcoin Core 24.0+ (running in regtest mode)
- Go packages:
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
git clone https://github.com/yourusername/tsb-p-token-creator.git
cd tsb-p-token-creator

# Initialize Go module and dependencies
go mod init tsbp
go get github.com/btcsuite/btcd/btcec/v2
go get github.com/btcsuite/btcd/btcutil
go get github.com/btcsuite/btcd/chaincfg
go get github.com/btcsuite/btcd/txscript
go get github.com/btcsuite/btcd/wire

# Ensure Bitcoin Core is running in regtest
bitcoin-cli -regtest getblockchaininfo

# Build
go build -o taproottoken
```

## Quick Start

```bash
./taproottoken --name "myToken" --amount 1000000 --metadata "This is a test token"
```

✅ Creates a Taproot address  
✅ Funds it automatically  
✅ Constructs a spend transaction  
✅ Reveals token data on-chain  
✅ Extracts and prints token attributes  

## Command Line Parameters

| Parameter | Description | Default Value |
|-----------|-------------|---------------|
| --name | Token ID (padded to 16 bytes) | "gobi-token" |
| --amount | Token amount (integer) | 1337 |
| --metadata | Optional metadata string | "TSB reveal test" |
| --typecode | Token type code (integer) | 0 (Fungible Token) |

## Full Usage Example

### Create a Token

```go
output, err := CreateToken("myToken", 1000000, "Metadata about my token")
if err != nil {
    log.Fatal(err)
}
fmt.Println("Token Address:", output.Address)
```

### Fund the Token Address

```go
funding, err := FundAddress(output.Address, 0.01)
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Funded UTXO: %s:%d\n", funding.TxID, funding.Vout)
```

### Spend and Reveal the Token

```go
destAddr, _ := RunBitcoinCommand("getnewaddress")
txid, err := SpendToken(destAddr)
if err != nil {
    log.Fatal(err)
}
fmt.Println("Token revealed in TX:", txid)
```

### Extract Token Data

```go
keyHex, _ := os.ReadFile("token_key.hex")
token, _ := LoadTaprootToken(string(keyHex))

rawHex, _ := os.ReadFile("spending_tx.hex")
tokenData, err := token.RevealTokenDataFromHex(string(rawHex))
if err != nil {
    log.Fatal(err)
}

fmt.Printf("TokenID: %s\n", tokenData.TokenID)
fmt.Printf("Amount : %d\n", tokenData.Amount)
fmt.Printf("TypeCode: %d\n", tokenData.TypeCode)
fmt.Printf("Metadata: %s\n", tokenData.Metadata)
fmt.Printf("Timestamp: %d\n", tokenData.Timestamp)
```

## Security Considerations

- By default, outputs are spendable by anyone (OP_TRUE)
- For production, implement ownership enforcement (e.g., signature requirements, hash locks)
- Always test thoroughly on regtest or testnet before using on Bitcoin mainnet
- Properly manage your Taproot internal keys securely

## Potential Use Cases

- Fungible tokens
- NFTs
- Proof-of-existence documents
- Supply chain asset tracking
- Cross-chain bridging assets
- Programmable DAOs and governance tokens
- **Programmable Assets**: TSB-P tokens can support programmable conditions (e.g., oracle checks, signature checks, time-locks) through Taproot extensions and script branching

## License

MIT License

## Resources

- [BIP341: Taproot](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki)
- [BIP342: Tapscript](https://github.com/bitcoin/bips/blob/master/bip-0342.mediawiki)