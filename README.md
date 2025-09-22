# TSB-P: Token Standard for Bitcoin – Programmable with Compliance

A Bitcoin-native token standard implementation that leverages **Taproot script-path spending** to securely embed token data on-chain.  
TSB-P tokens are fully verifiable without relying on OP_RETURN or off-chain storage, preserving Bitcoin’s Layer 1 trust model.  
Now upgraded with **comprehensive compliance and regulatory features**.

---

## ✨ Proven Production Features

- **Native Bitcoin Layer 1 Integration** – Tokens live entirely inside Taproot script-paths  
- **Privacy-Preserving** – Token data remains hidden until spent via script-path reveal  
- **Wallet-Native Management** – Hybrid tokens recognized and managed by Bitcoin Core wallets  
- **Atomic Token Transfers** – Multi-input, multi-output splitting with automatic change handling  
- **BIP32 Deterministic Keys** – Standard Bitcoin derivation paths for key management  
- **Production-Grade UTXO Management** – Funding source selection + fee optimization  
- **Programmable** – Extendable via Taproot script branching and conditions  
- **Enterprise Token Splitting** – Complex transfers with accurate token accounting  
- **Metadata & Timestamp Support** – Flexible metadata and proof-of-existence timestamps  
- **Simple Stateless Verification** – Blockchain-only validation, no indexers  
- **Descriptor Wallet Compatible** – Modern Bitcoin Core support  
- **Advanced Transfer System** – Token splitting with proper change handling  

---

## 🔒 NEW: Compliance & Regulatory Features

- **KYC/AML Support** – Built-in identity verification requirements  
- **Jurisdiction Controls** – Restrict tokens to specific regions/countries  
- **Accredited Investor Gates** – Limit tokens to verified investors  
- **Time-Based Expiry** – Tokens that auto-expire at set times  
- **Transfer Restrictions** – Granular controls on token transfers  
- **Freeze & Clawback** – Optional issuer enforcement tools  
- **Privacy-Preserving Identity** – SHA256-hashed KYC data, never stored directly  
- **Multi-Jurisdictional Support** – Bitmap flags for 10+ jurisdictions  

---

## 🚀 Real Production Transfer Example

**Recently Completed Transfer:**
```bash
# Original token: SPLIT-FINAL3 (50,000,000 tokens)
# Transfer amount: 5,000,000 tokens
# Change amount: 45,000,000 tokens

# Funding TX: 3eefae4b780ce8587b357b957b2ecdaaaff7ff5ddbfbaa665a7dee9b9cf0484a
# Recipient TX: f55bb6b5054e077ec07a89dffbf59e77f27a8abfc72ec550cee7514ee74d0b7c
# Change TX: 312d5b1800a326d7da56028912f832501e82ec6a3f1238df9ef111f6d102f5e8

✅ Result: Atomic 3-transaction process completed successfully
```

---

## How It Works

1. **Token Creation** – A Taproot address is generated with a script embedding token metadata  
2. **Hybrid Mode** – Uses recipient’s public key as internal key for wallet recognition  
3. **Funding** – Bitcoin is sent to the generated address, locking in the token  
4. **Script-Path Spending** – Spending the UTXO reveals token data on-chain through the witness  
5. **Wallet Integration** – Tokens appear in standard Bitcoin wallets for native management  
6. **On-chain Verification** – Token authenticity and attributes are provable by decoding the witness  

---

## Token Data Structure (Enhanced)

Taproot script path with compliance fields:

```
OP_TRUE
OP_IF
  <"TSB">
  <tokenID> (16 bytes)
  <amount> (8 bytes, big-endian)
  <typeCode> (1 byte)
  OP_DROP OP_DROP OP_DROP OP_DROP
  <metadata> (variable length)
  <timestamp> (8 bytes, big-endian)
  OP_DROP OP_DROP

  # NEW: Compliance fields
  <complianceFlags> (4 bytes)
  <jurisdictionBits> (2 bytes)
  <identityHash> (variable length)
  <expiry> (8 bytes, big-endian)
  OP_DROP OP_DROP OP_DROP OP_DROP

  OP_TRUE
OP_ENDIF
```

### Enhanced Fields

| Field            | Description |
|------------------|-------------|
| complianceFlags  | 32-bit flags (KYC, accredited-only, freezeable, etc.) |
| jurisdictionBits | 16-bit bitmap of allowed jurisdictions |
| identityHash     | SHA256 hash of KYC identity data |
| expiry           | UNIX timestamp when token expires |

---

## Compliance Flags

| Flag                  | Bit | Description |
|-----------------------|-----|-------------|
| FLAG_KYC_REQUIRED     | 0   | Require KYC verification |
| FLAG_ACCREDITED_ONLY  | 1   | Accredited investors only |
| FLAG_NO_US_PERSONS    | 2   | Restrict US persons |
| FLAG_FREEZE_ENABLED   | 3   | Can be frozen by issuer |
| FLAG_CLAWBACK_ENABLED | 4   | Issuer clawback allowed |
| FLAG_TRANSFER_RESTRICTED | 5 | Transfer restrictions apply |

---

## Token Type Codes (Extended)

| typeCode | Meaning          | Compliance Defaults |
|----------|------------------|---------------------|
| 0        | Standard Token   | None |
| 1        | Stablecoin       | KYC Required |
| 2        | Security Token   | KYC + Accredited Only |
| 3        | Bond Token       | KYC + Transfer Restricted + Expiry |
| 4        | Equity Token     | KYC + Accredited + Freezeable |
| 5        | Restricted Token | KYC + Transfer Restricted |
| 6        | NFT              | Optional |
| 7        | Multi-Sig Token  | Signature Requirements |
| 8        | Governance Token | Optional |
| 9        | Vesting Token    | Time-locked |

---

## 🚀 Quick Start – Compliance Examples

### KYC-Required Stablecoin
```bash
./tsb-token-cli create --name "USDC" --amount 1000000 --typecode 1   --kyc-required --jurisdictions "US,EU,UK"   --metadata "USD Stablecoin" --autofund --autoreveal
```

### Security Token with Restrictions
```bash
./tsb-token-cli create --name "EQUITY" --amount 100 --typecode 2   --accredited-only --no-us --jurisdictions "EU,UK,SG"   --metadata "Company Equity Token" --expiry-days 365   --autofund --autoreveal
```

### Bond Token with Expiry
```bash
./tsb-token-cli create --name "BOND2025" --amount 1000 --typecode 3   --kyc-required --transfer-restricted --expiry-days 365   --metadata "Corporate Bond 2025" --autofund --autoreveal
```

### Check Token Compliance Status
```bash
./tsb-token-cli check-compliance <txid>
```

**Example Output:**
```
📋 Token Compliance Status:
  Token ID: USDC
  Type: Stablecoin
  Amount: 1000000

🔒 Compliance Requirements:
  KYC Required, Transfer Restricted

🌍 Allowed Jurisdictions: US, EU, UK

⏰ Expiry: 2025-12-31 23:59:59 (245 days remaining)

✅ Token is currently COMPLIANT
```

---

## Compliance Commands

| Command                | Description                  | Example |
|------------------------|------------------------------|---------|
| `check-compliance`      | Check token compliance status | `./tsb-token-cli check-compliance <txid>` |
| `--kyc-required`        | Require KYC verification     | `--kyc-required` |
| `--accredited-only`     | Limit to accredited investors | `--accredited-only` |
| `--no-us`               | Restrict US persons          | `--no-us` |
| `--freezeable`          | Enable freeze capability     | `--freezeable` |
| `--clawback`            | Enable clawback              | `--clawback` |
| `--transfer-restricted` | Restrict transfers           | `--transfer-restricted` |
| `--jurisdictions`       | Allowed countries            | `--jurisdictions "US,EU,UK"` |
| `--expiry-days`         | Expire after N days          | `--expiry-days 365` |
| `--identity-hash`       | Provide identity hash        | `--identity-hash <hash>` |

---

## Supported Jurisdictions

| Code | Jurisdiction      | Bit |
|------|-------------------|-----|
| US   | United States     | 0 |
| EU   | European Union    | 1 |
| UK   | United Kingdom    | 2 |
| CA   | Canada            | 3 |
| JP   | Japan             | 4 |
| SG   | Singapore         | 5 |
| CH   | Switzerland       | 6 |
| AU   | Australia         | 7 |
| HK   | Hong Kong         | 8 |
| AE   | UAE               | 9 |

---

## Security Considerations

- **Identity Privacy** – Only SHA256 hashes of KYC data stored on-chain  
- **Jurisdiction Enforcement** – Region checks embedded in token script  
- **Expiry Enforcement** – Tokens auto-invalidate past expiry  
- **Immutable Rules** – Compliance embedded, cannot be bypassed  
- **Transfer Validation** – Compliance checked on every transfer  
- **Audit Trail** – All compliance decisions verifiable on-chain  

---

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

# Ensure Bitcoin Core is running in testnet with wallet
bitcoin-cli -testnet createwallet "token_wallet"
bitcoin-cli -testnet -rpcwallet=token_wallet getbalance

# Build the CLI tool
go build -o tsb-token-cli taproot_token_cli.go taproot_token.go
```

---

## Workflow

Full token lifecycle:

1. **Create Hybrid Token** – Recognized in Bitcoin wallets  
2. **Reveal Token** – Embed token data on-chain  
3. **Verify Creation** – Confirm in wallet/CLI scan  
4. **Transfer Tokens** – Split into transfer + change  
5. **Verify Transfer** – On both sender + recipient sides

---

## Roadmap

### Version 2.0 – Compliance Edition ✅
- KYC/AML integration  
- Jurisdiction controls  
- Accredited investor gates  
- Time-based expiry  
- Transfer restrictions  
- Privacy-preserving identity  

### Version 2.1 (Active Development)
- Oracle-based compliance updates  
- Dynamic jurisdiction rules  
- Multi-signature compliance approvals  
- Regulatory reporting exports  

### Version 3.0 (Planned)
- Zero-knowledge proof compliance  
- Cross-chain compliance bridges  
- Automated regulatory reporting  
- Enterprise compliance dashboard  

---

## License

MIT License
