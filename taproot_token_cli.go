package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// ---------------------- Bitcoin CLI Runner ----------------------

const BitcoinCLI = "/usr/local/bin/bitcoin-cli -testnet -rpcwallet=token_wallet"

// const BitcoinCLI = "/usr/local/bin/bitcoin-cli -testnet -rpcwallet=recipient"

func RunBitcoinCommand(args string) (string, error) {
	cmd := exec.Command("sh", "-c", fmt.Sprintf("%s %s", BitcoinCLI, args))
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("bitcoin-cli error: %v - %s", err, string(output))
	}
	return strings.TrimSpace(string(output)), nil
}

// ---------------------- File Utilities ----------------------

type OutputData struct {
	Address         string    `json:"address"`
	ScriptHex       string    `json:"scriptHex"`
	ControlBlockHex string    `json:"controlBlockHex"`
	TokenData       TokenData `json:"tokenData"`
	DerivationPath  string    `json:"derivationPath"`
	WalletAddress   string    `json:"walletAddress"`
	RecipientPubKey string    `json:"recipientPubKey,omitempty"`
}

type FundingData struct {
	TxID           string `json:"txid"`
	Vout           uint32 `json:"vout"`
	Value          int64  `json:"value"`
	Address        string `json:"address"`
	DerivationPath string `json:"derivationPath,omitempty"`
}

func SaveOutputData(filename string, data *OutputData) error {
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filename, jsonData, 0644)
}

func LoadOutputData(filename string) (*OutputData, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	var outputData OutputData
	err = json.Unmarshal(data, &outputData)
	return &outputData, err
}

func SaveFundingData(filename string, data *FundingData) error {
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filename, jsonData, 0644)
}

func LoadFundingData(filename string) (*FundingData, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	var fundingData FundingData
	err = json.Unmarshal(data, &fundingData)
	return &fundingData, err
}

// ---------------------- Token Operations ----------------------

func CreateToken(tokenID string, amount uint64, metadata string, typeCode uint8) (*OutputData, error) {
	// Derive token key using BIP32 derivation path
	token, walletAddr, err := DeriveTokenKeyFromWallet(tokenID)
	if err != nil {
		return nil, fmt.Errorf("failed to derive token key: %w", err)
	}

	// Get the derivation path
	derivationPath := GetTokenDerivationPath(tokenID, Network == &chaincfg.TestNet3Params)

	// Prepare token data
	paddedTokenID := tokenID
	if len(tokenID) < 16 {
		paddedTokenID = tokenID + strings.Repeat("\x00", 16-len(tokenID))
	} else if len(tokenID) > 16 {
		paddedTokenID = tokenID[:16]
	}

	tokenData := &TokenData{
		TokenID:   paddedTokenID,
		Amount:    amount,
		Metadata:  metadata,
		Timestamp: uint64(time.Now().Unix()),
		TypeCode:  typeCode,
	}

	// Create Taproot script
	scriptTree, err := token.CreateTaprootOutput(tokenData)
	if err != nil {
		return nil, err
	}

	address, err := token.GetTaprootAddress()
	if err != nil {
		return nil, err
	}

	// Remove the importaddress command - not compatible with descriptor wallets
	// Instead, we'll just use the wallet's tracking capabilities

	// Create and save output data
	output := &OutputData{
		Address:         address,
		ScriptHex:       hex.EncodeToString(scriptTree.Script),
		ControlBlockHex: hex.EncodeToString(scriptTree.ControlBlock),
		TokenData:       *tokenData,
		DerivationPath:  derivationPath,
		WalletAddress:   walletAddr,
	}

	err = SaveOutputData("taproot_output.json", output)
	if err != nil {
		return nil, err
	}

	fmt.Println("✅ Token Created:")
	fmt.Println("  Address:", address)
	fmt.Println("  Token ID:", tokenID)
	fmt.Println("  Amount:", amount)
	fmt.Println("  Metadata:", metadata)
	fmt.Println("  Derivation Path:", derivationPath)
	fmt.Println("  Wallet Key Address:", walletAddr)

	return output, nil
}

// CreateHybridTaprootOutput creates a token script where the recipient's key is used
// as the internal key, making the address recognizable by their wallet
func CreateHybridTaprootOutput(token *TokenData, recipientPubKey *btcec.PublicKey) (*TaprootScriptTree, error) {
	builder := txscript.NewScriptBuilder()

	// TSB Pattern - Same script structure as before
	builder.AddOp(txscript.OP_TRUE)
	builder.AddOp(txscript.OP_IF)

	// Token marker and data fields
	builder.AddData([]byte("TSB"))
	builder.AddData([]byte(token.TokenID))
	amountBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(amountBytes, token.Amount)
	builder.AddData(amountBytes)
	builder.AddData([]byte{token.TypeCode})

	// Drop standard fields
	builder.AddOp(txscript.OP_DROP)
	builder.AddOp(txscript.OP_DROP)
	builder.AddOp(txscript.OP_DROP)
	builder.AddOp(txscript.OP_DROP)

	// Metadata and timestamp
	builder.AddData([]byte(token.Metadata))
	timestampBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(timestampBytes, token.Timestamp)
	builder.AddData(timestampBytes)

	// Drop optional fields
	builder.AddOp(txscript.OP_DROP)
	builder.AddOp(txscript.OP_DROP)

	// Ownership verification with the recipient's key (same as before)
	builder.AddData(recipientPubKey.SerializeCompressed())
	builder.AddOp(txscript.OP_CHECKSIG)

	builder.AddOp(txscript.OP_ENDIF)

	// Compile the script
	script, err := builder.Script()
	if err != nil {
		return nil, err
	}

	// Create the Taproot leaf
	var sizeBuf [binary.MaxVarintLen64]byte
	sz := binary.PutUvarint(sizeBuf[:], uint64(len(script)))
	leafInput := make([]byte, 1+sz+len(script))
	leafInput[0] = TapscriptLeafVersion
	copy(leafInput[1:], sizeBuf[:sz])
	copy(leafInput[1+sz:], script)

	// Hash the leaf
	leafHash := TaggedHash(TapscriptLeafTaggedHash, leafInput)
	merkleRoot := leafHash // Single leaf, so merkle root = leaf hash

	// KEY DIFFERENCE: Use the recipient's public key as the internal key
	// Note: We're now correctly using this for the ENTIRE address calculation
	internalKey := recipientPubKey

	// Compute the tweaked key
	tweakedPubKey := txscript.ComputeTaprootOutputKey(internalKey, merkleRoot)

	// Create control block (needed for script path spending)
	internalKeyBytes := internalKey.SerializeCompressed()[1:33] // x-only key
	comp := tweakedPubKey.SerializeCompressed()
	var parity byte = 0
	if comp[0] == 0x03 {
		parity = 1
	}
	cb0 := TapscriptLeafVersion | parity
	controlBlock := append([]byte{cb0}, internalKeyBytes...)

	// Return the complete script tree
	tree := &TaprootScriptTree{
		Script:        script,
		LeafHash:      leafHash,
		MerkleRoot:    merkleRoot,
		TweakedPubKey: tweakedPubKey,
		ControlBlock:  controlBlock,
		InternalKey:   internalKey, // Make sure we store the internal key for later use
	}

	return tree, nil
}

// CreateHybridToken creates a Taproot token that will be recognized by the recipient's wallet
func CreateHybridToken(tokenID string, amount uint64, metadata string, typeCode uint8, recipientPubKey *btcec.PublicKey) (*OutputData, error) {
	fmt.Println("🔄 Creating hybrid Taproot token...")

	// Prepare token data
	paddedTokenID := tokenID
	if len(tokenID) < 16 {
		paddedTokenID = tokenID + strings.Repeat("\x00", 16-len(tokenID))
	} else if len(tokenID) > 16 {
		paddedTokenID = tokenID[:16]
	}

	tokenData := &TokenData{
		TokenID:   paddedTokenID,
		Amount:    amount,
		Metadata:  metadata,
		Timestamp: uint64(time.Now().Unix()),
		TypeCode:  typeCode,
	}

	// Create Taproot output with recipient's public key as the internal key
	scriptTree, err := CreateHybridTaprootOutput(tokenData, recipientPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create hybrid token output: %w", err)
	}

	// Get the Taproot address
	comp := scriptTree.TweakedPubKey.SerializeCompressed()
	xOnly := comp[1:33]
	addr, err := btcutil.NewAddressTaproot(xOnly, Network)
	if err != nil {
		return nil, fmt.Errorf("failed to create address: %w", err)
	}

	// Create and save output data
	output := &OutputData{
		Address:         addr.EncodeAddress(),
		ScriptHex:       hex.EncodeToString(scriptTree.Script),
		ControlBlockHex: hex.EncodeToString(scriptTree.ControlBlock),
		TokenData:       *tokenData,
		RecipientPubKey: hex.EncodeToString(recipientPubKey.SerializeCompressed()),
	}

	fmt.Println("✅ Hybrid Token Created:")
	fmt.Println("  Address:", addr.EncodeAddress())
	fmt.Println("  Token ID:", tokenID)
	fmt.Println("  Amount:", amount)
	fmt.Println("  Metadata:", metadata)
	fmt.Println("  Type Code:", typeCode)
	fmt.Println("  Recipient Key:", hex.EncodeToString(recipientPubKey.SerializeCompressed()))

	return output, nil
}

func FundAddress(address string, btcAmount float64) (*FundingData, error) {
	txid, err := RunBitcoinCommand(fmt.Sprintf("sendtoaddress %s %.8f", address, btcAmount))
	if err != nil {
		return nil, err
	}

	// Generate a new address correctly using the wallet
	newAddress, err := RunBitcoinCommand("getnewaddress")
	if err != nil {
		return nil, err
	}

	// Use RunBitcoinCommand for the generate command to ensure wallet is specified
	_, err = RunBitcoinCommand(fmt.Sprintf("generatetoaddress 1 %s", newAddress))
	if err != nil {
		return nil, err
	}

	raw, err := RunBitcoinCommand(fmt.Sprintf("getrawtransaction %s true", txid))
	if err != nil {
		return nil, err
	}

	var tx map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &tx); err != nil {
		return nil, err
	}

	vouts := tx["vout"].([]interface{})
	for i, v := range vouts {
		vout := v.(map[string]interface{})
		spk := vout["scriptPubKey"].(map[string]interface{})
		if addr, ok := spk["address"].(string); ok && addr == address {
			value := int64(vout["value"].(float64) * 100_000_000)
			funding := &FundingData{
				TxID:    txid,
				Vout:    uint32(i),
				Value:   value,
				Address: address,
			}
			SaveFundingData("funding_data.json", funding)
			return funding, nil
		}
	}

	return nil, errors.New("no matching output found")
}

// DescriptorWalletTransferToken - transfers a detected token using wallet signing for descriptor wallets
func DescriptorWalletTransferToken(tokenUTXO *FundingData, tokenData *TokenData,
	transferAmount uint64, recipientAddress string, feeRate int64) (string, *FundingData, error) {

	fmt.Println("🔧 Descriptor wallet transfer for detected token...")
	fmt.Printf("🔍 Token UTXO address: %s\n", tokenUTXO.Address)

	// For descriptor wallets, we can't extract the private key directly
	// Instead, we'll create a transaction and let the wallet sign what it can

	fmt.Println("🔄 Creating transaction for wallet signing...")

	// Create a basic transaction structure
	prevHash, err := chainhash.NewHashFromStr(tokenUTXO.TxID)
	if err != nil {
		return "", nil, fmt.Errorf("invalid UTXO TXID: %w", err)
	}

	outpoint := wire.NewOutPoint(prevHash, tokenUTXO.Vout)
	txIn := wire.NewTxIn(outpoint, nil, nil)

	tx := wire.NewMsgTx(2)
	tx.AddTxIn(txIn)

	// Add output to recipient address
	recipientAddr, err := btcutil.DecodeAddress(recipientAddress, Network)
	if err != nil {
		return "", nil, fmt.Errorf("invalid recipient address: %w", err)
	}

	recipientScript, err := txscript.PayToAddrScript(recipientAddr)
	if err != nil {
		return "", nil, fmt.Errorf("failed to create recipient script: %w", err)
	}

	// Calculate fee and output amount
	const dustAmount = int64(10000)
	fee := int64(1000)
	outputAmount := tokenUTXO.Value - fee

	if outputAmount < dustAmount {
		return "", nil, fmt.Errorf("insufficient funds: UTXO value %d too small after fee %d", tokenUTXO.Value, fee)
	}

	tx.AddTxOut(wire.NewTxOut(outputAmount, recipientScript))

	// First, try to get the wallet to sign this basic transaction
	var buf bytes.Buffer
	tx.Serialize(&buf)
	txHex := hex.EncodeToString(buf.Bytes())

	fmt.Println("🔐 Attempting wallet signing...")
	signedTxJSON, err := RunBitcoinCommand(fmt.Sprintf("signrawtransactionwithwallet %s", txHex))
	if err != nil {
		return "", nil, fmt.Errorf("failed to sign with wallet: %w", err)
	}

	var signed struct {
		Hex      string `json:"hex"`
		Complete bool   `json:"complete"`
		Errors   []struct {
			Txid  string `json:"txid"`
			Vout  int    `json:"vout"`
			Error string `json:"error"`
		} `json:"errors"`
	}
	if err := json.Unmarshal([]byte(signedTxJSON), &signed); err != nil {
		return "", nil, fmt.Errorf("failed to parse signed tx: %w", err)
	}

	if !signed.Complete {
		fmt.Println("⚠️ Wallet couldn't fully sign the transaction")
		if len(signed.Errors) > 0 {
			for _, e := range signed.Errors {
				fmt.Printf("   Error: %s\n", e.Error)
			}
		}
		return "", nil, fmt.Errorf("wallet signing incomplete - this UTXO might not be spendable by the wallet")
	}

	// If we get here, the wallet was able to sign it (shouldn't happen for Taproot script path)
	fmt.Println("✅ Wallet signed the transaction successfully")

	// Try to broadcast the signed transaction
	txid, err := RunBitcoinCommand(fmt.Sprintf("sendrawtransaction %s", signed.Hex))
	if err != nil {
		return "", nil, fmt.Errorf("failed to broadcast transaction: %w", err)
	}

	recipientFunding := &FundingData{
		TxID:    txid,
		Vout:    0,
		Value:   outputAmount,
		Address: recipientAddress,
	}

	fmt.Printf("✅ Token transferred successfully!\n")
	fmt.Printf("   Transaction: %s\n", txid)
	fmt.Printf("   Recipient will receive the token at: %s\n", recipientAddress)

	return txid, recipientFunding, nil
}

// AlternativeTransferToken - Alternative approach for tokens that can't be spent normally
func AlternativeTransferToken(tokenUTXO *FundingData, tokenData *TokenData,
	transferAmount uint64, recipientAddress string, feeRate int64) (string, *FundingData, error) {

	fmt.Println("🔧 Alternative transfer approach...")
	fmt.Printf("🔍 This will create a new token and send the Bitcoin value to the recipient\n")
	fmt.Printf("🔍 The recipient can then extract the token data from the transaction\n")

	// Get a funding UTXO from the wallet (not the token UTXO)
	unspentJSON, err := RunBitcoinCommand("listunspent")
	if err != nil {
		return "", nil, fmt.Errorf("failed to list unspent outputs: %w", err)
	}

	var unspent []map[string]interface{}
	if err := json.Unmarshal([]byte(unspentJSON), &unspent); err != nil {
		return "", nil, fmt.Errorf("failed to parse unspent outputs: %w", err)
	}

	// Find a suitable UTXO that's NOT the token UTXO
	var fundingUTXO map[string]interface{}
	for _, utxo := range unspent {
		txid, _ := utxo["txid"].(string)
		vout, _ := utxo["vout"].(float64)

		// Skip the token UTXO
		if txid == tokenUTXO.TxID && uint32(vout) == tokenUTXO.Vout {
			continue
		}

		amount, _ := utxo["amount"].(float64)
		if amount > 0.00001 { // At least 1000 sats
			fundingUTXO = utxo
			break
		}
	}

	if fundingUTXO == nil {
		return "", nil, fmt.Errorf("no suitable funding UTXO found")
	}

	fundingTxid, _ := fundingUTXO["txid"].(string)
	fundingVout := uint32(fundingUTXO["vout"].(float64))
	fundingAmount := int64(fundingUTXO["amount"].(float64) * 100000000)

	fmt.Printf("🔍 Using funding UTXO: %s:%d (%d sats)\n", fundingTxid, fundingVout, fundingAmount)

	// Create a new token with the same data but for the recipient
	// 1. CREATE DETERMINISTIC RECIPIENT TOKEN
	recipientToken, err := NewTaprootToken()
	if err != nil {
		return "", nil, fmt.Errorf("failed to create recipient token: %w", err)
	}

	// Create token data for the transfer amount
	transferTokenData := &TokenData{
		TokenID:   tokenData.TokenID,
		Amount:    transferAmount,
		TypeCode:  tokenData.TypeCode,
		Metadata:  tokenData.Metadata + fmt.Sprintf(" [Transferred from %s]", tokenUTXO.TxID[:8]),
		Timestamp: uint64(time.Now().Unix()),
	}

	_, err = recipientToken.CreateTaprootOutput(transferTokenData)
	if err != nil {
		return "", nil, fmt.Errorf("failed to create recipient token output: %w", err)
	}

	recipientTokenAddr, err := recipientToken.GetTaprootAddress()
	if err != nil {
		return "", nil, fmt.Errorf("failed to get recipient token address: %w", err)
	}

	fmt.Printf("✅ Created new token address for recipient: %s\n", recipientTokenAddr)

	// Send some Bitcoin to this new token address to fund it
	const tokenFunding = 0.00001 // 1000 sats
	fmt.Printf("🔄 Funding the new token address with %.8f BTC...\n", tokenFunding)

	fundTxid, err := RunBitcoinCommand(fmt.Sprintf("sendtoaddress %s %.8f", recipientTokenAddr, tokenFunding))
	if err != nil {
		return "", nil, fmt.Errorf("failed to fund token address: %w", err)
	}

	// Mine a block to confirm the funding
	newAddress, err := RunBitcoinCommand("getnewaddress")
	if err != nil {
		return "", nil, err
	}
	_, err = RunBitcoinCommand(fmt.Sprintf("generatetoaddress 1 %s", newAddress))
	if err != nil {
		return "", nil, err
	}

	fmt.Printf("✅ Token funded: %s\n", fundTxid)

	// Spend the new token to the recipient's address
	fmt.Println("🔄 Revealing token to recipient...")

	spendTx, err := recipientToken.CreateScriptPathSpendingTx(
		fundTxid, 0, 1000, recipientAddress, 2000,
	)
	if err != nil {
		return "", nil, fmt.Errorf("failed to create spend tx: %w", err)
	}

	var spendBuf bytes.Buffer
	spendTx.Serialize(&spendBuf)
	spendHex := hex.EncodeToString(spendBuf.Bytes())

	finalTxid, err := RunBitcoinCommand(fmt.Sprintf("sendrawtransaction %s", spendHex))
	if err != nil {
		return "", nil, fmt.Errorf("failed to broadcast spend tx: %w", err)
	}

	// Save the recipient's token key for them
	err = recipientToken.SavePrivateKey("recipient_token_key.hex")
	if err != nil {
		fmt.Printf("⚠️ Warning: Could not save recipient key: %v\n", err)
	} else {
		fmt.Println("💾 Saved recipient token key to: recipient_token_key.hex")
		fmt.Println("   Send this file to the recipient so they can manage their token")
	}

	recipientFunding := &FundingData{
		TxID:    finalTxid,
		Vout:    0,
		Value:   300, // Approximate after fees
		Address: recipientAddress,
	}

	fmt.Printf("✅ Alternative token transfer completed!\n")
	fmt.Printf("   New token transaction: %s\n", finalTxid)
	fmt.Printf("   Recipient can extract token data from this transaction\n")
	fmt.Printf("   Token data embedded: %d %s tokens\n", transferAmount, tokenData.TokenID)

	return finalTxid, recipientFunding, nil
}

func SpendToken(destination string) (string, error) {
	fmt.Println("\n🔍 DEBUG: Starting SpendToken")

	// Load token data first to get derivation information
	outputData, err := LoadOutputData("taproot_output.json")
	if err != nil {
		return "", err
	}
	fmt.Println("🔍 DEBUG: Output data loaded")

	// Check if this is a hybrid token (has RecipientPubKey)
	isHybridToken := outputData.RecipientPubKey != ""
	if isHybridToken {
		fmt.Println("✅ Detected a hybrid token - will maintain hybrid mode")
	}

	// Load funding data
	fundingData, err := LoadFundingData("funding_data.json")
	if err != nil {
		return "", err
	}
	fmt.Println("🔍 DEBUG: Funding data loaded")
	fmt.Printf("🔍 DEBUG: Funding TxID: %s, Vout: %d, Value: %d\n",
		fundingData.TxID, fundingData.Vout, fundingData.Value)

	// Check if this is a BIP32-derived token
	var token *TaprootToken
	if outputData.DerivationPath != "" && outputData.WalletAddress != "" {
		// This is a BIP32 token - we need to create a token using the same script
		fmt.Println("🔍 DEBUG: Using BIP32 token reconstruction")

		// Re-derive the token key using the saved token ID
		tokenID := strings.TrimRight(outputData.TokenData.TokenID, "\x00")
		fmt.Printf("🔍 DEBUG: Re-deriving token with ID: %s\n", tokenID)
		token, _, err = DeriveTokenKeyFromWallet(tokenID)
		if err != nil {
			return "", fmt.Errorf("❌ Failed to re-derive token from wallet: %w", err)
		}
		fmt.Println("✅ Re-used original wallet-derived key")
	} else {
		// Standard token from file
		keyHex, err := os.ReadFile("token_key.hex")
		if err != nil {
			return "", err
		}
		fmt.Println("🔍 DEBUG: Private key loaded from token_key.hex")

		token, err = LoadTaprootToken(string(keyHex))
		if err != nil {
			return "", err
		}
	}

	fmt.Println("🔍 DEBUG: Token loaded")

	// Important: Decode the script and control block from the saved data
	scriptBytes, err := hex.DecodeString(outputData.ScriptHex)
	if err != nil {
		return "", err
	}

	controlBlockBytes, err := hex.DecodeString(outputData.ControlBlockHex)
	if err != nil {
		return "", err
	}

	fmt.Printf("🔍 DEBUG: Script length: %d bytes\n", len(scriptBytes))
	fmt.Printf("🔍 DEBUG: Control block length: %d bytes\n", len(controlBlockBytes))

	// Need to fully initialize the script tree
	// First check if control block is valid (must be at least 33 bytes)
	if len(controlBlockBytes) < 33 {
		return "", fmt.Errorf("invalid control block length: %d", len(controlBlockBytes))
	}

	// Extract internal key from control block (bytes 1-33)
	internalKeyBytes := controlBlockBytes[1:33]
	fmt.Printf("🔍 DEBUG: Internal key: %x\n", internalKeyBytes)

	// Create internal key
	internalKey, err := btcec.ParsePubKey(append([]byte{0x02}, internalKeyBytes...))
	if err != nil {
		return "", fmt.Errorf("failed to parse internal key: %w", err)
	}

	// Create a proper leaf hash
	var sizeBuf [binary.MaxVarintLen64]byte
	sz := binary.PutUvarint(sizeBuf[:], uint64(len(scriptBytes)))
	leafInput := make([]byte, 1+sz+len(scriptBytes))
	leafInput[0] = TapscriptLeafVersion
	copy(leafInput[1:], sizeBuf[:sz])
	copy(leafInput[1+sz:], scriptBytes)

	leafHash := TaggedHash(TapscriptLeafTaggedHash, leafInput)

	// Merkle root is just the leaf hash in this case
	merkleRoot := leafHash

	// Compute tweaked pubkey
	tweakedPubKey := txscript.ComputeTaprootOutputKey(internalKey, merkleRoot)

	// Fully initialize script tree with all required fields
	token.ScriptTree = &TaprootScriptTree{
		Script:        scriptBytes,
		LeafHash:      leafHash,
		MerkleRoot:    merkleRoot,
		TweakedPubKey: tweakedPubKey,
		ControlBlock:  controlBlockBytes,
	}

	// Get the address for verification
	reconstructedAddress, err := token.GetTaprootAddress()
	if err != nil {
		return "", err
	}

	fmt.Println("🔍 DEBUG: --- FULL DEBUG LOG START ---")
	fmt.Printf("🔍 DEBUG: Saved script hex: %s\n", outputData.ScriptHex)
	fmt.Printf("🔍 DEBUG: Saved control block hex: %s\n", outputData.ControlBlockHex)
	fmt.Printf("🔍 DEBUG: Saved address: %s\n", outputData.Address)

	fmt.Printf("🔍 DEBUG: Loaded token:\n")
	fmt.Printf("    TokenID:   %s\n", outputData.TokenData.TokenID)
	fmt.Printf("    Amount:    %d\n", outputData.TokenData.Amount)
	fmt.Printf("    Metadata:  %s\n", outputData.TokenData.Metadata)
	fmt.Printf("    Timestamp: %d\n", outputData.TokenData.Timestamp)

	fmt.Println("🔍 DEBUG: Reconstructed tweaked pubkey:")
	fmt.Printf("    %x\n", tweakedPubKey.SerializeCompressed())

	fmt.Println("🔍 DEBUG: Generated Taproot address from reconstructed data:")
	fmt.Println("    ", reconstructedAddress)

	fmt.Println("🔍 DEBUG: --- FULL DEBUG LOG END ---")

	// Verify the address matches - this is important
	fmt.Printf("🔍 DEBUG: Address match: %v\n", reconstructedAddress == outputData.Address)
	if reconstructedAddress != outputData.Address {
		fmt.Printf("⚠️ WARNING: Address mismatch - will attempt to proceed anyway\n")
		fmt.Printf("    Expected: %s\n", outputData.Address)
		fmt.Printf("    Got:      %s\n", reconstructedAddress)
	}

	// Get the address from the token to verify it matches the funding
	address, err := token.GetTaprootAddress()
	if err != nil {
		return "", err
	}
	fmt.Printf("🔍 DEBUG: Address matches funding: %v\n", address == fundingData.Address)

	// NEW CODE: For hybrid tokens, get the destination's public key and create a hybrid output
	if isHybridToken {
		fmt.Println("🔍 DEBUG: Preparing hybrid output for destination")

		// Get the public key for the destination address
		addrInfoOutput, err := RunBitcoinCommand(fmt.Sprintf("getaddressinfo %s", destination))
		if err != nil {
			fmt.Printf("⚠️ Warning: Failed to get address info: %v\n", err)
		} else {
			var addrInfo map[string]interface{}
			if err := json.Unmarshal([]byte(addrInfoOutput), &addrInfo); err != nil {
				fmt.Printf("⚠️ Warning: Failed to parse address info: %v\n", err)
			} else {
				// Try to extract pubkey - handle both normal and Taproot addresses
				var pubkeyHex string

				// Try direct pubkey field first
				if val, ok := addrInfo["pubkey"].(string); ok {
					pubkeyHex = val
					fmt.Printf("🔍 DEBUG: Found direct pubkey: %s\n", pubkeyHex)
				} else if embedded, ok := addrInfo["embedded"].(map[string]interface{}); ok {
					// Try embedded.inner_pubkey for Taproot addresses
					if val, ok := embedded["inner_pubkey"].(string); ok {
						pubkeyHex = val
						fmt.Printf("🔍 DEBUG: Found embedded pubkey: %s\n", pubkeyHex)
					}
				}

				if pubkeyHex != "" {
					pubkeyBytes, err := hex.DecodeString(pubkeyHex)
					if err != nil {
						fmt.Printf("⚠️ Warning: Invalid pubkey hex: %v\n", err)
					} else {
						destinationPubKey, err := btcec.ParsePubKey(pubkeyBytes)
						if err != nil {
							fmt.Printf("⚠️ Warning: Failed to parse pubkey: %v\n", err)
						} else {
							// Create a hybrid Taproot output using the destination's pubkey
							fmt.Println("✅ Creating hybrid Taproot output for destination wallet")
							scriptTree, err := CreateHybridTaprootOutput(&outputData.TokenData, destinationPubKey)
							if err != nil {
								fmt.Printf("⚠️ Warning: Failed to create hybrid output: %v\n", err)
							} else {
								// Update the token's script tree to use hybrid mode
								token.ScriptTree = scriptTree

								// Get the new address to verify it
								newAddr, _ := token.GetTaprootAddress()
								fmt.Printf("🔍 DEBUG: New hybrid address: %s\n", newAddr)
							}
						}
					}
				} else {
					fmt.Println("⚠️ Could not find pubkey in address info, using standard mode")
				}
			}
		}
	}

	// Recreate the spending transaction with the updated witness structure
	tx, err := token.CreateScriptPathSpendingTx(
		fundingData.TxID,
		fundingData.Vout,
		fundingData.Value,
		destination,
		2000,
	)
	if err != nil {
		return "", err
	}

	// Debug the witness structure
	fmt.Println("🔍 DEBUG: Witness structure:")
	for i, item := range tx.TxIn[0].Witness {
		fmt.Printf("  Item %d: %x (length: %d)\n", i, item, len(item))
	}

	var buf bytes.Buffer
	tx.Serialize(&buf)
	txHex := hex.EncodeToString(buf.Bytes())

	// Save the raw transaction for manual inspection
	err = os.WriteFile("spending_tx.hex", []byte(txHex), 0644)
	if err != nil {
		return "", err
	}
	fmt.Println("🔍 DEBUG: Transaction hex saved to spending_tx.hex")

	// Try to decode the transaction to verify validity
	decodeCmd := fmt.Sprintf("decoderawtransaction %s", txHex)
	_, err = RunBitcoinCommand(decodeCmd)
	if err != nil {
		fmt.Printf("🔍 DEBUG: Transaction decode error: %v\n", err)
	} else {
		fmt.Println("🔍 DEBUG: Transaction decoded successfully")
	}

	// Send the raw transaction
	fmt.Println("🔍 DEBUG: Sending raw transaction...")
	txid, err := RunBitcoinCommand(fmt.Sprintf("sendrawtransaction %s", txHex))
	if err != nil {
		return "", err
	}

	fmt.Println("✅ Revealed & Sent TX:", txid)
	return txid, nil
}

func RevealHybridToken(destination string) (string, error) {
	fmt.Println("\n🔍 DEBUG: Starting RevealHybridToken with direct wallet approach")

	// Load token data
	outputData, err := LoadOutputData("taproot_output.json")
	if err != nil {
		return "", err
	}

	// Load funding data
	fundingData, err := LoadFundingData("funding_data.json")
	if err != nil {
		return "", err
	}

	// DEBUG: Print funding data
	fmt.Printf("🔍 DEBUG: Using funding transaction: %s:%d (%d sats)\n",
		fundingData.TxID, fundingData.Vout, fundingData.Value)

	// Get a regular wallet address directly
	fmt.Println("🔍 DEBUG: Getting new wallet address")
	walletAddress, err := RunBitcoinCommand("getnewaddress \"TSBToken\" \"bech32m\"")
	if err != nil {
		return "", fmt.Errorf("failed to get address: %w", err)
	}

	fmt.Printf("✅ Using wallet address directly: %s\n", walletAddress)

	// Load token key
	keyHex, err := os.ReadFile("token_key.hex")
	if err != nil {
		return "", fmt.Errorf("failed to read token key: %w", err)
	}

	token, err := LoadTaprootToken(strings.TrimSpace(string(keyHex)))
	if err != nil {
		return "", fmt.Errorf("failed to load token key: %w", err)
	}

	// Setup script tree from saved data
	scriptBytes, err := hex.DecodeString(outputData.ScriptHex)
	if err != nil {
		return "", err
	}

	controlBlockBytes, err := hex.DecodeString(outputData.ControlBlockHex)
	if err != nil {
		return "", err
	}

	// Initialize script tree basics
	if len(controlBlockBytes) < 33 {
		return "", fmt.Errorf("invalid control block length: %d", len(controlBlockBytes))
	}

	internalKeyBytes := controlBlockBytes[1:33]
	internalKey, err := btcec.ParsePubKey(append([]byte{0x02}, internalKeyBytes...))
	if err != nil {
		return "", fmt.Errorf("failed to parse internal key: %w", err)
	}

	// Create leaf hash and merkle root
	var sizeBuf [binary.MaxVarintLen64]byte
	sz := binary.PutUvarint(sizeBuf[:], uint64(len(scriptBytes)))
	leafInput := make([]byte, 1+sz+len(scriptBytes))
	leafInput[0] = TapscriptLeafVersion
	copy(leafInput[1:], sizeBuf[:sz])
	copy(leafInput[1+sz:], scriptBytes)

	leafHash := TaggedHash(TapscriptLeafTaggedHash, leafInput)
	merkleRoot := leafHash
	tweakedPubKey := txscript.ComputeTaprootOutputKey(internalKey, merkleRoot)

	// Set script tree
	token.ScriptTree = &TaprootScriptTree{
		Script:        scriptBytes,
		LeafHash:      leafHash,
		MerkleRoot:    merkleRoot,
		TweakedPubKey: tweakedPubKey,
		ControlBlock:  controlBlockBytes,
	}

	// Create transaction DIRECTLY to the wallet address (this is the key)
	tx, err := token.CreateScriptPathSpendingTx(
		fundingData.TxID,
		fundingData.Vout,
		fundingData.Value,
		walletAddress, // Use the wallet's address directly
		2000,
	)
	if err != nil {
		return "", err
	}

	// Serialize and broadcast
	var buf bytes.Buffer
	tx.Serialize(&buf)
	txHex := hex.EncodeToString(buf.Bytes())

	err = os.WriteFile("reveal_direct_tx.hex", []byte(txHex), 0644)
	if err != nil {
		return "", err
	}

	txid, err := RunBitcoinCommand(fmt.Sprintf("sendrawtransaction %s", txHex))
	if err != nil {
		return "", err
	}

	fmt.Println("✅ Revealed & Sent TX:", txid)
	fmt.Printf("✅ Token is now at address %s and will be visible in your wallet\n",
		walletAddress)

	return txid, nil
}

// ManageReceivedToken - New approach using wallet signing
func ManageReceivedToken(txid string) error {
	fmt.Printf("🔧 Managing received token from transaction: %s\n", txid)

	// Extract token data from the transaction
	tokenData, err := ExtractTokenFromTxID(txid)
	if err != nil {
		return fmt.Errorf("failed to extract token data: %w", err)
	}

	fmt.Printf("✅ Found token: %s (%d tokens)\n", tokenData.TokenID, tokenData.Amount)

	// Find the UTXO in recipient's wallet that came from this transaction
	utxo, err := findUTXOFromTransaction(txid)
	if err != nil {
		return fmt.Errorf("failed to find UTXO in wallet: %w", err)
	}

	fmt.Printf("✅ Found UTXO in your wallet: %s:%d (%d sats)\n",
		utxo.TxID, utxo.Vout, utxo.Value)

	fmt.Printf("🎉 Token is ready for wallet-native management!\n")
	fmt.Printf("   Your wallet can sign transactions for this token.\n")
	fmt.Printf("   No hex files needed!\n")

	return nil
}

// Helper function to find UTXO from transaction
func findUTXOFromTransaction(txid string) (*FundingData, error) {
	unspentJSON, err := RunBitcoinCommand("listunspent")
	if err != nil {
		return nil, err
	}

	var unspent []map[string]interface{}
	if err := json.Unmarshal([]byte(unspentJSON), &unspent); err != nil {
		return nil, err
	}

	for _, utxo := range unspent {
		utxoTxid, _ := utxo["txid"].(string)
		if utxoTxid == txid {
			vout, _ := utxo["vout"].(float64)
			amount, _ := utxo["amount"].(float64)
			address, _ := utxo["address"].(string)

			return &FundingData{
				TxID:    txid,
				Vout:    uint32(vout),
				Value:   int64(amount * 100000000),
				Address: address,
			}, nil
		}
	}

	return nil, fmt.Errorf("UTXO not found in wallet")
}

// Add to TransferToken function in taproot_token_cli.go
func TransferToken(tokenKeyHex string, tokenUTXO *FundingData, tokenData *TokenData,
	transferAmount uint64, recipientAddress string, feeRate int64) (string, *FundingData, error) {
	// Load token key data
	token, err := LoadTaprootToken(tokenKeyHex)
	if err != nil {
		return "", nil, fmt.Errorf("failed to load token key: %w", err)
	}

	// Validate canonical token ID
	if !ValidateCanonicalTokenID(tokenData.TokenID, tokenUTXO.TxID) {
		return "", nil, fmt.Errorf("canonical token ID mismatch: tokenID does not match txid prefix")
	}

	// Create the token split transaction
	tx, err := token.SplitToken(
		tokenUTXO.TxID,
		tokenUTXO.Vout,
		tokenUTXO.Value,
		tokenData,
		transferAmount,
		recipientAddress,
		feeRate,
	)

	// If we don't have enough funds, try with multiple inputs
	if err != nil && strings.Contains(err.Error(), "insufficient funds") {
		// Extract how much we need vs how much we have
		parts := strings.Split(err.Error(), "need ")
		if len(parts) > 1 {
			needHaveParts := strings.Split(parts[1], ", have ")
			if len(needHaveParts) > 1 {
				needed, nerr := strconv.ParseInt(needHaveParts[0], 10, 64)
				have, herr := strconv.ParseInt(needHaveParts[1], 10, 64)
				if nerr == nil && herr == nil {
					additionalNeeded := needed - have
					fmt.Printf("⚠️ Insufficient funds in token UTXO. Need %d more satoshis\n", additionalNeeded)
					fmt.Println("🔄 Attempting to use additional inputs from wallet...")

					// Try again with multiple inputs
					tx, err = token.CreateMultiInputTokenTransaction(
						tokenUTXO,
						additionalNeeded+1000, // Add a buffer
						tokenData,
						transferAmount,
						recipientAddress,
						feeRate,
					)
				}
			}
		}
	}

	if err != nil {
		return "", nil, err
	}

	// Serialize and broadcast transaction
	var buf bytes.Buffer
	tx.Serialize(&buf)
	txHex := hex.EncodeToString(buf.Bytes())

	err = os.WriteFile("transfer_tx.hex", []byte(txHex), 0644)
	if err != nil {
		return "", nil, fmt.Errorf("failed to save transaction hex: %w", err)
	}

	txid, err := RunBitcoinCommand(fmt.Sprintf("sendrawtransaction %s", txHex))
	if err != nil {
		return "", nil, fmt.Errorf("failed to broadcast transaction: %w", err)
	}

	// Record the recipient funding info
	recipientFunding := &FundingData{
		TxID:    txid,
		Vout:    0,
		Value:   10000,
		Address: recipientAddress,
	}

	return txid, recipientFunding, nil
}

// Add to taproot_token_cli.go
func RecoverTokensFromDerivationPaths() ([]*TokenWithFunding, error) {
	fmt.Println("🔍 Searching for tokens using BIP32 derivation paths...")

	// Get all wallet addresses and labels
	addressesJSON, err := RunBitcoinCommand("listaddressgroupings")
	if err != nil {
		return nil, fmt.Errorf("failed to list addresses: %w", err)
	}

	var addresses [][]interface{}
	if err := json.Unmarshal([]byte(addressesJSON), &addresses); err != nil {
		return nil, fmt.Errorf("failed to parse addresses: %w", err)
	}

	tokens := []*TokenWithFunding{}

	// Check each address for token-related labels
	for _, group := range addresses {
		for _, addrData := range group {
			addr, ok := addrData.([]interface{})
			if !ok || len(addr) < 2 {
				continue
			}

			addrStr, ok := addr[0].(string)
			if !ok {
				continue
			}

			// Get address info to check labels
			addrInfoJSON, err := RunBitcoinCommand(fmt.Sprintf("getaddressinfo %s", addrStr))
			if err != nil {
				continue
			}

			var addrInfo map[string]interface{}
			if err := json.Unmarshal([]byte(addrInfoJSON), &addrInfo); err != nil {
				continue
			}

			// Check for our token path label pattern
			labels, ok := addrInfo["labels"].([]interface{})
			if !ok {
				continue
			}

			for _, label := range labels {
				labelStr, ok := label.(string)
				if !ok {
					continue
				}

				// Check if this is a token derivation path label
				if strings.HasPrefix(labelStr, "TokenPath:") {
					parts := strings.Split(labelStr, ":")
					if len(parts) < 3 {
						continue
					}

					path := parts[1]
					tokenID := parts[2]

					fmt.Printf("✅ Found token at derivation path %s with ID %s\n", path, tokenID)

					// Get unspent outputs for this address
					unspentJSON, err := RunBitcoinCommand(fmt.Sprintf("listunspent 0 9999999 [%s]", addrStr))
					if err != nil {
						continue
					}

					var unspent []map[string]interface{}
					if err := json.Unmarshal([]byte(unspentJSON), &unspent); err != nil {
						continue
					}

					for _, utxo := range unspent {
						txid, ok := utxo["txid"].(string)
						if !ok {
							continue
						}

						vout, ok := utxo["vout"].(float64)
						if !ok {
							continue
						}

						amount, ok := utxo["amount"].(float64)
						if !ok {
							continue
						}

						// Get transaction to extract token data
						_, err = RunBitcoinCommand(fmt.Sprintf("getrawtransaction %s true", txid))
						if err != nil {
							continue
						}

						// Try to extract token data from transaction
						// [This would need to be implemented based on your token format]

						// For now, create a placeholder token
						tokenWithFunding := &TokenWithFunding{
							TokenData: &TokenData{
								TokenID:  tokenID,
								Amount:   1, // Placeholder
								Metadata: "Recovered from " + path,
							},
							Funding: &FundingData{
								TxID:           txid,
								Vout:           uint32(vout),
								Value:          int64(amount * 100000000),
								Address:        addrStr,
								DerivationPath: path,
							},
							Filename: "recovered",
						}

						tokens = append(tokens, tokenWithFunding)
					}
				}
			}
		}
	}

	return tokens, nil
}

func ListTokensInWallet() ([]*TokenWithFunding, error) {
	fmt.Println("🔍 DEBUG: Starting token scan...")

	// Debug: List files with _output.json
	files, _ := os.ReadDir(".")
	fmt.Println("🔍 DEBUG: Looking for token files:")
	foundFiles := false
	for _, file := range files {
		if strings.HasSuffix(file.Name(), "_output.json") {
			fmt.Printf("  Found token file: %s\n", file.Name())
			foundFiles = true
		}
	}
	if !foundFiles {
		fmt.Println("  No token output files found - create a token first")
	}

	// Get unspent outputs from the wallet
	unspentJSON, err := RunBitcoinCommand("listunspent")
	if err != nil {
		fmt.Printf("🔍 DEBUG: Error listing unspent outputs: %v\n", err)
		return nil, fmt.Errorf("failed to list unspent outputs: %w", err)
	}

	fmt.Println("🔍 DEBUG: Found wallet UTXOs:")
	// Initialize unspent variable before json.Unmarshal
	var unspent []map[string]interface{}
	if err = json.Unmarshal([]byte(unspentJSON), &unspent); err != nil {
		fmt.Printf("🔍 DEBUG: Error parsing unspent outputs: %v\n", err)
		return nil, fmt.Errorf("failed to parse unspent outputs: %w", err)
	}

	if len(unspent) == 0 {
		fmt.Println("  No unspent outputs found in wallet")
	} else {
		for i, utxo := range unspent {
			txid, _ := utxo["txid"].(string)
			vout, _ := utxo["vout"].(float64)
			amount, _ := utxo["amount"].(float64)
			fmt.Printf("  UTXO %d: %s:%d (%.8f BTC)\n", i+1, txid, int(vout), amount)
		}
	}

	tokens := []*TokenWithFunding{}

	// Try to find tokens in wallet by examining local files
	for _, file := range files {
		if strings.HasSuffix(file.Name(), "_output.json") {
			outputData, err := LoadOutputData(file.Name())
			if err != nil {
				fmt.Printf("🔍 DEBUG: Error loading output data from %s: %v\n", file.Name(), err)
				continue
			}

			// Check if we have corresponding funding data
			fundingFile := strings.Replace(file.Name(), "_output.json", "_funding.json", 1)
			var fundingData *FundingData
			fundingData, err = LoadFundingData(fundingFile)
			if err != nil {
				// Try default funding file if specific one not found
				fmt.Printf("🔍 DEBUG: No specific funding file found, trying default\n")
				fundingData, err = LoadFundingData("funding_data.json")
				if err != nil {
					fmt.Printf("🔍 DEBUG: No funding data found for %s\n", file.Name())
					continue
				}
			}

			fmt.Printf("🔍 DEBUG: Found token in file %s, checking if UTXO exists\n", file.Name())
			fmt.Printf("🔍 DEBUG: Looking for TXID: %s, Vout: %d\n", fundingData.TxID, fundingData.Vout)

			// Verify UTXOs exist in wallet
			found := false
			for _, utxo := range unspent {
				txid, ok := utxo["txid"].(string)
				if !ok {
					continue
				}
				vout, ok := utxo["vout"].(float64)
				if !ok {
					continue
				}

				if txid == fundingData.TxID && uint32(vout) == fundingData.Vout {
					found = true
					fmt.Printf("🔍 DEBUG: ✅ Found matching UTXO for token: %s\n", outputData.TokenData.TokenID)
					break
				}
			}

			if !found {
				fmt.Printf("🔍 DEBUG: ❌ No matching UTXO found for token in %s\n", file.Name())
			}

			if found {
				tokens = append(tokens, &TokenWithFunding{
					TokenData: &outputData.TokenData,
					Funding:   fundingData,
					Filename:  file.Name(),
				})
			}
		}
	}

	return tokens, nil
}

// TokenWithFunding combines token data with its funding information
type TokenWithFunding struct {
	TokenData *TokenData
	Funding   *FundingData
	Filename  string
}

// BypassTransferToken skips canonical ID validation for detected tokens
// BypassTransferToken skips canonical ID validation for detected tokens
func BypassTransferToken(tokenKeyHex string, tokenUTXO *FundingData, tokenData *TokenData,
	transferAmount uint64, recipientAddress string, feeRate int64) (string, *FundingData, error) {

	fmt.Println("🔧 Finding the actual wallet key for detected token...")

	// Extract original name without any txid suffix
	originalName := tokenData.TokenID
	if strings.Contains(originalName, ":") {
		parts := strings.Split(originalName, ":")
		originalName = parts[0]
	}

	// Remove null padding
	originalName = strings.TrimRight(originalName, "\x00")

	fmt.Printf("🔍 Looking for wallet key for token ID: %s\n", originalName)

	// Search wallet addresses for the token label
	addressesJSON, err := RunBitcoinCommand("listaddressgroupings")
	if err != nil {
		return "", nil, fmt.Errorf("failed to list addresses: %w", err)
	}

	var addresses [][]interface{}
	if err := json.Unmarshal([]byte(addressesJSON), &addresses); err != nil {
		return "", nil, fmt.Errorf("failed to parse addresses: %w", err)
	}

	var tokenAddress string
	found := false

	// Check each address for token labels
	for _, group := range addresses {
		for _, addrData := range group {
			addr, ok := addrData.([]interface{})
			if !ok || len(addr) < 1 {
				continue
			}

			addrStr, ok := addr[0].(string)
			if !ok {
				continue
			}

			// Get address info to check labels
			addrInfoJSON, err := RunBitcoinCommand(fmt.Sprintf("getaddressinfo %s", addrStr))
			if err != nil {
				continue
			}

			var addrInfo map[string]interface{}
			if err := json.Unmarshal([]byte(addrInfoJSON), &addrInfo); err != nil {
				continue
			}

			// Check labels for our token
			if rawLabels, ok := addrInfo["labels"].([]interface{}); ok {
				for _, lbl := range rawLabels {
					var labelStr string
					if m, ok := lbl.(map[string]interface{}); ok {
						if name, ok := m["name"].(string); ok {
							labelStr = name
						}
					} else if s, ok := lbl.(string); ok {
						labelStr = s
					}

					// Check for both label formats
					// Old format: "Token:SPX:"
					// New format: "TokenPath:m/86'/1'/0'/0/123456:SPX"
					tokenMatches := strings.Contains(labelStr, "Token:"+originalName+":") ||
						(strings.Contains(labelStr, ":"+originalName) && strings.Contains(labelStr, "TokenPath:"))

					if tokenMatches {
						tokenAddress = addrStr
						found = true
						fmt.Printf("✅ Found wallet address for token: %s (label: %s)\n", tokenAddress, labelStr)
						break
					}
				}
				if found {
					break
				}
			}
		}
		if found {
			break
		}
	}

	var token *TaprootToken

	if found {
		// Get the private key for this address from the wallet
		fmt.Printf("🔐 Getting private key for address: %s\n", tokenAddress)
		privKeyWIF, err := RunBitcoinCommand(fmt.Sprintf("dumpprivkey %s", tokenAddress))
		if err != nil {
			return "", nil, fmt.Errorf("failed to get private key for token address: %w", err)
		}

		// Convert WIF to private key
		wif, err := btcutil.DecodeWIF(privKeyWIF)
		if err != nil {
			return "", nil, fmt.Errorf("failed to decode WIF: %w", err)
		}

		privKey, _ := btcec.PrivKeyFromBytes(wif.PrivKey.Serialize())

		// Create token with the actual wallet key
		token = &TaprootToken{
			PrivateKey: privKey,
			PublicKey:  privKey.PubKey(),
		}

		fmt.Println("✅ Using actual wallet private key for token")
	} else {
		// Fallback to provided token key (might not work for detected tokens)
		fmt.Println("⚠️ Could not find wallet key, trying provided key (may fail)")
		token, err = LoadTaprootToken(tokenKeyHex)
		if err != nil {
			return "", nil, fmt.Errorf("failed to load token key: %w", err)
		}
	}

	// Skip canonical ID validation - just pad out the token ID to match UTXO
	paddedTokenID := tokenData.TokenID
	if !strings.Contains(paddedTokenID, ":") {
		paddedTokenID = fmt.Sprintf("%s:%s", tokenData.TokenID, tokenUTXO.TxID[:8])
	}

	// Create a copy of token data with the padded ID
	paddedTokenData := &TokenData{
		TokenID:   paddedTokenID,
		Amount:    tokenData.Amount,
		TypeCode:  tokenData.TypeCode,
		Metadata:  tokenData.Metadata,
		Timestamp: tokenData.Timestamp,
	}

	// Try to create the normal transaction first
	tx, err := token.SplitToken(
		tokenUTXO.TxID,
		tokenUTXO.Vout,
		tokenUTXO.Value,
		paddedTokenData,
		transferAmount,
		recipientAddress,
		feeRate,
	)

	// If we don't have enough funds, try with multiple inputs
	if err != nil && strings.Contains(err.Error(), "insufficient funds") {
		// Extract how much we need vs how much we have
		parts := strings.Split(err.Error(), "need ")
		if len(parts) > 1 {
			needHaveParts := strings.Split(parts[1], ", have ")
			if len(needHaveParts) > 1 {
				needed, nerr := strconv.ParseInt(needHaveParts[0], 10, 64)
				have, herr := strconv.ParseInt(needHaveParts[1], 10, 64)
				if nerr == nil && herr == nil {
					additionalNeeded := needed - have
					fmt.Printf("⚠️ Insufficient funds in token UTXO. Need %d more satoshis\n", additionalNeeded)
					fmt.Println("🔄 Attempting to use additional inputs from wallet...")

					// Try again with multiple inputs
					tx, err = token.CreateMultiInputTokenTransaction(
						tokenUTXO,
						additionalNeeded+1000, // Add a buffer
						paddedTokenData,
						transferAmount,
						recipientAddress,
						feeRate,
					)
				}
			}
		}
	}

	if err != nil {
		return "", nil, err
	}

	var buf bytes.Buffer
	tx.Serialize(&buf)
	txHex := hex.EncodeToString(buf.Bytes())

	err = os.WriteFile("transfer_tx.hex", []byte(txHex), 0644)
	if err != nil {
		return "", nil, fmt.Errorf("failed to save transaction hex: %w", err)
	}

	txid, err := RunBitcoinCommand(fmt.Sprintf("sendrawtransaction %s", txHex))
	if err != nil {
		return "", nil, fmt.Errorf("failed to broadcast transaction: %w", err)
	}

	recipientFunding := &FundingData{
		TxID:    txid,
		Vout:    0,
		Value:   10000,
		Address: recipientAddress,
	}

	return txid, recipientFunding, nil
}

func handleCreateCommand() {
	var tokenName = "demo-token"
	var tokenAmount uint64 = 1
	var tokenMetadata = "Demo token"
	var tokenTypeCode uint8 = 0
	var recipientKeyFile, recipientPubHex string
	var autofund, autoreveal, useHybridMode bool // Added useHybridMode flag here

	for i := 1; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "--name":
			tokenName = os.Args[i+1]
			i++
		case "--amount":
			amt, err := strconv.ParseUint(os.Args[i+1], 10, 64)
			if err != nil {
				fmt.Fprintf(os.Stderr, "❌ Invalid amount: %v\n", err)
				os.Exit(1)
			}
			tokenAmount = amt
			i++
		case "--metadata":
			tokenMetadata = os.Args[i+1]
			i++
		case "--typecode":
			tc, err := strconv.ParseUint(os.Args[i+1], 10, 8)
			if err != nil {
				fmt.Fprintf(os.Stderr, "❌ Invalid typecode: %v\n", err)
				os.Exit(1)
			}
			tokenTypeCode = uint8(tc)
			i++
		case "--recipientkey":
			recipientKeyFile = os.Args[i+1]
			i++
		case "--recipientpub":
			recipientPubHex = os.Args[i+1]
			i++
		case "--autofund":
			autofund = true
		case "--autoreveal":
			autoreveal = true
		case "--hybrid": // Add this case to parse the hybrid flag
			useHybridMode = true
		}
	}

	fmt.Println("🔄 Creating token...")

	var output *OutputData
	var err error

	// Get recipient's public key if provided
	var recipientPubKey *btcec.PublicKey
	if recipientKeyFile != "" || recipientPubHex != "" {
		if recipientKeyFile != "" {
			privHex, err := os.ReadFile(recipientKeyFile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "❌ Failed to read recipient key: %v\n", err)
				os.Exit(1)
			}
			privKey, _ := btcec.PrivKeyFromBytes(bytes.TrimSpace(privHex))
			recipientPubKey = privKey.PubKey()
		} else {
			pubBytes, err := hex.DecodeString(recipientPubHex)
			if err != nil {
				fmt.Fprintf(os.Stderr, "❌ Invalid recipient pubkey: %v\n", err)
				os.Exit(1)
			}
			recipientPubKey, err = btcec.ParsePubKey(pubBytes)
			if err != nil {
				fmt.Fprintf(os.Stderr, "❌ Failed to parse pubkey: %v\n", err)
				os.Exit(1)
			}
		}
	}

	// THIS IS WHERE WE ADD THE HYBRID MODE LOGIC
	// Create token based on the selected mode
	if useHybridMode && recipientPubKey != nil {
		// Use hybrid mode with recipient's pubkey as internal key
		output, err = CreateHybridToken(tokenName, tokenAmount, tokenMetadata, tokenTypeCode, recipientPubKey)
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ Error creating hybrid token: %v\n", err)
			os.Exit(1)
		}
	} else if recipientPubKey != nil {
		// Standard token with ownership (existing code)
		token := &TokenData{
			TokenID:   tokenName,
			Amount:    tokenAmount,
			Metadata:  tokenMetadata,
			TypeCode:  tokenTypeCode,
			Timestamp: uint64(time.Now().Unix()),
		}

		issuerToken, err := NewTaprootToken()
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ Token key gen failed: %v\n", err)
			os.Exit(1)
		}
		if err = issuerToken.SavePrivateKey("token_key.hex"); err != nil {
			fmt.Fprintf(os.Stderr, "❌ Could not save token key: %v\n", err)
			os.Exit(1)
		}

		tree, err := issuerToken.CreateTaprootOutputWithOwnership(token, recipientPubKey)
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ Script creation failed: %v\n", err)
			os.Exit(1)
		}

		addr, err := issuerToken.GetTaprootAddress()
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ Address generation failed: %v\n", err)
			os.Exit(1)
		}

		output = &OutputData{
			Address:         addr,
			ScriptHex:       hex.EncodeToString(tree.Script),
			ControlBlockHex: hex.EncodeToString(tree.ControlBlock),
			TokenData:       *token,
		}
	} else {
		// Standard token without recipient (existing code)
		output, err = CreateToken(tokenName, tokenAmount, tokenMetadata, tokenTypeCode)
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ Error creating token: %v\n", err)
			os.Exit(1)
		}
	}

	if err = SaveOutputData("taproot_output.json", output); err != nil {
		fmt.Fprintf(os.Stderr, "❌ Failed to save token output: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("✅ Token created:")
	fmt.Println("  Address:", output.Address)
	fmt.Println("  Token ID:", output.TokenData.TokenID)
	fmt.Println("  Amount:", output.TokenData.Amount)
	fmt.Println("  Metadata:", output.TokenData.Metadata)
	fmt.Println("  TypeCode:", output.TokenData.TypeCode)
	if useHybridMode {
		fmt.Println("  Mode: Hybrid (recognized by recipient's wallet)")
	}

	// ✅ Autofund the Taproot address
	if autofund {
		fmt.Println("\n🔄 Funding the address...")
		funding, err := FundAddress(output.Address, 0.00000850)
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ Error funding address: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("✅ Address funded: %s:%d (%d sats)\n", funding.TxID, funding.Vout, funding.Value)
	}

	// ✅ Spend token (script-path) + reveal metadata
	if autoreveal {
		fmt.Println("\n🔄 Reusing original address to retain token ownership...")

		outputData, err := LoadOutputData("taproot_output.json")
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ Failed to load token output: %v\n", err)
			os.Exit(1)
		}

		newAddr := outputData.Address
		fmt.Println("✅ Destination address:", newAddr)

		fmt.Println("\n🔄 Spending token...")
		var txid string

		// Use the hybrid reveal for hybrid tokens
		if useHybridMode {
			txid, err = RevealHybridToken(newAddr)
		} else {
			txid, err = SpendToken(newAddr)
		}

		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ Error spending token: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("✅ Token spent on-chain:", txid)

		fmt.Println("\n🔄 Revealing embedded token data...")
		keyHex, err := os.ReadFile("token_key.hex")
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ Could not read token_key.hex: %v\n", err)
			os.Exit(1)
		}
		tkn, err := LoadTaprootToken(strings.TrimSpace(string(keyHex)))
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ Could not load TaprootToken: %v\n", err)
			os.Exit(1)
		}
		rawHex, err := os.ReadFile("spending_tx.hex")
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ Could not read spending_tx.hex: %v\n", err)
			os.Exit(1)
		}
		revealed, err := tkn.RevealTokenDataFromHex(string(rawHex))
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ Error extracting on-chain data: %v\n", err)
			os.Exit(1)
		}

		fmt.Println("\n🔓 Revealed Token Data:")
		fmt.Printf("  TokenID   : %s\n", revealed.TokenID)
		fmt.Printf("  Amount    : %d\n", revealed.Amount)
		fmt.Printf("  TypeCode  : %d\n", revealed.TypeCode)
		fmt.Printf("  Metadata  : %s\n", revealed.Metadata)
		fmt.Printf("  Timestamp : %d\n", revealed.Timestamp)
	}
}

// Complete handleTransferCommand function
func handleTransferCommand() {
	var recipientAddress string
	var transferAmount uint64
	var tokenFile string
	var fundingFile string
	var feeRate int64 = 2000
	var listTokens bool

	for i := 0; i < len(os.Args); i++ {
		arg := os.Args[i]
		switch arg {
		case "--to":
			if i+1 < len(os.Args) {
				recipientAddress = os.Args[i+1]
				i++
			}
		case "--amount":
			if i+1 < len(os.Args) {
				amt, err := strconv.ParseUint(os.Args[i+1], 10, 64)
				if err != nil {
					fmt.Fprintf(os.Stderr, "❌ Invalid amount: %v\n", err)
					os.Exit(1)
				}
				transferAmount = amt
				i++
			}
		case "--token":
			if i+1 < len(os.Args) {
				tokenFile = os.Args[i+1]
				i++
			}
		case "--funding":
			if i+1 < len(os.Args) {
				fundingFile = os.Args[i+1]
				i++
			}
		case "--fee":
			if i+1 < len(os.Args) {
				fee, err := strconv.ParseInt(os.Args[i+1], 10, 64)
				if err != nil {
					fmt.Fprintf(os.Stderr, "❌ Invalid fee rate: %v\n", err)
					os.Exit(1)
				}
				feeRate = fee
				i++
			}
		case "--list":
			listTokens = true
		}
	}

	// If --list flag is provided, just list tokens and exit
	if listTokens {
		tokens, err := ScanWalletForTokens()
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ Failed to list tokens: %v\n", err)
			os.Exit(1)
		}

		fmt.Println("🔍 Tokens in your wallet:")
		if len(tokens) == 0 {
			fmt.Println("  No tokens found")
			os.Exit(0)
		}

		for i, t := range tokens {
			fmt.Printf("%d. Token: %s\n", i+1, t.TokenData.TokenID)
			fmt.Printf("   Amount: %d\n", t.TokenData.Amount)
			fmt.Printf("   Metadata: %s\n", t.TokenData.Metadata)
			fmt.Printf("   UTXO: %s:%d (%d sats)\n", t.Funding.TxID[:8]+"...", t.Funding.Vout, t.Funding.Value)
			fmt.Println()
		}
		os.Exit(0)
	}

	// If no token specified, list tokens and prompt for selection
	var selectedToken *TokenWithFunding
	if tokenFile == "" && fundingFile == "" {
		tokens, err := ScanWalletForTokens()
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ Failed to list tokens: %v\n", err)
			os.Exit(1)
		}

		if len(tokens) == 0 {
			fmt.Println("❌ No tokens found in your wallet")
			os.Exit(1)
		}

		fmt.Println("🔍 Select a token to transfer:")
		for i, t := range tokens {
			fmt.Printf("%d. Token: %s\n", i+1, t.TokenData.TokenID)
			fmt.Printf("   Amount: %d\n", t.TokenData.Amount)
			fmt.Printf("   Metadata: %s\n", t.TokenData.Metadata)
			fmt.Printf("   UTXO: %s:%d\n", t.Funding.TxID[:8]+"...", t.Funding.Vout)
			fmt.Println()
		}

		var choice int
		fmt.Print("Enter token number: ")
		fmt.Scanf("%d", &choice)

		if choice < 1 || choice > len(tokens) {
			fmt.Fprintf(os.Stderr, "❌ Invalid selection\n")
			os.Exit(1)
		}

		selectedToken = tokens[choice-1]

		// Create temporary files for detected tokens
		if selectedToken.Filename == "detected" {
			fmt.Println("⚙️ Creating temporary files for detected token...")

			// Save token data to temporary file
			tempOutput := &OutputData{
				Address:   selectedToken.Funding.Address,
				TokenData: *selectedToken.TokenData,
			}
			tempFile := "temp_token_output.json"
			err = SaveOutputData(tempFile, tempOutput)
			if err != nil {
				fmt.Fprintf(os.Stderr, "❌ Failed to save temporary token data: %v\n", err)
				os.Exit(1)
			}
			tokenFile = tempFile

			// Save funding data to temporary file
			tempFunding := &FundingData{
				TxID:    selectedToken.Funding.TxID,
				Vout:    selectedToken.Funding.Vout,
				Value:   selectedToken.Funding.Value,
				Address: selectedToken.Funding.Address,
			}
			tempFundingFile := "temp_token_funding.json"
			err = SaveFundingData(tempFundingFile, tempFunding)
			if err != nil {
				fmt.Fprintf(os.Stderr, "❌ Failed to save temporary funding data: %v\n", err)
				os.Exit(1)
			}
			fundingFile = tempFundingFile

			fmt.Printf("✅ Temporary files created:\n  Token: %s\n  Funding: %s\n",
				tempFile, tempFundingFile)
		} else {
			tokenFile = selectedToken.Filename
			// Try to use matching funding file if available
			specificFundingFile := strings.Replace(tokenFile, "_output.json", "_funding.json", 1)
			if _, err := os.Stat(specificFundingFile); err == nil {
				fundingFile = specificFundingFile
			} else {
				fundingFile = "funding_data.json"
			}
		}

		// If transfer amount not specified, prompt for it
		if transferAmount == 0 {
			fmt.Printf("Token balance: %d\n", selectedToken.TokenData.Amount)
			fmt.Print("Enter amount to transfer: ")
			fmt.Scanf("%d", &transferAmount)

			if transferAmount == 0 || transferAmount > selectedToken.TokenData.Amount {
				fmt.Fprintf(os.Stderr, "❌ Invalid transfer amount\n")
				os.Exit(1)
			}
		}
	}

	if recipientAddress == "" {
		fmt.Fprintln(os.Stderr, "❌ Missing required --to address")
		os.Exit(1)
	}

	if transferAmount == 0 {
		fmt.Fprintln(os.Stderr, "❌ Missing or invalid --amount")
		os.Exit(1)
	}

	// Use default files if not specified
	if tokenFile == "" {
		tokenFile = "taproot_output.json"
	}
	if fundingFile == "" {
		fundingFile = "funding_data.json"
	}

	fmt.Println("📦 Loading token and funding files")
	outputData, err := LoadOutputData(tokenFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Failed to load token data from %s: %v\n", tokenFile, err)
		os.Exit(1)
	}
	fundingData, err := LoadFundingData(fundingFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Failed to load funding data from %s: %v\n", fundingFile, err)
		os.Exit(1)
	}

	// DEBUG: Print funding data to verify the correct UTXO is being used
	fmt.Printf("🔍 DEBUG: Using funding data: TXID=%s, Vout=%d, Value=%d\n",
		fundingData.TxID, fundingData.Vout, fundingData.Value)

	if transferAmount > outputData.TokenData.Amount {
		fmt.Fprintf(os.Stderr, "❌ You do not own enough of the token. Balance: %d, Requested: %d\n",
			outputData.TokenData.Amount, transferAmount)
		os.Exit(1)
	}

	// Create transfer transaction
	fmt.Println("🔄 Creating transfer transaction...")
	var txid string
	var recipientFunding *FundingData

	// Check if this is a detected token
	isDetectedToken := tokenFile == "temp_token_output.json"
if isDetectedToken {
    fmt.Println("✅ Using wallet-native split for hybrid token")
    
    txid, recipientFunding, err = WalletNativeSplitToken(
        fundingData,
        &outputData.TokenData,
        transferAmount,
        recipientAddress,
        feeRate,
    )
    
    if err != nil {
        fmt.Fprintf(os.Stderr, "❌ Transfer failed: %v\n", err)
        os.Exit(1)
    }
    
} else {
    // Use normal transfer for file-based tokens
    keyHex, err := os.ReadFile("token_key.hex")
    if err != nil {
        fmt.Fprintf(os.Stderr, "❌ Failed to read token key: %v\n", err)
        os.Exit(1)
    }

    txid, recipientFunding, err = TransferToken(
        strings.TrimSpace(string(keyHex)),
        fundingData,
        &outputData.TokenData,
        transferAmount,
        recipientAddress,
        feeRate,
    )
    
    if err != nil {
        fmt.Fprintf(os.Stderr, "❌ Transfer failed: %v\n", err)
        os.Exit(1)
    }
}

	// Update token balance in file
	outputData.TokenData.Amount -= transferAmount
	_ = SaveOutputData(tokenFile, outputData)
	_ = SaveFundingData("recipient_funding.json", recipientFunding)

	fmt.Println("\n✅ Token transfer successful!")
	fmt.Println("  Token       :", outputData.TokenData.TokenID)
	fmt.Printf("  To Address  : %s\n", recipientAddress)
	fmt.Println("  Amount      :", transferAmount)
	fmt.Println("  Transaction :", txid)
	fmt.Println("  Remaining   :", outputData.TokenData.Amount)

	if isDetectedToken {
		fmt.Println("\n📧 IMPORTANT:")
		fmt.Println("  1. Send 'recipient_token_key.hex' to the recipient")
		fmt.Println("  2. The recipient can extract token data from transaction:", txid)
		fmt.Println("  3. The token data is embedded in the transaction witness")
	}
}

// ScanWalletForTokens scans for both direct UTXOs and BIP32-derived tokens
func ScanWalletForTokens() ([]*TokenWithFunding, error) {
	fmt.Println("🔍 Scanning wallet UTXOs directly for tokens...")

	// Get unspent outputs from the wallet
	unspentJSON, err := RunBitcoinCommand("listunspent")
	if err != nil {
		return nil, fmt.Errorf("failed to list unspent outputs: %w", err)
	}

	var unspent []map[string]interface{}
	if err = json.Unmarshal([]byte(unspentJSON), &unspent); err != nil {
		return nil, fmt.Errorf("failed to parse unspent outputs: %w", err)
	}

	fmt.Printf("Found %d UTXOs in wallet\n", len(unspent))

	tokens := []*TokenWithFunding{}

	// First check direct UTXOs for tokens (existing method)
	directTokens, err := scanDirectUTXOs(unspent)
	if err != nil {
		fmt.Printf("⚠️ Warning: Error in direct UTXO scan: %v\n", err)
	} else {
		tokens = append(tokens, directTokens...)
	}

	// Then scan for BIP32-derived tokens using address labels
	fmt.Println("🔍 Scanning wallet for BIP32-derived tokens...")
	bip32Tokens, err := scanBIP32Tokens()
	if err != nil {
		fmt.Printf("⚠️ Warning: Error in BIP32 token scan: %v\n", err)
	} else {
		tokens = append(tokens, bip32Tokens...)
	}

	return tokens, nil
}

func scanDirectUTXOs(unspent []map[string]interface{}) ([]*TokenWithFunding, error) {
	tokens := []*TokenWithFunding{}

	// Load the private key to use for script checks
	keyFile := "token_key.hex"
	privKeyHex, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read token key: %w", err)
	}
	token, err := LoadTaprootToken(strings.TrimSpace(string(privKeyHex)))
	if err != nil {
		return nil, fmt.Errorf("failed to load token key: %w", err)
	}

	// Check each UTXO that has a Taproot address (tb1p prefix on testnet)
	for _, utxo := range unspent {
		txid, ok := utxo["txid"].(string)
		if !ok {
			continue
		}
		vout, ok := utxo["vout"].(float64)
		if !ok {
			continue
		}
		amount, ok := utxo["amount"].(float64)
		if !ok {
			continue
		}
		address, ok := utxo["address"].(string)
		if !ok {
			continue
		}

		// Only check Taproot addresses (they start with "tb1p" on testnet)
		if !strings.HasPrefix(address, "tb1p") {
			continue
		}

		fmt.Printf("Checking Taproot UTXO: %s:%d\n", txid, int(vout))

		// Get the raw transaction
		rawTxHex, err := RunBitcoinCommand(fmt.Sprintf("getrawtransaction %s", txid))
		if err != nil {
			fmt.Printf("⚠️ Couldn't get raw tx for %s: %v\n", txid, err)
			continue
		}

		// Try to extract token data
		tokenData, err := token.RevealTokenDataFromHex(rawTxHex)
		if err != nil {
			// Not a token or couldn't parse token data
			fmt.Printf("  Not a token or couldn't extract data: %v\n", err)
			continue
		}

		// Found a token! Show all fields
		fmt.Printf("✅ Found token in UTXO %s:%d\n", txid, int(vout))
		fmt.Printf("   Token ID: %s\n", tokenData.TokenID)
		fmt.Printf("   Amount: %d\n", tokenData.Amount)
		fmt.Printf("   TypeCode: %d\n", tokenData.TypeCode)
		fmt.Printf("   Metadata: %s\n", tokenData.Metadata)
		fmt.Printf("   Timestamp: %d (%s)\n", tokenData.Timestamp,
			time.Unix(int64(tokenData.Timestamp), 0).Format(time.RFC3339))

		fundingData := &FundingData{
			TxID:    txid,
			Vout:    uint32(vout),
			Value:   int64(amount * 100000000),
			Address: address,
		}

		tokens = append(tokens, &TokenWithFunding{
			TokenData: tokenData,
			Funding:   fundingData,
			Filename:  "detected", // This was detected, not loaded from file
		})
	}

	return tokens, nil
}

// 3. Add a new extract-token command that takes a transaction ID
func ExtractTokenFromTxID(txid string) (*TokenData, error) {
	// Get the raw transaction
	rawTxHex, err := RunBitcoinCommand(fmt.Sprintf("getrawtransaction %s", txid))
	if err != nil {
		return nil, fmt.Errorf("failed to get transaction: %w", err)
	}

	// Load token key for extraction
	keyHex, err := os.ReadFile("token_key.hex")
	if err != nil {
		return nil, fmt.Errorf("failed to read token key: %w", err)
	}

	token, err := LoadTaprootToken(strings.TrimSpace(string(keyHex)))
	if err != nil {
		return nil, fmt.Errorf("failed to load token key: %w", err)
	}

	// Extract token data
	tokenData, err := token.RevealTokenDataFromHex(rawTxHex)
	if err != nil {
		return nil, fmt.Errorf("failed to extract token data: %w", err)
	}

	return tokenData, nil
}

// Add a handler for the extract-token command
func handleExtractCommand() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "❌ Missing transaction ID")
		fmt.Fprintln(os.Stderr, "Usage: ./tsb-token-cli extract-token <txid>")
		os.Exit(1)
	}

	txid := os.Args[1]

	tokenData, err := ExtractTokenFromTxID(txid)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Failed to extract token data: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("\n🔓 Extracted Token Data:")
	fmt.Printf("  TokenID   : %s\n", tokenData.TokenID)
	fmt.Printf("  Amount    : %d\n", tokenData.Amount)
	fmt.Printf("  TypeCode  : %d\n", tokenData.TypeCode)
	fmt.Printf("  Metadata  : %s\n", tokenData.Metadata)
	fmt.Printf("  Timestamp : %d (%s)\n", tokenData.Timestamp,
		time.Unix(int64(tokenData.Timestamp), 0).Format(time.RFC3339))
}

func scanBIP32Tokens() ([]*TokenWithFunding, error) {
	tokens := []*TokenWithFunding{}

	// Get all UTXOs from wallet
	utxosJSON, err := RunBitcoinCommand("listunspent")
	if err != nil {
		return nil, fmt.Errorf("failed to list UTXOs: %w", err)
	}

	var utxos []map[string]interface{}
	if err := json.Unmarshal([]byte(utxosJSON), &utxos); err != nil {
		return nil, fmt.Errorf("failed to parse UTXOs: %w", err)
	}

	for _, utxo := range utxos {
		address, _ := utxo["address"].(string)
		txid, _ := utxo["txid"].(string)
		voutFloat, _ := utxo["vout"].(float64)
		vout := uint32(voutFloat)
		amount, _ := utxo["amount"].(float64)

		// Get address info to extract label
		infoJSON, err := RunBitcoinCommand(fmt.Sprintf("getaddressinfo \"%s\"", address))
		if err != nil {
			fmt.Printf("⚠️ Error calling getaddressinfo for %s: %v\n", address, err)
			continue
		}

		var info map[string]interface{}
		if err := json.Unmarshal([]byte(infoJSON), &info); err != nil {
			fmt.Printf("⚠️ Error parsing address info: %v\n", err)
			continue
		}

		labels := []string{}

		if rawLabels, ok := info["labels"].([]interface{}); ok {
			for _, lbl := range rawLabels {
				if m, ok := lbl.(map[string]interface{}); ok {
					if name, ok := m["name"].(string); ok {
						labels = append(labels, name)
					}
				}
			}
		}

		for _, label := range labels {
			if strings.HasPrefix(label, "Token:") {
				parts := strings.Split(label, ":")
				if len(parts) < 3 {
					continue
				}

				tokenID := parts[1]
				path := parts[2]

				fmt.Printf("✅ Found token label: %s (Path: %s)\n", tokenID, path)

				// Try to load token data from file
				outputFile := fmt.Sprintf("%s_output.json", tokenID)
				outputData, err := LoadOutputData(outputFile)
				if err != nil {
					fmt.Printf("⚠️ Could not load output data for token %s: %v\n", tokenID, err)
					continue
				}

				// Load funding data (fallback to generic if needed)
				fundingFile := fmt.Sprintf("%s_funding.json", tokenID)
				fundingData, err := LoadFundingData(fundingFile)
				if err != nil {
					fundingData = &FundingData{
						TxID:           txid,
						Vout:           vout,
						Value:          int64(amount * 100000000),
						Address:        address,
						DerivationPath: path,
					}
				}

				tokens = append(tokens, &TokenWithFunding{
					TokenData: &outputData.TokenData,
					Funding:   fundingData,
					Filename:  outputFile,
				})
			}
		}
	}

	return tokens, nil
}

// CreateMultiInputTokenTransaction creates a transaction with multiple inputs to fund a token transfer
// CreateMultiInputTokenTransaction creates a transaction with multiple inputs to fund a token transfer
func (t *TaprootToken) CreateMultiInputTokenTransaction(
	tokenUTXO *FundingData,
	additionalFunds int64, // How many more satoshis we need
	tokenData *TokenData,
	transferAmount uint64,
	recipientAddress string,
	feeRate int64,
) (*wire.MsgTx, error) {
	fmt.Printf("📊 Creating multi-input transaction (need %d more sats)\n", additionalFunds)

	// ✅ FIX: For detected tokens, we need to reconstruct the ScriptTree
	if t.ScriptTree == nil {
		fmt.Println("🔧 Reconstructing ScriptTree for detected token...")

		// Create a basic token output to initialize ScriptTree
		tempTokenData := &TokenData{
			TokenID:   tokenData.TokenID,
			Amount:    tokenData.Amount,
			TypeCode:  tokenData.TypeCode,
			Metadata:  tokenData.Metadata,
			Timestamp: tokenData.Timestamp,
		}

		_, err := t.CreateTaprootOutput(tempTokenData)
		if err != nil {
			return nil, fmt.Errorf("failed to reconstruct ScriptTree: %w", err)
		}
		fmt.Println("✅ ScriptTree reconstructed")
	}

	// Keep track of which UTXOs we've already used to avoid duplicates
	usedUTXOs := make(map[string]bool)
	tokenUTXOKey := tokenUTXO.TxID + ":" + strconv.Itoa(int(tokenUTXO.Vout))
	usedUTXOs[tokenUTXOKey] = true

	// Start with the token input
	prevHash, err := chainhash.NewHashFromStr(tokenUTXO.TxID)
	if err != nil {
		return nil, fmt.Errorf("invalid token TXID: %w", err)
	}
	outpoint := wire.NewOutPoint(prevHash, tokenUTXO.Vout)
	txIn := wire.NewTxIn(outpoint, nil, nil)

	// Create transaction
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(txIn)
	fmt.Printf("📥 Added token input: %s:%d\n", tokenUTXO.TxID, tokenUTXO.Vout)

	// Find additional UTXOs to fund the transaction
	unspentJSON, err := RunBitcoinCommand("listunspent")
	if err != nil {
		return nil, fmt.Errorf("failed to list wallet UTXOs: %w", err)
	}

	var unspent []map[string]interface{}
	if err = json.Unmarshal([]byte(unspentJSON), &unspent); err != nil {
		return nil, fmt.Errorf("failed to parse UTXO list: %w", err)
	}

	fmt.Printf("🔍 Searching %d wallet UTXOs for additional inputs\n", len(unspent))

	additionalInputs := []wire.TxIn{}
	fundingAmount := int64(0)

	// Find UTXOs that are NOT the token UTXO
	for _, utxo := range unspent {
		txid, ok := utxo["txid"].(string)
		if !ok {
			continue
		}
		vout, ok := utxo["vout"].(float64)
		if !ok {
			continue
		}

		// Create a key for this UTXO to check in our map
		utxoKey := txid + ":" + strconv.Itoa(int(vout))

		// Skip UTXOs we've already used (including the token UTXO)
		if usedUTXOs[utxoKey] {
			fmt.Printf("  Skipping already used UTXO: %s\n", utxoKey)
			continue
		}

		// Skip if this is the token UTXO (redundant check but keeping for safety)
		if txid == tokenUTXO.TxID && uint32(vout) == tokenUTXO.Vout {
			fmt.Printf("  Skipping token UTXO: %s:%d (already included)\n", txid, int(vout))
			continue
		}

		amount, ok := utxo["amount"].(float64)
		if !ok {
			continue
		}

		// Convert BTC to satoshis
		satoshis := int64(amount * 100000000)
		fmt.Printf("  Found UTXO: %s:%d (%d sats)\n", txid, int(vout), satoshis)

		// Mark this UTXO as used
		usedUTXOs[utxoKey] = true

		// Add this UTXO as an input
		inputHash, _ := chainhash.NewHashFromStr(txid)
		inputOutpoint := wire.NewOutPoint(inputHash, uint32(vout))
		input := wire.NewTxIn(inputOutpoint, nil, nil)
		additionalInputs = append(additionalInputs, *input)

		fundingAmount += satoshis
		fmt.Printf("  Running total: %d/%d sats\n", fundingAmount, additionalFunds)

		if fundingAmount >= additionalFunds {
			fmt.Printf("✅ Found enough additional inputs: %d sats\n", fundingAmount)
			break
		}
	}

	if fundingAmount < additionalFunds {
		return nil, fmt.Errorf("couldn't find enough additional inputs: need %d, found %d",
			additionalFunds, fundingAmount)
	}

	// Add the additional inputs to the transaction
	for i := range additionalInputs {
		tx.AddTxIn(&additionalInputs[i])
		fmt.Printf("📥 Added extra input #%d\n", i+1)
	}

	// Create recipient output - SIMPLE APPROACH
	recipientAddr, err := btcutil.DecodeAddress(recipientAddress, Network)
	if err != nil {
		return nil, fmt.Errorf("invalid recipient address: %w", err)
	}

	recipientScript, err := txscript.PayToAddrScript(recipientAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to create recipient script: %w", err)
	}

	// Use minimum dust amount for the token output
	const minOutputAmount = 100000
	recipientTxOut := wire.NewTxOut(minOutputAmount, recipientScript)
	tx.AddTxOut(recipientTxOut)
	fmt.Printf("📤 Added recipient output: %d sats to %s\n", minOutputAmount, recipientAddress)

	// Add change output for token if needed
	changeAmount := tokenData.Amount - transferAmount
	if changeAmount > 0 {
		// Get a new address from your wallet for the change
		changeAddress, err := RunBitcoinCommand("getnewaddress \"TSBToken-Change\" \"bech32m\"")
		if err != nil {
			return nil, fmt.Errorf("failed to get change address: %w", err)
		}

		changeAddr, err := btcutil.DecodeAddress(changeAddress, Network)
		if err != nil {
			return nil, fmt.Errorf("failed to decode change address: %w", err)
		}

		changeScript, err := txscript.PayToAddrScript(changeAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to create change script: %w", err)
		}

		changeTxOut := wire.NewTxOut(minOutputAmount, changeScript)
		tx.AddTxOut(changeTxOut)
		fmt.Printf("📤 Added token change output: %d sats with %d tokens to %s\n",
			minOutputAmount, changeAmount, changeAddress)
	} else {
		fmt.Println("📤 No token change output needed (transferring all tokens)")
	}

	// Add change output for Bitcoin
	totalInput := tokenUTXO.Value + fundingAmount
	totalOutput := int64(len(tx.TxOut)) * minOutputAmount

	// Estimate fee
	txSize := 100 + (len(tx.TxIn) * 150) + (len(tx.TxOut) * 50)
	fee := (feeRate * int64(txSize)) / 1000
	if fee < 300 {
		fee = 300
	}

	bitcoinChange := totalInput - totalOutput - fee
	fmt.Printf("💰 Transaction summary: %d sats in, %d sats out, %d fee, %d change\n",
		totalInput, totalOutput, fee, bitcoinChange)

	if bitcoinChange > 10000 {
		// Create change address for Bitcoin
		changeAddrStr, err := RunBitcoinCommand("getnewaddress")
		if err != nil {
			return nil, err
		}
		changeAddr, err := btcutil.DecodeAddress(changeAddrStr, Network)
		if err != nil {
			return nil, err
		}
		changeScript, err := txscript.PayToAddrScript(changeAddr)
		if err != nil {
			return nil, err
		}
		changeTxOut := wire.NewTxOut(bitcoinChange, changeScript)
		tx.AddTxOut(changeTxOut)
		fmt.Printf("📤 Added Bitcoin change output: %d sats to %s\n", bitcoinChange, changeAddrStr)
	} else {
		fmt.Printf("⚠️ Bitcoin change too small (%d sats), adding to fee\n", bitcoinChange)
	}

	// Set up the witness for token script-path spend (first input)
	witness := wire.TxWitness{
		t.ScriptTree.Script,
		t.ScriptTree.ControlBlock,
	}
	tx.TxIn[0].Witness = witness

	fmt.Printf("✅ Created transaction with %d inputs and %d outputs\n", len(tx.TxIn), len(tx.TxOut))

	// Serialize the transaction for Bitcoin Core to sign
	var buf bytes.Buffer
	tx.Serialize(&buf)
	txHex := hex.EncodeToString(buf.Bytes())

	// Have Bitcoin Core sign the transaction
	fmt.Println("🔐 Signing transaction with wallet...")
	signedTxJSON, err := RunBitcoinCommand(fmt.Sprintf("signrawtransactionwithwallet %s", txHex))
	if err != nil {
		return nil, fmt.Errorf("failed to sign transaction: %w", err)
	}

	// Parse the signed transaction JSON
	var signedTxResult struct {
		Hex      string `json:"hex"`
		Complete bool   `json:"complete"`
	}
	if err = json.Unmarshal([]byte(signedTxJSON), &signedTxResult); err != nil {
		return nil, fmt.Errorf("failed to parse signed tx: %w", err)
	}

	if !signedTxResult.Complete {
		return nil, fmt.Errorf("transaction signing incomplete")
	}

	// Deserialize the signed transaction
	signedTxBytes, err := hex.DecodeString(signedTxResult.Hex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode signed tx: %w", err)
	}

	var signedTx wire.MsgTx
	if err = signedTx.Deserialize(bytes.NewReader(signedTxBytes)); err != nil {
		return nil, fmt.Errorf("failed to deserialize signed tx: %w", err)
	}

	fmt.Println("✅ Transaction signing completed successfully")
	return &signedTx, nil
}


// WalletNativeSplitToken - Creates proper token outputs with embedded data
func WalletNativeSplitToken(tokenUTXO *FundingData, tokenData *TokenData,
    transferAmount uint64, recipientAddress string, feeRate int64) (string, *FundingData, error) {
    
    fmt.Println("🔄 Creating wallet-native split with proper token outputs...")
    
    changeAmount := tokenData.Amount - transferAmount
    if changeAmount == 0 {
        return "", nil, fmt.Errorf("no change amount - use simple transfer instead")
    }
    
    // 1. CREATE RECIPIENT TOKEN ADDRESS
    fmt.Println("🔄 Creating recipient token address...")
    recipientToken, err := NewTaprootToken()
    if err != nil {
        return "", nil, fmt.Errorf("failed to create recipient token: %w", err)
    }
    
    recipientTokenData := &TokenData{
        TokenID:   tokenData.TokenID,
        Amount:    transferAmount,
        TypeCode:  tokenData.TypeCode,
        Metadata:  tokenData.Metadata,
        Timestamp: uint64(time.Now().Unix()),
    }
    
    _, err = recipientToken.CreateTaprootOutput(recipientTokenData)
    if err != nil {
        return "", nil, fmt.Errorf("failed to create recipient token output: %w", err)
    }
    
    recipientTokenAddr, err := recipientToken.GetTaprootAddress()
    if err != nil {
        return "", nil, fmt.Errorf("failed to get recipient token address: %w", err)
    }
    
    // 2. CREATE CHANGE TOKEN ADDRESS  
    fmt.Println("🔄 Creating change token address...")
    changeToken, err := NewTaprootToken()
    if err != nil {
        return "", nil, fmt.Errorf("failed to create change token: %w", err)
    }
    
    changeTokenData := &TokenData{
        TokenID:   tokenData.TokenID,
        Amount:    changeAmount,
        TypeCode:  tokenData.TypeCode,
        Metadata:  tokenData.Metadata,
        Timestamp: uint64(time.Now().Unix()),
    }
    
    _, err = changeToken.CreateTaprootOutput(changeTokenData)
    if err != nil {
        return "", nil, fmt.Errorf("failed to create change token output: %w", err)
    }
    
    changeTokenAddr, err := changeToken.GetTaprootAddress()
    if err != nil {
        return "", nil, fmt.Errorf("failed to get change token address: %w", err)
    }
    
    fmt.Printf("✅ Created recipient token address: %s (%d tokens)\n", recipientTokenAddr, transferAmount)
    fmt.Printf("✅ Created change token address: %s (%d tokens)\n", changeTokenAddr, changeAmount)
    
    // 3. CREATE TRANSACTION WITH PROPER TOKEN OUTPUTS
    prevHash, err := chainhash.NewHashFromStr(tokenUTXO.TxID)
    if err != nil {
        return "", nil, fmt.Errorf("invalid token TXID: %w", err)
    }
    
    outpoint := wire.NewOutPoint(prevHash, tokenUTXO.Vout)
    txIn := wire.NewTxIn(outpoint, nil, nil)
    
    tx := wire.NewMsgTx(2)
    tx.AddTxIn(txIn)
    
    totalInputValue := tokenUTXO.Value
    
    // Add additional funding if needed
    const dustAmount = int64(10000)
    requiredValue := dustAmount * 2
    
    if totalInputValue < requiredValue {
        fmt.Printf("⚠️ Need additional funding: have %d, need %d sats\n", totalInputValue, requiredValue)
        
        unspentJSON, err := RunBitcoinCommand("listunspent")
        if err != nil {
            return "", nil, fmt.Errorf("failed to list UTXOs: %w", err)
        }
        
        var unspent []map[string]interface{}
        if err := json.Unmarshal([]byte(unspentJSON), &unspent); err != nil {
            return "", nil, fmt.Errorf("failed to parse UTXOs: %w", err)
        }
        
        for _, utxo := range unspent {
            if totalInputValue >= requiredValue {
                break
            }
            
            txid, _ := utxo["txid"].(string)
            voutF, _ := utxo["vout"].(float64)
            amountF, _ := utxo["amount"].(float64)
            
            if txid == tokenUTXO.TxID && uint32(voutF) == tokenUTXO.Vout {
                continue
            }
            
            vout := uint32(voutF)
            amount := int64(amountF * 100000000)
            
            inputHash, err := chainhash.NewHashFromStr(txid)
            if err != nil {
                continue
            }
            inputOutpoint := wire.NewOutPoint(inputHash, vout)
            input := wire.NewTxIn(inputOutpoint, nil, nil)
            tx.AddTxIn(input)
            
            totalInputValue += amount
            fmt.Printf("📥 Added funding input: %s:%d (%d sats)\n", txid[:8], vout, amount)
        }
        
        if totalInputValue < requiredValue {
            return "", nil, fmt.Errorf("insufficient funds: need %d, have %d", requiredValue, totalInputValue)
        }
    }
    
    // Create outputs to token addresses
    recipientAddr, err := btcutil.DecodeAddress(recipientTokenAddr, Network)
    if err != nil {
        return "", nil, fmt.Errorf("invalid recipient token address: %w", err)
    }
    recipientScript, err := txscript.PayToAddrScript(recipientAddr)
    if err != nil {
        return "", nil, fmt.Errorf("failed to create recipient script: %w", err)
    }
    
    changeAddr, err := btcutil.DecodeAddress(changeTokenAddr, Network)
    if err != nil {
        return "", nil, fmt.Errorf("invalid change token address: %w", err)
    }
    changeScript, err := txscript.PayToAddrScript(changeAddr)
    if err != nil {
        return "", nil, fmt.Errorf("failed to create change script: %w", err)
    }
    
    tx.AddTxOut(wire.NewTxOut(dustAmount, recipientScript))
    tx.AddTxOut(wire.NewTxOut(dustAmount, changeScript))
    
    // Add Bitcoin change if needed
    fee := int64(1000)
    bitcoinChange := totalInputValue - (dustAmount * 2) - fee
    
    if bitcoinChange > dustAmount {
        btcChangeAddr, err := RunBitcoinCommand("getnewaddress")
        if err != nil {
            return "", nil, fmt.Errorf("failed to get bitcoin change address: %w", err)
        }
        btcChange, err := btcutil.DecodeAddress(btcChangeAddr, Network)
        if err != nil {
            return "", nil, fmt.Errorf("invalid bitcoin change address: %w", err)
        }
        btcChangeScript, err := txscript.PayToAddrScript(btcChange)
        if err != nil {
            return "", nil, fmt.Errorf("failed to create bitcoin change script: %w", err)
        }
        tx.AddTxOut(wire.NewTxOut(bitcoinChange, btcChangeScript))
        fmt.Printf("📤 Bitcoin change: %d sats\n", bitcoinChange)
    }
    
    // 4. SIGN AND BROADCAST FUNDING TRANSACTION
    var buf bytes.Buffer
    tx.Serialize(&buf)
    txHex := hex.EncodeToString(buf.Bytes())
    
    fmt.Println("🔐 Signing funding transaction with wallet...")
    signedTxJSON, err := RunBitcoinCommand(fmt.Sprintf("signrawtransactionwithwallet %s", txHex))
    if err != nil {
        return "", nil, fmt.Errorf("failed to sign transaction: %w", err)
    }
    
    var signed struct {
        Hex      string `json:"hex"`
        Complete bool   `json:"complete"`
    }
    if err := json.Unmarshal([]byte(signedTxJSON), &signed); err != nil {
        return "", nil, fmt.Errorf("failed to parse signed tx: %w", err)
    }
    
    if !signed.Complete {
        return "", nil, fmt.Errorf("wallet signing incomplete")
    }
    
    fmt.Println("📤 Broadcasting funding transaction...")
    fundingTxID, err := RunBitcoinCommand(fmt.Sprintf("sendrawtransaction %s", signed.Hex))
    if err != nil {
        return "", nil, fmt.Errorf("failed to broadcast funding transaction: %w", err)
    }
    
    fmt.Printf("✅ Funding transaction: %s\n", fundingTxID)
    
    // 5. REVEAL RECIPIENT TOKEN TO THEIR ADDRESS
    fmt.Println("🔄 Revealing recipient token...")
    recipientRevealTx, err := recipientToken.CreateScriptPathSpendingTx(
        fundingTxID, 0, dustAmount, recipientAddress, 2000,
    )
    if err != nil {
        return "", nil, fmt.Errorf("failed to create recipient reveal tx: %w", err)
    }
    
    var recipientBuf bytes.Buffer
    recipientRevealTx.Serialize(&recipientBuf)
    recipientRevealHex := hex.EncodeToString(recipientBuf.Bytes())
    
    recipientRevealTxID, err := RunBitcoinCommand(fmt.Sprintf("sendrawtransaction %s", recipientRevealHex))
    if err != nil {
        return "", nil, fmt.Errorf("failed to broadcast recipient reveal: %w", err)
    }
    
    // 6. REVEAL CHANGE TOKEN TO YOUR WALLET
    fmt.Println("🔄 Revealing change token...")
    myChangeAddress, err := RunBitcoinCommand("getnewaddress \"TSBToken-Change\" \"bech32m\"")
    if err != nil {
        return "", nil, fmt.Errorf("failed to get change address: %w", err)
    }
    
    changeRevealTx, err := changeToken.CreateScriptPathSpendingTx(
        fundingTxID, 1, dustAmount, myChangeAddress, 2000,
    )
    if err != nil {
        return "", nil, fmt.Errorf("failed to create change reveal tx: %w", err)
    }
    
    var changeBuf bytes.Buffer
    changeRevealTx.Serialize(&changeBuf)
    changeRevealHex := hex.EncodeToString(changeBuf.Bytes())
    
    changeRevealTxID, err := RunBitcoinCommand(fmt.Sprintf("sendrawtransaction %s", changeRevealHex))
    if err != nil {
        return "", nil, fmt.Errorf("failed to broadcast change reveal: %w", err)
    }
    
    recipientFunding := &FundingData{
        TxID:    recipientRevealTxID,
        Vout:    0,
        Value:   dustAmount - 2000, // After fee
        Address: recipientAddress,
    }
    
    fmt.Printf("✅ Wallet-native split completed!\n")
    fmt.Printf("   Funding transaction: %s\n", fundingTxID)
    fmt.Printf("   Recipient reveal: %s\n", recipientRevealTxID)
    fmt.Printf("   Change reveal: %s\n", changeRevealTxID)
    fmt.Printf("   Recipient: %d tokens\n", transferAmount)
    fmt.Printf("   Change: %d tokens\n", changeAmount)
    
    return recipientRevealTxID, recipientFunding, nil
}

func main() {
	// Command parsing
	var command string
	if len(os.Args) > 1 && !strings.HasPrefix(os.Args[1], "--") {
		command = os.Args[1]
		// Remove the command from args for easier processing
		os.Args = append(os.Args[:1], os.Args[2:]...)
	}

	// Process known commands
	switch command {
	case "transfer":
		handleTransferCommand()
		return
	case "extract-token":
		handleExtractCommand()
		return
	case "create":
		handleCreateCommand()
	case "manage-received":
		if len(os.Args) < 2 {
			fmt.Fprintln(os.Stderr, "❌ Missing transaction ID")
			fmt.Fprintln(os.Stderr, "Usage: ./tsb-token-cli manage-received <txid>")
			os.Exit(1)
		}

		txid := os.Args[1]
		err := ManageReceivedToken(txid)
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ Failed to manage received token: %v\n", err)
			os.Exit(1)
		}
		return
		return
	case "scan":
		tokens, err := ScanWalletForTokens()
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ Scan failed: %v\n", err)
			os.Exit(1)
		}
		if len(tokens) == 0 {
			fmt.Println("No tokens found in your wallet.")
			os.Exit(0)
		}
		fmt.Println("🔍 Tokens in your wallet:")
		for i, t := range tokens {
			fmt.Printf("%d. Token: %s\n", i+1, t.TokenData.TokenID)
			fmt.Printf("   Amount: %d\n", t.TokenData.Amount)
			fmt.Printf("   Metadata: %s\n", t.TokenData.Metadata)
			fmt.Printf("   UTXO: %s:%d (%d sats)\n\n",
				t.Funding.TxID, t.Funding.Vout, t.Funding.Value)
		}
		os.Exit(0)

	case "test-deterministic":
		fmt.Println("🧪 Testing deterministic key derivation...")

		tokenID := "TEST-DETERMINISTIC"
		utxoRef := "1234567890abcdef:0"

		fmt.Println("Test 1: First derivation")
		token1, addr1, err := DeriveTokenKeyDeterministic(tokenID, utxoRef)
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ Error in test 1: %v\n", err)
			os.Exit(1)
		}

		fmt.Println("\nTest 2: Second derivation (should match)")
		token2, addr2, err := DeriveTokenKeyDeterministic(tokenID, utxoRef)
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ Error in test 2: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("\n🔍 Results:\n")
		fmt.Printf("  Address 1: %s\n", addr1)
		fmt.Printf("  Address 2: %s\n", addr2)
		fmt.Printf("  Addresses match: %v\n", addr1 == addr2)

		// Check if we have private keys (legacy wallet) or not (descriptor wallet)
		if token1.PrivateKey != nil && token2.PrivateKey != nil {
			fmt.Printf("  Private keys match: %v\n", bytes.Equal(token1.PrivateKey.Serialize(), token2.PrivateKey.Serialize()))
			if addr1 == addr2 && bytes.Equal(token1.PrivateKey.Serialize(), token2.PrivateKey.Serialize()) {
				fmt.Println("✅ Deterministic key derivation working correctly! (Legacy wallet mode)")
			} else {
				fmt.Println("❌ Deterministic key derivation failed!")
			}
		} else {
			fmt.Printf("  Wallet mode: Descriptor (no private key extraction)\n")
			if addr1 == addr2 {
				fmt.Println("✅ Deterministic address generation working correctly! (Descriptor wallet mode)")
			} else {
				fmt.Println("❌ Deterministic address generation failed!")
			}
		}

		os.Exit(0)

	case "reveal-hybrid":
		fmt.Println("🔄 Running direct hybrid reveal...")

		txid, err := RevealHybridToken("not-used")
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ Error revealing hybrid token: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("✅ Token revealed on-chain:", txid)

		// Reveal the token data
		keyHex, err := os.ReadFile("token_key.hex")
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ Could not read token_key.hex: %v\n", err)
			os.Exit(1)
		}
		tkn, err := LoadTaprootToken(strings.TrimSpace(string(keyHex)))
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ Could not load TaprootToken: %v\n", err)
			os.Exit(1)
		}

		revealHexFile := "reveal_hybrid_tx.hex"
		if _, err := os.Stat(revealHexFile); os.IsNotExist(err) {
			revealHexFile = "spending_tx.hex"
		}

		rawHex, err := os.ReadFile(revealHexFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ Could not read transaction hex: %v\n", err)
			os.Exit(1)
		}

		revealed, err := tkn.RevealTokenDataFromHex(string(rawHex))
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ Error extracting on-chain data: %v\n", err)
			os.Exit(1)
		}

		fmt.Println("\n🔓 Revealed Token Data:")
		fmt.Printf("  TokenID   : %s\n", revealed.TokenID)
		fmt.Printf("  Amount    : %d\n", revealed.Amount)
		fmt.Printf("  TypeCode  : %d\n", revealed.TypeCode)
		fmt.Printf("  Metadata  : %s\n", revealed.Metadata)
		fmt.Printf("  Timestamp : %d\n", revealed.Timestamp)

		return

	default:
		fmt.Fprintln(os.Stderr, `❌ No command specified or unknown command.

Usage:
  ./tsb-token-cli create --name <id> --amount <amt> --metadata <text> --typecode <int>
  ./tsb-token-cli transfer --to <address> --amount <amt> [--recipientpub <hex>]
  ./tsb-token-cli transfer --list
  ./tsb-token-cli scan
  ./tsb-token-cli reveal-hybrid
  ./tsb-token-cli extract-token <txid>

Description:
  create         Create a new Taproot-based token
  transfer       Transfer part or all of a token to another address
  scan           Scan wallet UTXOs for embedded TSB tokens
  reveal-hybrid  Reveal a token in hybrid mode, making it visible in your wallet
  extract-token  Extract token data from a specific transaction
`)
		os.Exit(1)
	}
}
