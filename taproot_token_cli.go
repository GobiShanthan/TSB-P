package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
	"strconv"
	"github.com/btcsuite/btcd/btcec/v2"
    "github.com/btcsuite/btcd/btcutil"
    "github.com/btcsuite/btcd/chaincfg/chainhash"
    "github.com/btcsuite/btcd/txscript"
    "github.com/btcsuite/btcd/wire"
)

// ---------------------- Bitcoin CLI Runner ----------------------

const BitcoinCLI = "bitcoin-cli -testnet -rpcwallet=token_wallet"


func RunBitcoinCommand(args string) (string, error) {
	cmd := exec.Command("sh", "-c", fmt.Sprintf("%s %s", BitcoinCLI, args))
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("bitcoin-cli error: %v - %s", err, string(output))
	}
	return strings.TrimSpace(string(output)), nil
}

// ---------------------- File Utilities ----------------------

type FundingData struct {
	TxID    string  `json:"txid"`
	Vout    uint32  `json:"vout"`
	Value   int64   `json:"value"`
	Address string  `json:"address"`
}

type OutputData struct {
	Address         string    `json:"address"`
	ScriptHex       string    `json:"scriptHex"`
	ControlBlockHex string    `json:"controlBlockHex"`
	TokenData       TokenData `json:"tokenData"`
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
    var token *TaprootToken
    var err error

    keyFile := "token_key.hex"
    if _, err := os.Stat(keyFile); err == nil {
        privKeyHex, err := os.ReadFile(keyFile)
        if err != nil {
            return nil, err
        }
        token, err = LoadTaprootToken(string(privKeyHex))
        if err != nil {
            return nil, err
        }
    } else {
        token, err = NewTaprootToken()
        if err != nil {
            return nil, err
        }
        err = token.SavePrivateKey(keyFile)
        if err != nil {
            return nil, err
        }
    }

    paddedTokenID := tokenID
    if len(tokenID) < 16 {
        paddedTokenID = tokenID + strings.Repeat("\x00", 16-len(tokenID))
    } else if len(tokenID) > 16 {
        paddedTokenID = tokenID[:16]
    }

    // 🔥 IMPORTANT: Set timestamp now
    tokenData := &TokenData{
        TokenID:   paddedTokenID,
        Amount:    amount,
        Metadata:  metadata,
        Timestamp: uint64(time.Now().Unix()), 
		TypeCode:  typeCode,
    }

    scriptTree, err := token.CreateTaprootOutput(tokenData)
    if err != nil {
        return nil, err
    }

    address, err := token.GetTaprootAddress()
    if err != nil {
        return nil, err
    }

    output := &OutputData{
        Address:         address,
        ScriptHex:       hex.EncodeToString(scriptTree.Script),
        ControlBlockHex: hex.EncodeToString(scriptTree.ControlBlock),
        TokenData:       *tokenData, // ✅ Save timestamp inside
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

func SpendToken(destination string) (string, error) {
	fmt.Println("\n🔍 DEBUG: Starting SpendToken")
	
	keyHex, err := os.ReadFile("token_key.hex")
	if err != nil {
		return "", err
	}
	fmt.Println("🔍 DEBUG: Private key loaded")
	
	token, err := LoadTaprootToken(string(keyHex))
	if err != nil {
		return "", err
	}
	fmt.Println("🔍 DEBUG: Token loaded")
	
	outputData, err := LoadOutputData("taproot_output.json")
	if err != nil {
		return "", err
	}
	fmt.Println("🔍 DEBUG: Output data loaded")
	
	fundingData, err := LoadFundingData("funding_data.json")
	if err != nil {
		return "", err
	}
	fmt.Println("🔍 DEBUG: Funding data loaded")
	fmt.Printf("🔍 DEBUG: Funding TxID: %s, Vout: %d, Value: %d\n", 
		fundingData.TxID, fundingData.Vout, fundingData.Value)

	// IMPORTANT: Create a completely fresh Taproot output with exactly the same data
	tokenData := &TokenData{
		TokenID:  outputData.TokenData.TokenID,
		Amount:   outputData.TokenData.Amount,
		TypeCode:  outputData.TokenData.TypeCode,
		Metadata: outputData.TokenData.Metadata,
		Timestamp: outputData.TokenData.Timestamp,
	}
	
	scriptTree, err := token.CreateTaprootOutput(tokenData)
if err != nil {
    return "", err
}

// ✅ Call GetTaprootAddress right after scriptTree
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

fmt.Println("🔍 DEBUG: Generated script hex from memory:")
fmt.Printf("    %x\n", scriptTree.Script)

fmt.Println("🔍 DEBUG: Generated control block:")
fmt.Printf("    %x\n", scriptTree.ControlBlock)

fmt.Println("🔍 DEBUG: Generated tweaked pubkey:")
fmt.Printf("    %x\n", scriptTree.TweakedPubKey.SerializeCompressed())

fmt.Println("🔍 DEBUG: Generated Taproot address from tweaked key:")
fmt.Println("    ", reconstructedAddress)

fmt.Println("🔍 DEBUG: --- FULL DEBUG LOG END ---")
	
	// Verify the script is exactly the same as in the output data
	scriptHex := hex.EncodeToString(scriptTree.Script)
	controlBlockHex := hex.EncodeToString(scriptTree.ControlBlock)
	
	fmt.Printf("🔍 DEBUG: Script match: %v\n", scriptHex == outputData.ScriptHex)
	fmt.Printf("🔍 DEBUG: Control block match: %v\n", controlBlockHex == outputData.ControlBlockHex)
	
	// Get the address from the token to verify it matches
	address, err := token.GetTaprootAddress()
	if err != nil {
		return "", err
	}
	fmt.Printf("🔍 DEBUG: Address match: %v\n", address == fundingData.Address)
	
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

func TransferToken(tokenKeyHex string, tokenUTXO *FundingData, tokenData *TokenData, 
                  transferAmount uint64, recipientPubKey *btcec.PublicKey, feeRate int64) (string, *FundingData, error) {
    token, err := LoadTaprootToken(tokenKeyHex)
    if (err != nil) {
        return "", nil, fmt.Errorf("failed to load token key: %w", err)
    }

    if !ValidateCanonicalTokenID(tokenData.TokenID, tokenUTXO.TxID) {
        return "", nil, fmt.Errorf("canonical token ID mismatch: tokenID does not match txid prefix")
    }

    tx, err := token.SplitToken(
        tokenUTXO.TxID,
        tokenUTXO.Vout,
        tokenUTXO.Value,
        tokenData,
        transferAmount,
        recipientPubKey,
        feeRate,
    )
    if err != nil {
        return "", nil, fmt.Errorf("failed to create transfer transaction: %w", err)
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

    // fallback: return x-only pubkey manually
    xOnly := recipientPubKey.X().Bytes()
    address := hex.EncodeToString(xOnly)

    recipientFunding := &FundingData{
        TxID:    txid,
        Vout:    0,
        Value:   tx.TxOut[0].Value,
        Address: address,
    }

    return txid, recipientFunding, nil
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
func BypassTransferToken(tokenKeyHex string, tokenUTXO *FundingData, tokenData *TokenData, 
                  transferAmount uint64, recipientPubKey *btcec.PublicKey, feeRate int64) (string, *FundingData, error) {
    token, err := LoadTaprootToken(tokenKeyHex)
    if (err != nil) {
        return "", nil, fmt.Errorf("failed to load token key: %w", err)
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
        recipientPubKey,
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
                        additionalNeeded + 1000, // Add a buffer
                        paddedTokenData,
                        transferAmount,
                        recipientPubKey,
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

    // Return x-only pubkey manually
    xOnly := recipientPubKey.X().Bytes()
    address := hex.EncodeToString(xOnly)

    recipientFunding := &FundingData{
        TxID:    txid,
        Vout:    0,
        Value:   tx.TxOut[0].Value,
        Address: address,
    }

    return txid, recipientFunding, nil
}

func handleCreateCommand() {
    var tokenName = "demo-token"
    var tokenAmount uint64 = 1
    var tokenMetadata = "Demo token"
    var tokenTypeCode uint8 = 0
    var recipientKeyFile, recipientPubHex string
    var autofund, autoreveal bool

    for i := 1; i < len(os.Args); i++ {
        switch os.Args[i] {
        case "--name":
            tokenName = os.Args[i+1]; i++
        case "--amount":
            amt, err := strconv.ParseUint(os.Args[i+1], 10, 64)
            if err != nil {
                fmt.Fprintf(os.Stderr, "❌ Invalid amount: %v\n", err)
                os.Exit(1)
            }
            tokenAmount = amt; i++
        case "--metadata":
            tokenMetadata = os.Args[i+1]; i++
        case "--typecode":
            tc, err := strconv.ParseUint(os.Args[i+1], 10, 8)
            if err != nil {
                fmt.Fprintf(os.Stderr, "❌ Invalid typecode: %v\n", err)
                os.Exit(1)
            }
            tokenTypeCode = uint8(tc); i++
        case "--recipientkey":
            recipientKeyFile = os.Args[i+1]; i++
        case "--recipientpub":
            recipientPubHex = os.Args[i+1]; i++
        case "--autofund":
            autofund = true
        case "--autoreveal":
            autoreveal = true
        }
    }

    fmt.Println("🔄 Creating token...")

    var output *OutputData
    var err error

    if recipientKeyFile != "" || recipientPubHex != "" {
        var pubKey *btcec.PublicKey
        if recipientKeyFile != "" {
            privHex, err := os.ReadFile(recipientKeyFile)
            if err != nil {
                fmt.Fprintf(os.Stderr, "❌ Failed to read recipient key: %v\n", err)
                os.Exit(1)
            }
            privKey, _ := btcec.PrivKeyFromBytes(bytes.TrimSpace(privHex))
            pubKey = privKey.PubKey()
        } else {
            pubBytes, err := hex.DecodeString(recipientPubHex)
            if err != nil {
                fmt.Fprintf(os.Stderr, "❌ Invalid recipient pubkey: %v\n", err)
                os.Exit(1)
            }
            pubKey, err = btcec.ParsePubKey(pubBytes)
            if err != nil {
                fmt.Fprintf(os.Stderr, "❌ Failed to parse pubkey: %v\n", err)
                os.Exit(1)
            }
        }

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

        tree, err := issuerToken.CreateTaprootOutputWithOwnership(token, pubKey)
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
        txid, err := SpendToken(newAddr)
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




func handleTransferCommand() {
    var recipientAddress string
    var transferAmount uint64
    var tokenFile string
    var fundingFile string
    var feeRate int64 = 2000
    var recipientPubHex string
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
        case "--recipientpub":
            if i+1 < len(os.Args) {
                recipientPubHex = os.Args[i+1]
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
                Address:         selectedToken.Funding.Address,
                TokenData:       *selectedToken.TokenData,
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

    keyHex, err := os.ReadFile("token_key.hex")
    if err != nil {
        fmt.Fprintf(os.Stderr, "❌ Failed to read token key: %v\n", err)
        os.Exit(1)
    }

    if transferAmount > outputData.TokenData.Amount {
        fmt.Fprintf(os.Stderr, "❌ You do not own enough of the token. Balance: %d, Requested: %d\n", outputData.TokenData.Amount, transferAmount)
        os.Exit(1)
    }

    var recipientPubKey *btcec.PublicKey
    if recipientPubHex != "" {
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
    } else {
        tmpKey, _ := btcec.NewPrivateKey()
        recipientPubKey = tmpKey.PubKey()
        fmt.Println("⚠️ No recipient pubkey provided, generated temporary one")
    }

    fmt.Println("🔄 Creating transfer transaction...")
    var txid string
    var recipientFunding *FundingData

    // Check if this is a detected token
    isDetectedToken := tokenFile == "temp_token_output.json"
    if isDetectedToken {
        fmt.Println("⚠️ Using bypass transfer for token detected from blockchain")
        txid, recipientFunding, err = BypassTransferToken(
            strings.TrimSpace(string(keyHex)),
            fundingData,
            &outputData.TokenData,
            transferAmount,
            recipientPubKey,
            feeRate,
        )
    } else {
        txid, recipientFunding, err = TransferToken(
            strings.TrimSpace(string(keyHex)),
            fundingData,
            &outputData.TokenData,
            transferAmount,
            recipientPubKey,
            feeRate,
        )
    }

    if err != nil {
        fmt.Fprintf(os.Stderr, "❌ Transfer failed: %v\n", err)
        os.Exit(1)
    }

    // Update token balance in file
    outputData.TokenData.Amount -= transferAmount
    _ = SaveOutputData(tokenFile, outputData)
    _ = SaveFundingData("recipient_funding.json", recipientFunding)

    fmt.Println("\n✅ Token transfer successful!")
    fmt.Println("  Token       :", outputData.TokenData.TokenID)
    fmt.Printf("  To (x-only) : %s\n", recipientFunding.Address)
    fmt.Println("  Amount      :", transferAmount)
    fmt.Println("  Transaction :", txid)
    fmt.Println("  Remaining   :", outputData.TokenData.Amount)
}

// ScanWalletForTokens directly examines UTXOs for token data
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
    
    tokens := []*TokenWithFunding{}
    
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
        
        // Found a token!
        fmt.Printf("✅ Found token in UTXO %s:%d\n", txid, int(vout))
        fmt.Printf("   Token ID: %s\n", tokenData.TokenID)
        fmt.Printf("   Amount: %d\n", tokenData.Amount)
        
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


// CreateMultiInputTokenTransaction creates a transaction with multiple inputs to fund a token transfer
func (t *TaprootToken) CreateMultiInputTokenTransaction(
    tokenUTXO *FundingData,
    additionalFunds int64, // How many more satoshis we need
    tokenData *TokenData,
    transferAmount uint64,
    recipientPubKey *btcec.PublicKey,
    feeRate int64,
) (*wire.MsgTx, error) {
    fmt.Printf("📊 Creating multi-input transaction (need %d more sats)\n", additionalFunds)
    
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
    
    // Create recipient output with token
    recipientTokenData := &TokenData{
        TokenID:   tokenData.TokenID,
        Amount:    transferAmount,
        TypeCode:  tokenData.TypeCode,
        Metadata:  tokenData.Metadata,
        Timestamp: uint64(time.Now().Unix()),
    }
    
    recipientScriptTree, err := t.CreateTaprootOutputWithOwnership(recipientTokenData, recipientPubKey)
    if err != nil {
        return nil, fmt.Errorf("failed to create recipient script: %w", err)
    }
    
    recipientPubKeyBytes := recipientScriptTree.TweakedPubKey.SerializeCompressed()[1:33]
    recipientAddr, err := btcutil.NewAddressTaproot(recipientPubKeyBytes, Network)
    if err != nil {
        return nil, fmt.Errorf("failed to create recipient address: %w", err)
    }
    
    recipientScript, err := txscript.PayToAddrScript(recipientAddr)
    if err != nil {
        return nil, fmt.Errorf("failed to create recipient script: %w", err)
    }
    
    // Use minimum dust amount for the token output
    const minOutputAmount = 546
    recipientTxOut := wire.NewTxOut(minOutputAmount, recipientScript)
    tx.AddTxOut(recipientTxOut)
    fmt.Printf("📤 Added recipient output: %d sats to %s\n", minOutputAmount, recipientAddr.EncodeAddress())
    
    // Add change output for token if needed
    if changeAmount := tokenData.Amount - transferAmount; changeAmount > 0 {
        changeTokenData := &TokenData{
            TokenID:   tokenData.TokenID,
            Amount:    changeAmount,
            TypeCode:  tokenData.TypeCode,
            Metadata:  tokenData.Metadata,
            Timestamp: uint64(time.Now().Unix()),
        }
        
        changeScriptTree, err := t.CreateTaprootOutputWithOwnership(changeTokenData, t.PublicKey)
        if err != nil {
            return nil, fmt.Errorf("failed to create change script: %w", err)
        }
        
        changePubKeyBytes := changeScriptTree.TweakedPubKey.SerializeCompressed()[1:33]
        changeAddr, err := btcutil.NewAddressTaproot(changePubKeyBytes, Network)
        if err != nil {
            return nil, fmt.Errorf("failed to create change address: %w", err)
        }
        
        changeScript, err := txscript.PayToAddrScript(changeAddr)
        if err != nil {
            return nil, fmt.Errorf("failed to create change script: %w", err)
        }
        
        changeTxOut := wire.NewTxOut(minOutputAmount, changeScript)
        tx.AddTxOut(changeTxOut)
        fmt.Printf("📤 Added token change output: %d sats with %d tokens\n", minOutputAmount, changeAmount)
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
    
    if bitcoinChange > 546 {
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
    case "create":
        handleCreateCommand()
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

default:
    fmt.Fprintln(os.Stderr, `❌ No command specified or unknown command.

Usage:
  ./tsb-token-cli create --name <id> --amount <amt> --metadata <text> --typecode <int>
  ./tsb-token-cli transfer --to <address> --amount <amt> [--recipientpub <hex>]
  ./tsb-token-cli transfer --list
  ./tsb-token-cli scan

Description:
  create     Create a new Taproot-based token
  transfer   Transfer part or all of a token to another address
  scan       Scan wallet UTXOs for embedded TSB tokens
`)
    os.Exit(1)
    }
}
