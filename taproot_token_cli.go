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
)

// ---------------------- Bitcoin CLI Runner ----------------------

const BitcoinCLI = "bitcoin-cli -regtest -rpcwallet=token_wallet"

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

func CreateToken(tokenID string, amount uint64, metadata string) (*OutputData, error) {
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
        Timestamp: uint64(time.Now().Unix()), // 🔥🔥🔥
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


// ---------------------- CLI Entrypoint ----------------------

func main() {
	var tokenName = "gobi-token"
	var tokenAmount uint64 = 1337
	var tokenMetadata = "TSB reveal test"

	// Handle optional CLI arguments
	if len(os.Args) > 1 {
		for i := 1; i < len(os.Args); i++ {
			arg := os.Args[i]
			if arg == "--name" && i+1 < len(os.Args) {
				tokenName = os.Args[i+1]
				i++
			} else if arg == "--amount" && i+1 < len(os.Args) {
				amt, err := strconv.ParseUint(os.Args[i+1], 10, 64)
				if err != nil {
					fmt.Fprintf(os.Stderr, "❌ Invalid amount: %v\n", err)
					os.Exit(1)
				}
				tokenAmount = amt
				i++
			} else if arg == "--metadata" && i+1 < len(os.Args) {
				tokenMetadata = os.Args[i+1]
				i++
			}
		}
	}

	fmt.Println("\n🔄 Creating token...")
	output, err := CreateToken(tokenName, tokenAmount, tokenMetadata)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Error creating token: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("✅ Token created successfully")

	fmt.Println("\n🔄 Funding the address...")
	funding, err := FundAddress(output.Address, 1.0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Error funding address: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("✅ Address funded: %s:%d (%d sats)\n", funding.TxID, funding.Vout, funding.Value)

	fmt.Println("\n🔄 Generating destination address...")
	newAddress, err := RunBitcoinCommand("getnewaddress")
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Error generating new address: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("✅ Destination address:", newAddress)

	fmt.Println("\n🔄 Spending token (script-path spend)...")
	txid, err := SpendToken(newAddress)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Error spending token: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("✅ Token spent on-chain:", txid)

	fmt.Println("\n🔄 Revealing embedded token data from on-chain spending_tx.hex...")
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
	fmt.Printf("  TokenID : %s\n", revealed.TokenID)
	fmt.Printf("  Amount  : %d\n", revealed.Amount)
	fmt.Printf("  Metadata: %s\n", revealed.Metadata)
	fmt.Printf("  Timestamp: %d\n", revealed.Timestamp)

	fmt.Println("\n🎉 All operations completed successfully with no fake fallbacks!")
}