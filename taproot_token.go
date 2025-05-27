package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"os"
    "sort"
	"fmt"
    "time"
    "encoding/json"
    "strings"
    "strconv"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
  

)

const (
	TapscriptLeafTaggedHash = "TapLeaf"
	TaprootTweakTaggedHash   = "TapTweak"
	TapscriptLeafVersion     = 0xc0
)

var Network = &chaincfg.TestNet3Params

type TokenData struct {
	TokenID   string
	Amount    uint64
	TypeCode  byte
	Metadata  string
	Timestamp uint64
}

func UpdateWithCanonicalTokenID(tokenData *TokenData, revealTxID string) {
    // Extract original name without any txid suffix
    originalName := tokenData.TokenID
    if strings.Contains(originalName, ":") {
        parts := strings.Split(originalName, ":")
        originalName = parts[0]
    }
    
    // Remove null padding
    originalName = strings.TrimRight(originalName, "\x00")
    
    // Use first 8 chars of the revealTxID
    shortRevealID := revealTxID
    if len(revealTxID) > 8 {
        shortRevealID = revealTxID[:8]
    }
    
    // Format: NAME:REVEAL8
    tokenData.TokenID = fmt.Sprintf("%s:%s", originalName, shortRevealID)
}

// ValidateCanonicalTokenID verifies the token ID suffix matches the reveal TXID
func ValidateCanonicalTokenID(tokenID string, revealTxID string) bool {
    // Check if TokenID has the expected format
    parts := strings.Split(tokenID, ":")
    if len(parts) != 2 {
        return false
    }
    
    // Extract the TXID portion from TokenID
    tokenIDSuffix := parts[1]
    
    // Get the first N chars of the actual txid (matching suffix length)
    shortTxID := revealTxID
    if len(revealTxID) > len(tokenIDSuffix) {
        shortTxID = revealTxID[:len(tokenIDSuffix)]
    }
    
    // Validate they match
    return tokenIDSuffix == shortTxID
}



func (t *TokenData) ToBytes() []byte {
	tokenIDBuf := []byte(t.TokenID)
	tokenIDLen := uint16(len(tokenIDBuf))
	metadataBuf := []byte(t.Metadata)
	metadataLen := uint16(len(metadataBuf))

	totalSize := 2 + len(tokenIDBuf) + 8 + 2 + len(metadataBuf)
	buf := make([]byte, totalSize)

	offset := 0
	binary.LittleEndian.PutUint16(buf[offset:], tokenIDLen)
	offset += 2
	copy(buf[offset:], tokenIDBuf)
	offset += len(tokenIDBuf)

	binary.LittleEndian.PutUint64(buf[offset:], t.Amount)
	offset += 8

	binary.LittleEndian.PutUint16(buf[offset:], metadataLen)
	offset += 2
	copy(buf[offset:], metadataBuf)

	return buf
}

func TokenDataFromBytes(buf []byte) (*TokenData, error) {
	if len(buf) < 12 {
		return nil, errors.New("buffer too small for token data")
	}

	offset := 0
	tokenIDLen := binary.LittleEndian.Uint16(buf[offset:])
	offset += 2
	if offset+int(tokenIDLen) > len(buf) {
		return nil, errors.New("invalid tokenID length")
	}
	tokenID := string(buf[offset : offset+int(tokenIDLen)])
	offset += int(tokenIDLen)

	amount := binary.LittleEndian.Uint64(buf[offset:])
	offset += 8

	metadataLen := binary.LittleEndian.Uint16(buf[offset:])
	offset += 2
	if offset+int(metadataLen) > len(buf) {
		return nil, errors.New("invalid metadata length")
	}
	metadata := string(buf[offset : offset+int(metadataLen)])

	return &TokenData{
		TokenID:  tokenID,
		Amount:   amount,
		Metadata: metadata,
	}, nil
}

func TaggedHash(tag string, data []byte) []byte {
	tagHash := sha256.Sum256([]byte(tag))
	h := sha256.New()
	h.Write(tagHash[:])
	h.Write(tagHash[:])
	h.Write(data)
	return h.Sum(nil)
}

type TaprootScriptTree struct {
	Script        []byte
	LeafHash      []byte
	MerkleRoot    []byte
	TweakedPubKey *btcec.PublicKey
	ControlBlock  []byte
    InternalKey   *btcec.PublicKey
}

type TaprootToken struct {
	PrivateKey *btcec.PrivateKey
	PublicKey  *btcec.PublicKey
	ScriptTree *TaprootScriptTree
}

func NewTaprootToken() (*TaprootToken, error) {
	privKey, err := btcec.NewPrivateKey()
	if err != nil {
		return nil, err
	}
	return &TaprootToken{
		PrivateKey: privKey,
		PublicKey:  privKey.PubKey(),
	}, nil
}

func LoadTaprootToken(privKeyHex string) (*TaprootToken, error) {
	privKeyBytes, err := hex.DecodeString(privKeyHex)
	if err != nil {
		return nil, err
	}
	privKey, _ := btcec.PrivKeyFromBytes(privKeyBytes)
	return &TaprootToken{
		PrivateKey: privKey,
		PublicKey:  privKey.PubKey(),
	}, nil
}

func (t *TaprootToken) CreateTaprootOutput(token *TokenData) (*TaprootScriptTree, error) {
    builder := txscript.NewScriptBuilder()

    builder.AddOp(txscript.OP_TRUE)  // 👈 ADD this first
    builder.AddOp(txscript.OP_IF)    // 👈 THEN this

    // Push standard fields
    builder.AddData([]byte("TSB"))                             // Marker
    builder.AddData([]byte(token.TokenID))                     // TokenID
    amountBytes := make([]byte, 8)
    binary.BigEndian.PutUint64(amountBytes, token.Amount)
    builder.AddData(amountBytes)                               // Amount
    builder.AddData([]byte{token.TypeCode})                    // TypeCode

    // Drop standard fields
    builder.AddOp(txscript.OP_DROP)
    builder.AddOp(txscript.OP_DROP)
    builder.AddOp(txscript.OP_DROP)
    builder.AddOp(txscript.OP_DROP)

    // Push optional fields
    builder.AddData([]byte(token.Metadata))                    // Metadata
    timestampBytes := make([]byte, 8)
    binary.BigEndian.PutUint64(timestampBytes, token.Timestamp)
    builder.AddData(timestampBytes)                            // Timestamp

    // Drop optional fields
    builder.AddOp(txscript.OP_DROP)                            // Timestamp
    builder.AddOp(txscript.OP_DROP)                            // Metadata

    // Final programmable logic (basic OP_TRUE for now)
    builder.AddOp(txscript.OP_TRUE)

    // End with OP_ENDIF
    builder.AddOp(txscript.OP_ENDIF)

    // Compile the script
    script, err := builder.Script()
    if err != nil {
        return nil, err
    }

    // Taproot leaf creation
    var sizeBuf [binary.MaxVarintLen64]byte
    sz := binary.PutUvarint(sizeBuf[:], uint64(len(script)))
    leafInput := make([]byte, 1+sz+len(script))
    leafInput[0] = TapscriptLeafVersion
    copy(leafInput[1:], sizeBuf[:sz])
    copy(leafInput[1+sz:], script)

    leafHash := TaggedHash(TapscriptLeafTaggedHash, leafInput)
    merkleRoot := leafHash
    tweakedPubKey := txscript.ComputeTaprootOutputKey(t.PublicKey, merkleRoot)

    internalX := t.PublicKey.SerializeCompressed()[1:33]
    comp := tweakedPubKey.SerializeCompressed()
    var parity byte
    if comp[0] == 0x03 {
        parity = 1
    }
    cb0 := TapscriptLeafVersion | parity
    controlBlock := append([]byte{cb0}, internalX...)

    tree := &TaprootScriptTree{
        Script:        script,
        LeafHash:      leafHash,
        MerkleRoot:    merkleRoot,
        TweakedPubKey: tweakedPubKey,
        ControlBlock:  controlBlock,
    }
    t.ScriptTree = tree
    return tree, nil
}




// For debugging, let's add a helper function to dump the transaction hex
func DumpTransactionHex(tx *wire.MsgTx) string {
    var buf bytes.Buffer
    tx.Serialize(&buf)
    return hex.EncodeToString(buf.Bytes())
}

// GetTaprootAddress returns the bech32m P2TR address for your output key Q.
func (t *TaprootToken) GetTaprootAddress() (string, error) {
    if t.ScriptTree == nil || t.ScriptTree.TweakedPubKey == nil {
        return "", errors.New("script tree not initialized")
    }

    comp := t.ScriptTree.TweakedPubKey.SerializeCompressed()
    xOnly := comp[1:33]
    addr, err := btcutil.NewAddressTaproot(xOnly, Network)
    if err != nil {
        return "", err
    }
    return addr.EncodeAddress(), nil
}


// CreateScriptPathSpendingTx constructs a script-path spend witness using
// your saved script and control block.
func (t *TaprootToken) CreateScriptPathSpendingTx(
    prevTxID string,
    prevTxIndex uint32,
    amount int64,
    toAddress string,
    feeRate int64,
) (*wire.MsgTx, error) {
    if t.ScriptTree == nil {
        return nil, errors.New("script tree not initialized")
    }

    // 1) Outpoint
    prevHash, err := chainhash.NewHashFromStr(prevTxID)
    if err != nil {
        return nil, err
    }
    out := wire.NewOutPoint(prevHash, prevTxIndex)
    txIn := wire.NewTxIn(out, nil, nil)

    // 2) Destination script
    destAddr, err := btcutil.DecodeAddress(toAddress, Network)
    if err != nil {
        return nil, err
    }
    destScript, err := txscript.PayToAddrScript(destAddr)
    if err != nil {
        return nil, err
    }

    // 3) Fee & outputs
    const estSize = 200
    fee := (feeRate * estSize) / 1000
    
    // Lower minimum fee for small test transactions
    if fee < 300 {
        fee = 300
    }
    
    sendAmt := amount - fee
    if sendAmt <= 0 {
        return nil, errors.New("insufficient funds for fee")
    }
    txOut := wire.NewTxOut(sendAmt, destScript)

    tx := wire.NewMsgTx(2)
    tx.AddTxIn(txIn)
    tx.AddTxOut(txOut)

    // 4) Script-path witness: [<script> <controlBlock>]
    witness := wire.TxWitness{
        t.ScriptTree.Script,           // your script
        t.ScriptTree.ControlBlock,     // your control block
    }
    tx.TxIn[0].Witness = witness

    return tx, nil
}



// Update the SplitToken function to fix the label search pattern
func (t *TaprootToken) SplitToken(prevTxID string, prevTxIndex uint32, prevAmount int64,
    tokenData *TokenData, transferAmount uint64, recipientAddress string, feeRate int64) (*wire.MsgTx, error) {

    if transferAmount == 0 || transferAmount > tokenData.Amount {
        return nil, fmt.Errorf("invalid transfer amount")
    }

    changeAmount := tokenData.Amount - transferAmount

    // ✅ Find the existing wallet key that was used to create this token
    if t.ScriptTree == nil {
        fmt.Println("🔧 Finding the original wallet key for this token...")
        
        // Extract original name without any txid suffix
        originalName := tokenData.TokenID
        if strings.Contains(originalName, ":") {
            parts := strings.Split(originalName, ":")
            originalName = parts[0]
        }
        
        // Remove null padding
        originalName = strings.TrimRight(originalName, "\x00")
        
        fmt.Printf("🔍 Looking for existing key for token ID: %s\n", originalName)
        
        // Search wallet addresses for the token label
        addressesJSON, err := RunBitcoinCommand("listaddressgroupings")
        if err != nil {
            return nil, fmt.Errorf("failed to list addresses: %w", err)
        }

        var addresses [][]interface{}
        if err := json.Unmarshal([]byte(addressesJSON), &addresses); err != nil {
            return nil, fmt.Errorf("failed to parse addresses: %w", err)
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

                        // ✅ FIXED: Check for both label formats
                        // Old format: "Token:SPX:" 
                        // New format: "TokenPath:m/86'/1'/0'/0/123456:SPX"
                        tokenMatches := strings.Contains(labelStr, "Token:"+originalName+":") || 
                                       strings.Contains(labelStr, ":"+originalName) && strings.Contains(labelStr, "TokenPath:")
                        
                        if tokenMatches {
                            tokenAddress = addrStr
                            found = true
                            fmt.Printf("✅ Found existing token address: %s (label: %s)\n", tokenAddress, labelStr)
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

        if !found {
            return nil, fmt.Errorf("could not find existing wallet key for token %s", originalName)
        }

        // Get the private key for this address
        privKeyWIF, err := RunBitcoinCommand(fmt.Sprintf("dumpprivkey %s", tokenAddress))
        if err != nil {
            return nil, fmt.Errorf("failed to get private key for token address: %w", err)
        }

        // Convert WIF to private key
        wif, err := btcutil.DecodeWIF(privKeyWIF)
        if err != nil {
            return nil, fmt.Errorf("failed to decode WIF: %w", err)
        }

        privKey, _ := btcec.PrivKeyFromBytes(wif.PrivKey.Serialize())
        
        // Create token with the original key
        derivedToken := &TaprootToken{
            PrivateKey: privKey,
            PublicKey:  privKey.PubKey(),
        }
        
        // Create the ScriptTree using the original token data
        _, err = derivedToken.CreateTaprootOutput(tokenData)
        if err != nil {
            return nil, fmt.Errorf("failed to recreate ScriptTree: %w", err)
        }
        
        // Copy everything to our token
        t.ScriptTree = derivedToken.ScriptTree
        t.PrivateKey = derivedToken.PrivateKey
        t.PublicKey = derivedToken.PublicKey
        
        fmt.Println("✅ ScriptTree reconstructed using original wallet key")
    }

    // ... rest of the function remains the same ...
    fmt.Println("🔄 Creating new token addresses...")

// Create a deterministic token for the recipient using their wallet
fmt.Println("🔑 Creating deterministic token for recipient...")

// Use the funding transaction as UTXO reference for deterministic key
recipientToken, err := NewTaprootToken()
if err != nil {
    return nil, fmt.Errorf("failed to create recipient token: %w", err)
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
        return nil, fmt.Errorf("failed to create recipient token output: %w", err)
    }

    recipientTokenAddr, err := recipientToken.GetTaprootAddress()
    if err != nil {
        return nil, fmt.Errorf("failed to get recipient token address: %w", err)
    }

    fmt.Printf("✅ Created recipient token address: %s (%d tokens)\n", recipientTokenAddr, transferAmount)

    // 2. CREATE CHANGE TOKEN (if needed)
    var changeToken *TaprootToken
    var changeTokenAddr string
    if changeAmount > 0 {
        changeToken, err = NewTaprootToken()
        if err != nil {
            return nil, fmt.Errorf("failed to create change token: %w", err)
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
            return nil, fmt.Errorf("failed to create change token output: %w", err)
        }

        changeTokenAddr, err = changeToken.GetTaprootAddress()
        if err != nil {
            return nil, fmt.Errorf("failed to get change token address: %w", err)
        }

        fmt.Printf("✅ Created change token address: %s (%d tokens)\n", changeTokenAddr, changeAmount)
    }

    // 3. CREATE FUNDING TRANSACTION
    fmt.Println("🔄 Creating funding transaction...")

    const dustAmount = int64(10000)
    outputsNeeded := dustAmount * 2 // Both recipient and change
    if changeAmount == 0 {
        outputsNeeded = dustAmount // Only recipient
    }
    fee := int64(10000)
    totalNeeded := outputsNeeded + fee

    fmt.Printf("💰 Need %d sats total, have %d sats in token UTXO\n", totalNeeded, prevAmount)

    var tx *wire.MsgTx

    if prevAmount < totalNeeded {
        // Multi-input transaction needed
        fmt.Printf("⚠️ Insufficient funds in token UTXO. Need %d more satoshis\n", totalNeeded-prevAmount)
        fmt.Println("🔄 Creating multi-input funding transaction...")

        prevHash, err := chainhash.NewHashFromStr(prevTxID)
        if err != nil {
            return nil, err
        }
        tokenOutpoint := wire.NewOutPoint(prevHash, prevTxIndex)
        tokenTxIn := wire.NewTxIn(tokenOutpoint, nil, nil)

        tx = wire.NewMsgTx(2)
        tx.AddTxIn(tokenTxIn)

        // Get additional wallet UTXOs
        unspentJSON, err := RunBitcoinCommand("listunspent")
        if err != nil {
            return nil, fmt.Errorf("failed to list wallet UTXOs: %w", err)
        }

        var unspent []map[string]interface{}
        if err := json.Unmarshal([]byte(unspentJSON), &unspent); err != nil {
            return nil, fmt.Errorf("failed to parse UTXO list: %w", err)
        }

        additionalFunds := int64(0)
        usedUTXOs := make(map[string]bool)
        tokenUTXOKey := prevTxID + ":" + strconv.Itoa(int(prevTxIndex))
        usedUTXOs[tokenUTXOKey] = true

        // Add wallet UTXOs until we have enough
        for _, utxo := range unspent {
            if additionalFunds >= totalNeeded-prevAmount+1000 { // +buffer
                break
            }

            txid, ok := utxo["txid"].(string)
            voutF, vok := utxo["vout"].(float64)
            amountF, aok := utxo["amount"].(float64)
            if !ok || !vok || !aok {
                continue
            }

            vout := int(voutF)
            amount := int64(amountF * 1e8)

            utxoKey := txid + ":" + strconv.Itoa(vout)
            if usedUTXOs[utxoKey] {
                continue
            }

            inputHash, err := chainhash.NewHashFromStr(txid)
            if err != nil {
                continue
            }
            inputOutpoint := wire.NewOutPoint(inputHash, uint32(vout))
            input := wire.NewTxIn(inputOutpoint, nil, nil)
            tx.AddTxIn(input)

            additionalFunds += amount
            usedUTXOs[utxoKey] = true
            fmt.Printf("📥 Added input: %s:%d (%d sats)\n", txid[:8], vout, amount)
        }

        if additionalFunds < totalNeeded-prevAmount {
            return nil, fmt.Errorf("insufficient funds: need %d more, found %d", totalNeeded-prevAmount, additionalFunds)
        }

        // Add recipient token output
        recipientAddr, err := btcutil.DecodeAddress(recipientTokenAddr, Network)
        if err != nil {
            return nil, fmt.Errorf("invalid recipient token address: %w", err)
        }
        recipientScript, err := txscript.PayToAddrScript(recipientAddr)
        if err != nil {
            return nil, fmt.Errorf("failed to create recipient script: %w", err)
        }
        tx.AddTxOut(wire.NewTxOut(dustAmount, recipientScript))

        // Add change token output if needed
        if changeAmount > 0 {
            changeAddr, err := btcutil.DecodeAddress(changeTokenAddr, Network)
            if err != nil {
                return nil, fmt.Errorf("invalid change token address: %w", err)
            }
            changeScript, err := txscript.PayToAddrScript(changeAddr)
            if err != nil {
                return nil, fmt.Errorf("failed to create change script: %w", err)
            }
            tx.AddTxOut(wire.NewTxOut(dustAmount, changeScript))
        }

        // Add Bitcoin change output
        totalInput := prevAmount + additionalFunds
        feeEstimate := int64(len(tx.TxIn)*150 + len(tx.TxOut)*50 + 100)
        bitcoinChange := totalInput - outputsNeeded - feeEstimate

        if bitcoinChange > 10000 {
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
            tx.AddTxOut(wire.NewTxOut(bitcoinChange, changeScript))
            fmt.Printf("📤 Bitcoin change: %d sats\n", bitcoinChange)
        }

        // ✅ CRITICAL: Do NOT set token witness yet - let wallet sign first
        
        // Sign transaction with wallet (for additional inputs only)
        var buf bytes.Buffer
        tx.Serialize(&buf)
        txHex := hex.EncodeToString(buf.Bytes())

        fmt.Println("🔐 Signing wallet inputs...")
        signedTxJSON, err := RunBitcoinCommand(fmt.Sprintf("signrawtransactionwithwallet %s", txHex))
        if err != nil {
            return nil, fmt.Errorf("failed to sign transaction: %w", err)
        }

        var signed struct {
            Hex      string `json:"hex"`
            Complete bool   `json:"complete"`
        }
        if err := json.Unmarshal([]byte(signedTxJSON), &signed); err != nil {
            return nil, fmt.Errorf("failed to parse signed tx: %w", err)
        }

        // Note: Complete will be false because wallet can't sign the token input
        fmt.Printf("🔍 Wallet signing complete: %v\n", signed.Complete)

        signedBytes, err := hex.DecodeString(signed.Hex)
        if err != nil {
            return nil, fmt.Errorf("failed to decode signed tx: %w", err)
        }

        err = tx.Deserialize(bytes.NewReader(signedBytes))
        if err != nil {
            return nil, fmt.Errorf("failed to deserialize signed tx: %w", err)
        }

        // ✅ NOW set the token witness for the first input
        fmt.Println("🔐 Adding token witness to first input...")
        tx.TxIn[0].Witness = wire.TxWitness{
            t.ScriptTree.Script,
            t.ScriptTree.ControlBlock,
        }

        fmt.Printf("✅ Multi-input transaction created with %d inputs\n", len(tx.TxIn))

    } else {
        // Simple single-input transaction
        fmt.Println("🔄 Creating simple funding transaction...")

        prevHash, err := chainhash.NewHashFromStr(prevTxID)
        if err != nil {
            return nil, err
        }

        outpoint := wire.NewOutPoint(prevHash, prevTxIndex)
        txIn := wire.NewTxIn(outpoint, nil, nil)

        tx = wire.NewMsgTx(2)
        tx.AddTxIn(txIn)

        // Add recipient token output
        recipientAddr, err := btcutil.DecodeAddress(recipientTokenAddr, Network)
        if err != nil {
            return nil, fmt.Errorf("invalid recipient token address: %w", err)
        }
        recipientScript, err := txscript.PayToAddrScript(recipientAddr)
        if err != nil {
            return nil, fmt.Errorf("failed to create recipient script: %w", err)
        }
        tx.AddTxOut(wire.NewTxOut(dustAmount, recipientScript))

        // Add change token output if needed
        if changeAmount > 0 {
            changeAddr, err := btcutil.DecodeAddress(changeTokenAddr, Network)
            if err != nil {
                return nil, fmt.Errorf("invalid change token address: %w", err)
            }
            changeScript, err := txscript.PayToAddrScript(changeAddr)
            if err != nil {
                return nil, fmt.Errorf("failed to create change script: %w", err)
            }
            tx.AddTxOut(wire.NewTxOut(dustAmount, changeScript))
        }

        // Set token witness
        tx.TxIn[0].Witness = wire.TxWitness{
            t.ScriptTree.Script,
            t.ScriptTree.ControlBlock,
        }
    }

    // 4. BROADCAST FUNDING TRANSACTION
    var buf bytes.Buffer
    tx.Serialize(&buf)
    txHex := hex.EncodeToString(buf.Bytes())

    fmt.Println("📤 Broadcasting funding transaction...")
    fundingTxID, err := RunBitcoinCommand(fmt.Sprintf("sendrawtransaction %s", txHex))
    if err != nil {
        return nil, fmt.Errorf("failed to broadcast funding transaction: %w", err)
    }

    fmt.Printf("✅ Funding transaction: %s\n", fundingTxID)

    // Mine a block to confirm
    newAddress, err := RunBitcoinCommand("getnewaddress")
    if err != nil {
        return nil, err
    }
    _, err = RunBitcoinCommand(fmt.Sprintf("generatetoaddress 1 %s", newAddress))
    if err != nil {
        return nil, err
    }

    // 5. REVEAL RECIPIENT TOKEN
    fmt.Println("🔄 Revealing recipient token...")
    err = recipientToken.SavePrivateKey("temp_recipient_key.hex")
    if err != nil {
        return nil, fmt.Errorf("failed to save recipient key: %w", err)
    }

    recipientRevealTx, err := recipientToken.CreateScriptPathSpendingTx(
        fundingTxID, 0, dustAmount, recipientAddress, 2000,
    )
    if err != nil {
        return nil, fmt.Errorf("failed to create recipient reveal tx: %w", err)
    }

    var recipientBuf bytes.Buffer
    recipientRevealTx.Serialize(&recipientBuf)
    recipientRevealHex := hex.EncodeToString(recipientBuf.Bytes())

    recipientRevealTxID, err := RunBitcoinCommand(fmt.Sprintf("sendrawtransaction %s", recipientRevealHex))
    if err != nil {
        return nil, fmt.Errorf("failed to broadcast recipient reveal: %w", err)
    }
    fmt.Printf("✅ Recipient token revealed: %s\n", recipientRevealTxID)

    // 6. REVEAL CHANGE TOKEN (if needed)
    if changeAmount > 0 {
        fmt.Println("🔄 Revealing change token...")
        err = changeToken.SavePrivateKey("temp_change_key.hex")
        if err != nil {
            return nil, fmt.Errorf("failed to save change key: %w", err)
        }

        myChangeAddress, err := RunBitcoinCommand("getnewaddress \"TSBToken-Change\" \"bech32m\"")
        if err != nil {
            return nil, fmt.Errorf("failed to get change address: %w", err)
        }

        changeRevealTx, err := changeToken.CreateScriptPathSpendingTx(
            fundingTxID, 1, dustAmount, myChangeAddress, 2000,
        )
        if err != nil {
            return nil, fmt.Errorf("failed to create change reveal tx: %w", err)
        }

        var changeBuf bytes.Buffer
        changeRevealTx.Serialize(&changeBuf)
        changeRevealHex := hex.EncodeToString(changeBuf.Bytes())

        changeRevealTxID, err := RunBitcoinCommand(fmt.Sprintf("sendrawtransaction %s", changeRevealHex))
        if err != nil {
            return nil, fmt.Errorf("failed to broadcast change reveal: %w", err)
        }

        fmt.Printf("✅ Change token revealed: %s\n", changeRevealTxID)
    }

    // Mine final block
    _, err = RunBitcoinCommand(fmt.Sprintf("generatetoaddress 1 %s", newAddress))
    if err != nil {
        return nil, err
    }

    // Clean up temporary files
    os.Remove("temp_recipient_key.hex")
    os.Remove("temp_change_key.hex")

    fmt.Println("\n✅ Token split complete!")
    fmt.Printf("  Recipient will see: %d tokens in their wallet\n", transferAmount)
    if changeAmount > 0 {
        fmt.Printf("  You will see: %d tokens in your wallet\n", changeAmount)
    }
    fmt.Println("  Both tokens are now detectable by standard wallet scanning!")

    return tx, nil
}









// DirectUTXOTransferToken - Complete rewrite for descriptor wallets
func DirectUTXOTransferToken(tokenUTXO *FundingData, tokenData *TokenData,
    transferAmount uint64, recipientAddress string, feeRate int64) (string, *FundingData, error) {
    
    fmt.Println("🔧 Creating new token for recipient (descriptor wallet compatible)...")
    
// Create a new token for the recipient  
recipientToken, err := NewTaprootToken()
    if err != nil {
        return "", nil, fmt.Errorf("failed to create recipient token: %w", err)
    }

    // Create token data for the transfer amount
    transferTokenData := &TokenData{
        TokenID:   tokenData.TokenID,
        Amount:    transferAmount,
        TypeCode:  tokenData.TypeCode,
        Metadata:  tokenData.Metadata,
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

    fmt.Printf("✅ Created new token address: %s\n", recipientTokenAddr)

    // Fund the new token address
    const tokenFunding = 0.00001 // 1000 sats
    fmt.Printf("🔄 Funding token address with %.8f BTC...\n", tokenFunding)
    
    fundTxid, err := RunBitcoinCommand(fmt.Sprintf("sendtoaddress %s %.8f", recipientTokenAddr, tokenFunding))
    if err != nil {
        return "", nil, fmt.Errorf("failed to fund token address: %w", err)
    }

    // Mine a block to confirm
    newAddress, err := RunBitcoinCommand("getnewaddress")
    if err != nil {
        return "", nil, err
    }
    _, err = RunBitcoinCommand(fmt.Sprintf("generatetoaddress 1 %s", newAddress))
    if err != nil {
        return "", nil, err
    }

    fmt.Printf("✅ Token funded: %s\n", fundTxid)

    // Spend the token to the recipient's address (this reveals the token data)
    fmt.Println("🔄 Revealing token to recipient...")
    
    spendTx, err := recipientToken.CreateScriptPathSpendingTx(
        fundTxid, 0, 1000, recipientAddress, 2000,
    )
    if err != nil {
        return "", nil, fmt.Errorf("failed to create spend tx: %w", err)
    }

    var buf bytes.Buffer
    spendTx.Serialize(&buf)
    txHex := hex.EncodeToString(buf.Bytes())

    finalTxid, err := RunBitcoinCommand(fmt.Sprintf("sendrawtransaction %s", txHex))
    if err != nil {
        return "", nil, fmt.Errorf("failed to broadcast spend tx: %w", err)
    }

    // Mine another block
    _, err = RunBitcoinCommand(fmt.Sprintf("generatetoaddress 1 %s", newAddress))
    if err != nil {
        return "", nil, err
    }

    // Save the recipient's token key
// No hex key file needed - recipient uses their own wallet keys!
fmt.Println("✅ Recipient will use their own wallet keys - no hex file needed!")
fmt.Println("📧 The recipient can now manage tokens using their wallet directly")

    // Create recipient funding data
    recipientFunding := &FundingData{
        TxID:    finalTxid,
        Vout:    0,
        Value:   300, // Approximate value after fees
        Address: recipientAddress,
    }

    fmt.Printf("✅ Token transfer completed!\n")
    fmt.Printf("   Final transaction: %s\n", finalTxid)
    fmt.Printf("   Recipient can scan this transaction to see their %d %s tokens\n", transferAmount, tokenData.TokenID)
    fmt.Println("   The token data is embedded in the transaction witness")

    return finalTxid, recipientFunding, nil
}


func (t *TaprootToken) SavePrivateKey(filename string) error {
	privKeyHex := hex.EncodeToString(t.PrivateKey.Serialize())
	return os.WriteFile(filename, []byte(privKeyHex), 0600)
}





func ExtractTokenDataFromWitness(witness wire.TxWitness) (*TokenData, error) {
    if len(witness) < 1 {
        return nil, errors.New("witness stack too small")
    }

    script := witness[0]
    reader := bytes.NewReader(script)

    // 1. Marker
    markerLen, err := reader.ReadByte()
    if err != nil {
        return nil, err
    }
    if markerLen != 3 {
        return nil, fmt.Errorf("invalid marker length: %d", markerLen)
    }
    marker := make([]byte, 3)
    if _, err := reader.Read(marker); err != nil {
        return nil, err
    }
    if string(marker) != "TSB" {
        return nil, fmt.Errorf("invalid marker: %s", string(marker))
    }

    // 2. TokenID
    tokenIDLen, err := reader.ReadByte()
    if err != nil {
        return nil, err
    }
    if tokenIDLen != 16 {
        return nil, fmt.Errorf("invalid tokenID length: %d", tokenIDLen)
    }
    tokenID := make([]byte, 16)
    if _, err := reader.Read(tokenID); err != nil {
        return nil, err
    }

    // 3. Amount
    amountLen, err := reader.ReadByte()
    if err != nil {
        return nil, err
    }
    if amountLen != 8 {
        return nil, fmt.Errorf("invalid amount length: %d", amountLen)
    }
    amountBytes := make([]byte, 8)
    if _, err := reader.Read(amountBytes); err != nil {
        return nil, err
    }
    amount := binary.BigEndian.Uint64(amountBytes)

    // 4. Metadata
    metadataLen, err := reader.ReadByte()
    if err != nil {
        return nil, err
    }
    metadata := make([]byte, metadataLen)
    if _, err := reader.Read(metadata); err != nil {
        return nil, err
    }

    // Skip 4x OP_DROP
    for i := 0; i < 4; i++ {
        op, err := reader.ReadByte()
        if err != nil {
            return nil, err
        }
        if op != txscript.OP_DROP {
            return nil, fmt.Errorf("expected OP_DROP, got 0x%x", op)
        }
    }

    return &TokenData{
        TokenID:  string(tokenID),
        Amount:   amount,
        Metadata: string(metadata),
    }, nil
}


// RevealTokenDataFromHex parses a script-path spend and returns only the embedded fields,
// leaving TokenID exactly as the original name (no ":TXID" suffix).
func (t *TaprootToken) RevealTokenDataFromHex(rawTxHex string) (*TokenData, error) {
    // 1) Decode the hex into bytes
    txBytes, err := hex.DecodeString(strings.TrimSpace(rawTxHex))
    if err != nil {
        return nil, fmt.Errorf("failed to decode hex: %w", err)
    }

    // 2) Deserialize the transaction
    var tx wire.MsgTx
    if err := tx.Deserialize(bytes.NewReader(txBytes)); err != nil {
        return nil, fmt.Errorf("failed to deserialize transaction: %w", err)
    }

    // 3) Ensure there is at least one input with a witness
    if len(tx.TxIn) == 0 {
        return nil, fmt.Errorf("transaction has no inputs")
    }
    witness := tx.TxIn[0].Witness
    if len(witness) < 2 {
        return nil, fmt.Errorf("witness stack too short")
    }

    // 4) Extract the script (second-to-last element)
    scriptBytes := witness[len(witness)-2]

    // 5) Disassemble the script so we can parse pushes
    asm, err := txscript.DisasmString(scriptBytes)
    if err != nil {
        return nil, fmt.Errorf("failed to disassemble script: %w", err)
    }
    parts := strings.Split(asm, " ")
    if len(parts) < 16 {
        return nil, fmt.Errorf("script too short: %d parts", len(parts))
    }

    // 6) Parse fields in order:

    // a) OP_TRUE, OP_IF
    if parts[0] != "1" {
        return nil, fmt.Errorf("expected OP_TRUE, got %s", parts[0])
    }
    if parts[1] != "OP_IF" {
        return nil, fmt.Errorf("expected OP_IF, got %s", parts[1])
    }

    // b) Marker "TSB"
    marker, err := hex.DecodeString(parts[2])
    if err != nil || string(marker) != "TSB" {
        return nil, fmt.Errorf("invalid marker: %x", marker)
    }

    // c) TokenID (hex, then trim padding)
    rawID, err := hex.DecodeString(parts[3])
    if err != nil {
        return nil, fmt.Errorf("invalid tokenID: %w", err)
    }
    tokenID := strings.TrimRight(string(rawID), "\x00")

    // d) Amount (8-byte big endian)
    amtBytes, err := hex.DecodeString(parts[4])
    if err != nil {
        return nil, fmt.Errorf("invalid amount: %w", err)
    }
    amount := binary.BigEndian.Uint64(amtBytes)

    // e) TypeCode
    tc, err := strconv.ParseUint(parts[5], 10, 8)
    if err != nil {
        return nil, fmt.Errorf("invalid type code: %w", err)
    }
    typeCode := byte(tc)

    // f) Skip 4 × OP_DROP (parts[6] through parts[9])

    // g) Metadata
    metaBytes, err := hex.DecodeString(parts[10])
    if err != nil {
        return nil, fmt.Errorf("invalid metadata: %w", err)
    }
    metadata := string(metaBytes)

    // h) Timestamp (8-byte big endian)
    tsBytes, err := hex.DecodeString(parts[11])
    if err != nil {
        return nil, fmt.Errorf("invalid timestamp: %w", err)
    }
    timestamp := binary.BigEndian.Uint64(tsBytes)

    // Return only the raw fields—no suffix, no TXID appended.
    return &TokenData{
        TokenID:   tokenID,
        Amount:    amount,
        TypeCode:  typeCode,
        Metadata:  metadata,
        Timestamp: timestamp,
    }, nil
}



func (t *TaprootToken) CreateTaprootOutputWithOwnership(
	token *TokenData,
	recipientPubKey *btcec.PublicKey,
) (*TaprootScriptTree, error) {
	builder := txscript.NewScriptBuilder()

	// TSB-P Pattern Start
	builder.AddOp(txscript.OP_TRUE)
	builder.AddOp(txscript.OP_IF)

	builder.AddData([]byte("TSB"))                            // Marker
	builder.AddData([]byte(token.TokenID))                    // TokenID
	amountBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(amountBytes, token.Amount)
	builder.AddData(amountBytes)                              // Amount
	builder.AddData([]byte{token.TypeCode})                   // TypeCode

	builder.AddOp(txscript.OP_DROP)
	builder.AddOp(txscript.OP_DROP)
	builder.AddOp(txscript.OP_DROP)
	builder.AddOp(txscript.OP_DROP)

	builder.AddData([]byte(token.Metadata))                   // Metadata
	timestampBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(timestampBytes, token.Timestamp)
	builder.AddData(timestampBytes)                           // Timestamp

	builder.AddOp(txscript.OP_DROP)
	builder.AddOp(txscript.OP_DROP)

	// 👇 Ownership: require CHECKSIG for recipient pubkey
	builder.AddData(recipientPubKey.SerializeCompressed())    // pubkey
	builder.AddOp(txscript.OP_CHECKSIG)

	builder.AddOp(txscript.OP_ENDIF)

	// Compile script
	script, err := builder.Script()
	if err != nil {
		return nil, err
	}

	// Taproot leaf + control block
	var sizeBuf [binary.MaxVarintLen64]byte
	sz := binary.PutUvarint(sizeBuf[:], uint64(len(script)))
	leafInput := make([]byte, 1+sz+len(script))
	leafInput[0] = TapscriptLeafVersion
	copy(leafInput[1:], sizeBuf[:sz])
	copy(leafInput[1+sz:], script)

	leafHash := TaggedHash(TapscriptLeafTaggedHash, leafInput)
	merkleRoot := leafHash
	tweakedPubKey := txscript.ComputeTaprootOutputKey(t.PublicKey, merkleRoot)

	internalX := t.PublicKey.SerializeCompressed()[1:33]
	comp := tweakedPubKey.SerializeCompressed()
	parity := byte(0)
	if comp[0] == 0x03 {
		parity = 1
	}
	cb0 := TapscriptLeafVersion | parity
	controlBlock := append([]byte{cb0}, internalX...)

	tree := &TaprootScriptTree{
		Script:        script,
		LeafHash:      leafHash,
		MerkleRoot:    merkleRoot,
		TweakedPubKey: tweakedPubKey,
		ControlBlock:  controlBlock,
	}

	t.ScriptTree = tree
	return tree, nil
}


// BIP32 derivation path constants
const (
    // Base derivation paths (m/86' is Taproot path from BIP-86)
    TokenPathMainnet = "m/86'/0'/0'"  // For mainnet
    TokenPathTestnet = "m/86'/1'/0'"  // For testnet
    
    // We'll use account 0 and change 0 by default
    TokenDefaultAccount = 0
    TokenDefaultChange = 0
)

// GetTokenDerivationPath returns a deterministic path for a token
func GetTokenDerivationPath(tokenID string, isTestnet bool) string {
    // Create a deterministic index based on token ID
    tokenHashBytes := sha256.Sum256([]byte(tokenID))
    
    // Use the first 4 bytes of the hash as our child index
    // We mask the most significant bit to ensure it's a non-hardened index
    childIndex := binary.BigEndian.Uint32(tokenHashBytes[:4]) & 0x7FFFFFFF
    
    // Select the appropriate base path based on network
    basePath := TokenPathMainnet
    if isTestnet {
        basePath = TokenPathTestnet
    }
    
    // Construct full derivation path:
    // m/86'/0'/0'/0/childIndex (mainnet)
    // m/86'/1'/0'/0/childIndex (testnet)
    return fmt.Sprintf("%s/%d/%d", basePath, TokenDefaultChange, childIndex)
}

// DeriveTokenKeyFromWallet uses Bitcoin Core's built-in wallet to create deterministic keys
func DeriveTokenKeyFromWallet(tokenID string) (*TaprootToken, string, error) {
    // Get derivation path for this token
    path := GetTokenDerivationPath(tokenID, Network == &chaincfg.TestNet3Params)
    
    // Create a descriptive label that includes the path and token ID for future recovery
    addressLabel := fmt.Sprintf("Token:%s:Path:%s", tokenID, path)
    
    // Get a new address from the wallet
    fmt.Println("🔍 DEBUG: Getting new address from wallet...")
    addrOutput, err := RunBitcoinCommand(fmt.Sprintf("getnewaddress \"%s\" \"bech32m\"", addressLabel))
    if err != nil {
        return nil, "", fmt.Errorf("failed to get new address: %w", err)
    }
    fmt.Println("✅ Got address:", addrOutput)
    
    // Get the pubkey for this address
    fmt.Println("🔍 DEBUG: Getting address info...")
    addrInfoOutput, err := RunBitcoinCommand(fmt.Sprintf("getaddressinfo %s", addrOutput))
    if err != nil {
        return nil, "", fmt.Errorf("failed to get address info: %w", err)
    }
    
    // Print the address info for debugging
    fmt.Println("🔍 DEBUG: Address info:", addrInfoOutput)
    
    var addrInfo map[string]interface{}
    if err := json.Unmarshal([]byte(addrInfoOutput), &addrInfo); err != nil {
        return nil, "", fmt.Errorf("failed to parse address info: %w", err)
    }
    
    // Try to get pubkey from either pubkey or "embedded" section
    var pubkeyHex string
    var ok bool
    if pubkeyHex, ok = addrInfo["pubkey"].(string); !ok {
        // For Taproot addresses, the pubkey might be in the embedded section
        embedded, ok := addrInfo["embedded"].(map[string]interface{})
        if ok {
            pubkeyHex, ok = embedded["inner_pubkey"].(string)
            if !ok {
                fmt.Println("🔍 DEBUG: Address info keys:", addrInfo)
                return nil, "", fmt.Errorf("no pubkey found in address info or embedded section")
            }
        } else {
            // Direct fallback to using a new key instead
            fmt.Println("🔍 DEBUG: No embedded info, generating new key")
            token, err := NewTaprootToken()
            if err != nil {
                return nil, "", fmt.Errorf("failed to create new token: %w", err)
            }
            return token, addrOutput, nil
        }
    }
    
    // Parse the pubkey
    pubkeyBytes, err := hex.DecodeString(pubkeyHex)
    if err != nil {
        return nil, "", fmt.Errorf("invalid pubkey hex: %w", err)
    }
    
    pubkey, err := btcec.ParsePubKey(pubkeyBytes)
    if err != nil {
        return nil, "", fmt.Errorf("failed to parse pubkey: %w", err)
    }
    
    // Create a TaprootToken with the pubkey
    token := &TaprootToken{
        PublicKey: pubkey,
    }
    
    // Also try to get the private key - this may fail if wallet is locked
    privKeyWIF, err := RunBitcoinCommand(fmt.Sprintf("dumpprivkey %s", addrOutput))
    if err == nil {
        // If we got the private key, let's use it
        wif, err := btcutil.DecodeWIF(privKeyWIF)
        if err == nil {
            privKey, _ := btcec.PrivKeyFromBytes(wif.PrivKey.Serialize())
            token.PrivateKey = privKey
        }
    }
    
    // Store the path for tracking
    setLabelCmd := fmt.Sprintf("setlabel %s \"TokenPath:%s:%s\"", addrOutput, path, tokenID)
    _, _ = RunBitcoinCommand(setLabelCmd)
    
    return token, addrOutput, nil
}

// DeriveTokenKeyDeterministicDescriptor - Works with descriptor wallets
func DeriveTokenKeyDeterministicDescriptor(tokenID string, utxoRef string) (*TaprootToken, string, error) {
    fmt.Printf("🔑 Deriving deterministic key for token: %s (descriptor wallet mode)\n", tokenID)
    
    // Create a descriptive label for wallet tracking
    addressLabel := fmt.Sprintf("TokenDeterministic:%s:UTXO:%s", tokenID, utxoRef[:8])
    
    fmt.Printf("🔍 Address label: %s\n", addressLabel)
    
    // Get address from wallet using this deterministic label
    addrOutput, err := RunBitcoinCommand(fmt.Sprintf("getnewaddress \"%s\" \"bech32m\"", addressLabel))
    if err != nil {
        return nil, "", fmt.Errorf("failed to get deterministic address: %w", err)
    }
    
    // For descriptor wallets, we can't extract private keys easily
    // Instead, we'll create a token that relies on wallet signing
    // We'll get the public key from the address info
    addrInfoJSON, err := RunBitcoinCommand(fmt.Sprintf("getaddressinfo %s", addrOutput))
    if err != nil {
        return nil, "", fmt.Errorf("failed to get address info: %w", err)
    }
    
    var addrInfo map[string]interface{}
    if err := json.Unmarshal([]byte(addrInfoJSON), &addrInfo); err != nil {
        return nil, "", fmt.Errorf("failed to parse address info: %w", err)
    }
    
    // Try to get pubkey from address info
    var pubkeyHex string
    var ok bool
    if pubkeyHex, ok = addrInfo["pubkey"].(string); !ok {
        // For Taproot addresses, might be in embedded section
        if embedded, ok := addrInfo["embedded"].(map[string]interface{}); ok {
            if val, ok := embedded["inner_pubkey"].(string); ok {
                pubkeyHex = val
            }
        }
    }
    
    if pubkeyHex == "" {
        // Fallback: create a new random token for now
        fmt.Println("⚠️ Could not extract pubkey, creating new token (fallback mode)")
        token, err := NewTaprootToken()
        if err != nil {
            return nil, "", fmt.Errorf("failed to create fallback token: %w", err)
        }
        return token, addrOutput, nil
    }
    
    // Parse the pubkey
    pubkeyBytes, err := hex.DecodeString(pubkeyHex)
    if err != nil {
        return nil, "", fmt.Errorf("invalid pubkey hex: %w", err)
    }
    
    pubkey, err := btcec.ParsePubKey(pubkeyBytes)
    if err != nil {
        return nil, "", fmt.Errorf("failed to parse pubkey: %w", err)
    }
    
    // Create TaprootToken with public key only (wallet will sign when needed)
    token := &TaprootToken{
        PublicKey: pubkey,
        // PrivateKey: nil - wallet will handle signing
    }
    
    fmt.Printf("✅ Deterministic token key derived successfully (descriptor mode)\n")
    fmt.Printf("   Address: %s\n", addrOutput)
    fmt.Printf("   Public Key: %s\n", pubkeyHex)
    
    return token, addrOutput, nil
}

// DeriveTokenKeyDeterministic creates a deterministic token key from wallet
// Truly deterministic - returns same address for same inputs
func DeriveTokenKeyDeterministic(tokenID string, utxoRef string) (*TaprootToken, string, error) {
    fmt.Printf("🔑 Deriving deterministic key for token: %s\n", tokenID)
    
    // Create a descriptive label for wallet tracking  
    addressLabel := fmt.Sprintf("TokenDeterministic:%s:UTXO:%s", tokenID, utxoRef[:8])
    
    fmt.Printf("🔍 Address label: %s\n", addressLabel)
    
    // STEP 1: Check if we already have an address with this label
    existingAddr, err := findAddressByLabel(addressLabel)
    if err != nil {
        return nil, "", fmt.Errorf("failed to search for existing address: %w", err)
    }
    
    var addrOutput string
    if existingAddr != "" {
        // Found existing address with this label
        fmt.Printf("✅ Found existing deterministic address: %s\n", existingAddr)
        addrOutput = existingAddr
    } else {
        // Create new address with this label
        fmt.Printf("🆕 Creating new deterministic address...\n")
        addrOutput, err = RunBitcoinCommand(fmt.Sprintf("getnewaddress \"%s\" \"bech32m\"", addressLabel))
        if err != nil {
            return nil, "", fmt.Errorf("failed to get deterministic address: %w", err)
        }
        fmt.Printf("✅ Created new deterministic address: %s\n", addrOutput)
    }
    
// Try to get private key (works with legacy wallets)
privKeyWIF, err := RunBitcoinCommand(fmt.Sprintf("dumpprivkey %s", addrOutput))
if err != nil {
    // Descriptor wallet mode - get public key from address info
    fmt.Printf("⚠️ Descriptor wallet mode - extracting public key\n")
    
    addrInfoJSON, err := RunBitcoinCommand(fmt.Sprintf("getaddressinfo %s", addrOutput))
    if err != nil {
        return nil, "", fmt.Errorf("failed to get address info: %w", err)
    }
    
    var addrInfo map[string]interface{}
    if err := json.Unmarshal([]byte(addrInfoJSON), &addrInfo); err != nil {
        return nil, "", fmt.Errorf("failed to parse address info: %w", err)
    }
    
    // Extract public key - try multiple fields
    var pubkeyHex string
    if val, ok := addrInfo["pubkey"].(string); ok {
        pubkeyHex = val
    } else if embedded, ok := addrInfo["embedded"].(map[string]interface{}); ok {
        if val, ok := embedded["inner_pubkey"].(string); ok {
            pubkeyHex = val
        }
    }
    
    if pubkeyHex == "" {
        return nil, "", fmt.Errorf("could not extract public key from address info")
    }
    
    // Parse the public key
    pubkeyBytes, err := hex.DecodeString(pubkeyHex)
    if err != nil {
        return nil, "", fmt.Errorf("invalid pubkey hex: %w", err)
    }
    
    pubkey, err := btcec.ParsePubKey(pubkeyBytes)
    if err != nil {
        return nil, "", fmt.Errorf("failed to parse pubkey: %w", err)
    }
    
    token := &TaprootToken{
        PublicKey: pubkey,
        // PrivateKey: nil - wallet will handle signing
    }
    
    return token, addrOutput, nil
}
    
    // Legacy wallet mode - we have the private key
    wif, err := btcutil.DecodeWIF(privKeyWIF)
    if err != nil {
        return nil, "", fmt.Errorf("failed to decode WIF: %w", err)
    }
    
    privKey, _ := btcec.PrivKeyFromBytes(wif.PrivKey.Serialize())
    
    token := &TaprootToken{
        PrivateKey: privKey,
        PublicKey:  privKey.PubKey(),
    }
    
    fmt.Printf("✅ Deterministic token key derived successfully\n")
    
    return token, addrOutput, nil
}

// findAddressByLabel - Deterministic version that always returns same address
func findAddressByLabel(targetLabel string) (string, error) {
    // Try to get addresses with this label
    result, err := RunBitcoinCommand(fmt.Sprintf("getaddressesbylabel \"%s\"", targetLabel))
    if err != nil {
        // Label doesn't exist - that's ok, we'll create new
        return "", nil
    }
    
    // Parse the result - it's a JSON object with addresses as keys
    var addresses map[string]interface{}
    if err := json.Unmarshal([]byte(result), &addresses); err != nil {
        return "", fmt.Errorf("failed to parse addresses result: %w", err)
    }
    
    // Convert to slice and sort to make it deterministic
    var addrList []string
    for addr := range addresses {
        addrList = append(addrList, addr)
    }
    
    if len(addrList) == 0 {
        return "", nil
    }
    
    // Sort addresses to ensure deterministic order
    sort.Strings(addrList)
    
    // Always return the first address (lexicographically)
    return addrList[0], nil
}


// GetDeterministicTokenKey - wrapper function that was missing
func GetDeterministicTokenKey(tokenID string, txid string, vout uint32) (*TaprootToken, error) {
    utxoRef := fmt.Sprintf("%s:%d", txid, vout)
    token, _, err := DeriveTokenKeyDeterministic(tokenID, utxoRef)
    if err != nil {
        return nil, fmt.Errorf("failed to derive deterministic token key: %w", err)
    }
    return token, nil
}