package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"os"
	"fmt"
    "strings"
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

var Network = &chaincfg.RegressionNetParams

type TokenData struct {
	TokenID  string
	Amount   uint64
	Metadata string
    Timestamp uint64 
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

// CreateTaprootOutput builds the leaf script, computes the BIP-341 tweak
func (t *TaprootToken) CreateTaprootOutput(token *TokenData) (*TaprootScriptTree, error) {
    builder := txscript.NewScriptBuilder()

    // Push "TSB" marker
    builder.AddData([]byte("TSB"))

    // Push token ID (must be 16 bytes padded)
    builder.AddData([]byte(token.TokenID))

    // Push amount (8 bytes, big endian)
    amountBytes := make([]byte, 8)
    binary.BigEndian.PutUint64(amountBytes, token.Amount)
    builder.AddData(amountBytes)

    // Push metadata
    builder.AddData([]byte(token.Metadata))

    // Push timestamp (8 bytes, big endian)
    timestampBytes := make([]byte, 8)
    binary.BigEndian.PutUint64(timestampBytes, token.Timestamp)
    builder.AddData(timestampBytes)

    // Drop all fields
    builder.AddOp(txscript.OP_DROP) // Timestamp
    builder.AddOp(txscript.OP_DROP) // Metadata
    builder.AddOp(txscript.OP_DROP) // Amount
    builder.AddOp(txscript.OP_DROP) // TokenID
    builder.AddOp(txscript.OP_DROP) // Marker

    // Final programmable logic
    builder.AddOp(txscript.OP_TRUE)

    // Finalize the script
    script, err := builder.Script()
    if err != nil {
        return nil, err
    }

    // Build TapLeaf
    var sizeBuf [binary.MaxVarintLen64]byte
    sz := binary.PutUvarint(sizeBuf[:], uint64(len(script)))
    leafInput := make([]byte, 1+sz+len(script))
    leafInput[0] = TapscriptLeafVersion
    copy(leafInput[1:], sizeBuf[:sz])
    copy(leafInput[1+sz:], script)

    leafHash := TaggedHash(TapscriptLeafTaggedHash, leafInput)
    merkleRoot := leafHash

    // Correct Taproot tweak (BIP-341)
    tweakedPubKey := txscript.ComputeTaprootOutputKey(t.PublicKey, merkleRoot)

    // Build control block
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
    if fee < 1000 {
        fee = 1000
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



func (t *TaprootToken) RevealTokenDataFromHex(rawTxHex string) (*TokenData, error) {
    txBytes, err := hex.DecodeString(strings.TrimSpace(rawTxHex))
    if err != nil {
        return nil, fmt.Errorf("failed to decode hex: %w", err)
    }
    var tx wire.MsgTx
    err = tx.Deserialize(bytes.NewReader(txBytes))
    if err != nil {
        return nil, fmt.Errorf("failed to deserialize transaction: %w", err)
    }

    if len(tx.TxIn) == 0 {
        return nil, fmt.Errorf("transaction has no inputs")
    }

    input := tx.TxIn[0]

    if len(input.Witness) < 2 {
        return nil, fmt.Errorf("witness stack too short")
    }

    fmt.Println("🔍 DEBUG: Full Witness Stack:")
    for idx, item := range input.Witness {
        fmt.Printf("  Item %d: %x (length: %d)\n", idx, item, len(item))
    }

    var scriptBytes []byte

    if len(input.Witness[len(input.Witness)-1]) == 33 {
        scriptBytes = input.Witness[len(input.Witness)-2]
    } else {
        return nil, fmt.Errorf("unexpected control block length: %d", len(input.Witness[len(input.Witness)-1]))
    }

    fmt.Printf("🔍 DEBUG: Using scriptBytes for Disasm: %x\n", scriptBytes)

    scriptAsm, err := txscript.DisasmString(scriptBytes)
    if err != nil {
        return nil, fmt.Errorf("failed to disassemble script: %w", err)
    }
    fmt.Println("🔍 DEBUG: Script Disassembly:")
    fmt.Println(scriptAsm)

    parts := strings.Split(scriptAsm, " ")
    if len(parts) < 11 {
        return nil, fmt.Errorf("script too short: %d parts", len(parts))
    }

    markerBytes, err := hex.DecodeString(parts[0])
    if err != nil || string(markerBytes) != "TSB" {
        return nil, fmt.Errorf("invalid marker: %x", markerBytes)
    }

    tokenIDBytes, err := hex.DecodeString(parts[1])
    if err != nil {
        return nil, fmt.Errorf("invalid tokenID: %w", err)
    }
    tokenID := strings.TrimRight(string(tokenIDBytes), "\x00")

    amountBytes, err := hex.DecodeString(parts[2])
    if err != nil {
        return nil, fmt.Errorf("invalid amount: %w", err)
    }
    amount := binary.BigEndian.Uint64(amountBytes)

    metadataBytes, err := hex.DecodeString(parts[3])
    if err != nil {
        return nil, fmt.Errorf("invalid metadata: %w", err)
    }
    metadata := string(metadataBytes)

    timestampBytes, err := hex.DecodeString(parts[4])
    if err != nil {
        return nil, fmt.Errorf("invalid timestamp: %w", err)
    }
    timestamp := binary.BigEndian.Uint64(timestampBytes)

    // 🛠 Fixed check for DROP DROP DROP DROP DROP TRUE/1
    if parts[5] != "OP_DROP" || parts[6] != "OP_DROP" || parts[7] != "OP_DROP" || parts[8] != "OP_DROP" || parts[9] != "OP_DROP" || (parts[10] != "1" && parts[10] != "OP_TRUE") {
        return nil, fmt.Errorf("unexpected script ending: %v", parts[5:])
    }
    

    return &TokenData{
        TokenID:   tokenID,
        Amount:    amount,
        Metadata:  metadata,
        Timestamp: timestamp,
    }, nil
}
