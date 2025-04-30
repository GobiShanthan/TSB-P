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

var Network = &chaincfg.RegressionNetParams

type TokenData struct {
	TokenID   string
	Amount    uint64
	TypeCode  byte
	Metadata  string
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
    if len(parts) < 16 {
        return nil, fmt.Errorf("script too short: %d parts", len(parts))
    }

    // 1. Expect OP_TRUE
    if parts[0] != "1" {
        return nil, fmt.Errorf("expected OP_TRUE, got: %s", parts[0])
    }

    // 2. Expect OP_IF
    if parts[1] != "OP_IF" {
        return nil, fmt.Errorf("expected OP_IF, got: %s", parts[1])
    }

    // 3. Verify marker
    markerBytes, err := hex.DecodeString(parts[2])
    if err != nil || string(markerBytes) != "TSB" {
        return nil, fmt.Errorf("invalid marker: %x", markerBytes)
    }

    // 4. Extract token ID
    tokenIDBytes, err := hex.DecodeString(parts[3])
    if err != nil {
        return nil, fmt.Errorf("invalid tokenID: %w", err)
    }
    tokenID := strings.TrimRight(string(tokenIDBytes), "\x00")

    // 5. Extract amount
    amountBytes, err := hex.DecodeString(parts[4])
    if err != nil {
        return nil, fmt.Errorf("invalid amount: %w", err)
    }
    amount := binary.BigEndian.Uint64(amountBytes)

    // 6. Extract type_code
    typeCodeInt, err := strconv.ParseUint(parts[5], 10, 8)
    if err != nil {
        return nil, fmt.Errorf("invalid type_code: %w", err)
    }
    typeCode := byte(typeCodeInt)

    // 7. Verify 4x OP_DROP
    if parts[6] != "OP_DROP" || parts[7] != "OP_DROP" || parts[8] != "OP_DROP" || parts[9] != "OP_DROP" {
        return nil, fmt.Errorf("expected 4x OP_DROP after header fields")
    }

    // 8. Extract metadata
    fmt.Println("🔍 DEBUG: Raw metadata part:", parts[10])

    metadataDecoded, err := hex.DecodeString(parts[10])
    if err != nil {
        return nil, fmt.Errorf("invalid metadata hex: %w", err)
    }
    metadata := string(metadataDecoded)

    // 9. Extract timestamp
    timestampBytes, err := hex.DecodeString(parts[11])
    if err != nil {
        return nil, fmt.Errorf("invalid timestamp: %w", err)
    }
    if len(timestampBytes) != 8 {
        return nil, fmt.Errorf("timestamp wrong length")
    }
    timestamp := binary.BigEndian.Uint64(timestampBytes)

    // 10. Verify 2x OP_DROP
    if parts[12] != "OP_DROP" || parts[13] != "OP_DROP" {
        return nil, fmt.Errorf("expected 2x OP_DROP after metadata/timestamp")
    }

    // 11. Programmable logic (1 or OP_TRUE)
    if parts[14] != "1" && parts[14] != "OP_TRUE" {
        return nil, fmt.Errorf("unexpected programmable logic: %s", parts[14])
    }

    return &TokenData{
        TokenID:   tokenID,
        Amount:    amount,
        TypeCode:  typeCode,
        Metadata:  metadata,
        Timestamp: timestamp,
    }, nil
}
