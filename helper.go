package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"

	chaincfg "github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

const (
	HardenedOffset = 0x80000000 // 2^31 in hexadecimal
	API_URL        = "https://blockstream.info/testnet/api"
)

var CHAIN_CONFIG = chaincfg.TestNet3Params

// UTXO represents an unspent transaction output
type UTXO struct {
	OutPoint wire.OutPoint `json:"outpoint"`
	Value    int64         `json:"value"`
	PkScript []byte        `json:"pkscript"`
}

// auxUTXO is an auxiliary struct that matches the API response
type auxUTXO struct {
	TxID  string `json:"txid"`
	Vout  uint32 `json:"vout"`
	Value int64  `json:"value"`
}

// UTXOFetcher implements txscript.PrevOutputFetcher
type utxoFetcher struct {
	utxos []UTXO
}

// TxVout represents a transaction output from the Blockstream API
type TxVout struct {
	ScriptPubKey string `json:"scriptpubkey"`
	Value        int64  `json:"value"`
}

// TxInfo represents transaction details from the API
type TxInfo struct {
	Txid string   `json:"txid"`
	Vout []TxVout `json:"vout"`
}

// UnmarshalJSON customizes JSON unmarshaling for UTXO
func (u *UTXO) UnmarshalJSON(data []byte) error {
	var aux auxUTXO
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	hash, err := chainhash.NewHashFromStr(aux.TxID)
	if err != nil {
		return err
	}

	u.OutPoint = wire.OutPoint{
		Hash:  *hash,
		Index: aux.Vout,
	}
	u.Value = aux.Value
	return nil
}

// IsSegwitScript checks if a script is native segwit (P2WPKH or P2WSH)
func IsSegwitScript(script []byte) bool {
	log.Printf("Script: %x", script)

	switch {
	case len(script) == 22 && script[0] == 0x00 && script[1] == 0x14:
		return true // P2WPKH
	case len(script) == 34 && script[0] == 0x00 && script[1] == 0x20:
		return true // P2WSH
	default:
		return false
	}
}

// GetUTXOs fetches all UTXOs for an address
func GetUTXOs(address string) ([]UTXO, error) {
	resp, err := http.Get(fmt.Sprintf("%s/address/%s/utxo", API_URL, address))
	if err != nil {
		return nil, fmt.Errorf("failed to fetch UTXOs: %v", err)
	}
	defer resp.Body.Close()

	var utxos []UTXO
	if err := json.NewDecoder(resp.Body).Decode(&utxos); err != nil {
		return nil, fmt.Errorf("failed to decode UTXOs: %v", err)
	}

	// Update pkScript for each UTXO
	for i, utxo := range utxos {
		pkScript, err := GetScriptPubKey(utxo.OutPoint.Hash.String(), int(utxo.OutPoint.Index))
		if err != nil {
			return nil, err
		}
		utxos[i].PkScript = pkScript
	}

	return utxos, nil
}

// FetchPrevOutput implements txscript.PrevOutputFetcher interface
func (f utxoFetcher) FetchPrevOutput(outPoint wire.OutPoint) *wire.TxOut {
	for _, utxo := range f.utxos {
		if utxo.OutPoint == outPoint {
			return &wire.TxOut{
				Value:    utxo.Value,
				PkScript: utxo.PkScript,
			}
		}
	}
	return nil
}

// GetBalance calculates total balance from UTXOs
func GetBalance(address string) (int64, error) {
	utxos, err := GetUTXOs(address)
	if err != nil {
		return 0, err
	}

	var totalValue int64
	for _, utxo := range utxos {
		totalValue += utxo.Value
	}

	return totalValue, nil
}

// GetScriptPubKey fetches the scriptPubKey for a transaction output
func GetScriptPubKey(txid string, voutIndex int) ([]byte, error) {
	resp, err := http.Get(fmt.Sprintf("%s/tx/%s", API_URL, txid))
	if err != nil {
		return nil, fmt.Errorf("failed to fetch transaction info: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP error: %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}

	var tx TxInfo
	if err := json.Unmarshal(body, &tx); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %v", err)
	}

	if voutIndex < 0 || voutIndex >= len(tx.Vout) {
		return nil, errors.New("vout index out of range")
	}

	spkHex := tx.Vout[voutIndex].ScriptPubKey
	spk, err := hex.DecodeString(spkHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode script pub key hex: %v", err)
	}

	return spk, nil
}

// SendTransactionPlain sends the transaction as raw plain text.
func SendTransactionPlain(txHex []byte) {
	txHexStr := hex.EncodeToString(txHex)
	resp, err := http.Post(fmt.Sprintf("%s/tx", API_URL), "text/plain", bytes.NewBufferString(txHexStr))
	if err != nil {
		log.Fatalf("Error sending transaction: %v", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Failed to read response body: %v", err)
	}

	log.Printf("Transaction sent: %s, Response Body: %s", resp.Status, string(respBody))
}

// EstimateFee estimates the fee for a transaction
func EstimateFee(numInputs, numOutputs int, feeRate float64) int64 {
	baseSize := 10
	inputSize := 68 * numInputs
	outputSize := 31 * numOutputs
	vsize := baseSize + inputSize + outputSize
	return int64(float64(vsize)*feeRate) + 1
}

// GetFeeRate fetches the current fee rate from the Blockstream API
func GetFeeRate() (float64, error) {
	log.Println("Fetching fee rate", API_URL+"/fee-estimates")
	resp, err := http.Get(fmt.Sprintf("%s/fee-estimates", API_URL))
	if err != nil {
		return 0, fmt.Errorf("failed to fetch fee rate: %v", err)
	}
	defer resp.Body.Close()
	// Change the map value type to float64 because the API returns floating point values.
	var feeEstimates map[string]float64
	if err := json.NewDecoder(resp.Body).Decode(&feeEstimates); err != nil {
		return 0, fmt.Errorf("failed to decode fee estimates: %v", err)
	}

	// Retrieve the fee estimate for 1 block confirmation (i.e. the first estimate).
	firstFee, ok := feeEstimates["1"]
	if !ok {
		return 0, fmt.Errorf("fee estimate for key '1' not found")
	}
	log.Printf("Fee estimates: %v", firstFee)

	return firstFee, nil
}
