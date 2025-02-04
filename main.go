package main

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"sort"

	btcec "github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	bip32 "github.com/tyler-smith/go-bip32"
	bip39 "github.com/tyler-smith/go-bip39"
)

// WalletConfig holds wallet configuration parameters
type WalletConfig struct {
	mnemonic        string
	receiverAddress string
	amount          int64
}

// Wallet represents a Bitcoin wallet
type Wallet struct {
	privateKey []byte
	address    string
}

// NewWallet creates a new wallet from a mnemonic
func NewWallet(mnemonic string) (*Wallet, error) {
	if !bip39.IsMnemonicValid(mnemonic) {
		return nil, fmt.Errorf("invalid mnemonic: %s", mnemonic)
	}

	privateKey, address, err := deriveSegWitAddress(mnemonic)
	if err != nil {
		return nil, fmt.Errorf("error deriving SegWit address: %v", err)
	}

	return &Wallet{
		privateKey: privateKey,
		address:    address,
	}, nil
}

// deriveSegWitAddress derives a Native SegWit Address (BIP-84)
func deriveSegWitAddress(mnemonic string) ([]byte, string, error) {
	seed := bip39.NewSeed(mnemonic, "")

	masterKey, err := bip32.NewMasterKey(seed)
	if err != nil {
		return nil, "", err
	}

	// Derive the BIP-84 path: m/84'/0'/0'/0/0
	path := []uint32{
		HardenedOffset + 84, // Purpose
		HardenedOffset + 0,  // Coin (Bitcoin Mainnet)
		HardenedOffset + 0,  // Account 0
		0,                   // External chain
		0,                   // First address
	}

	key := masterKey
	for _, childIndex := range path {
		key, err = key.NewChildKey(childIndex)
		if err != nil {
			return nil, "", err
		}
	}

	privateKeyBytes := key.Key
	_, pubKey := btcec.PrivKeyFromBytes(privateKeyBytes)
	pubKeyHash := btcutil.Hash160(pubKey.SerializeCompressed())

	address, err := btcutil.NewAddressWitnessPubKeyHash(pubKeyHash, &CHAIN_CONFIG)
	if err != nil {
		return nil, "", err
	}

	return privateKeyBytes, address.String(), nil
}

// CreateTransaction creates and signs a new Bitcoin transaction
func (w *Wallet) CreateTransaction(receiverAddress string, amount int64) ([]byte, error) {
	tx := wire.NewMsgTx(wire.TxVersion)

	// Add output
	if err := addOutput(tx, receiverAddress, amount); err != nil {
		return nil, err
	}

	// Add inputs
	selectedUTXOs, totalValue, err := selectUTXOs(w.address, amount)
	if err != nil {
		return nil, err
	}

	if err := addInputs(tx, selectedUTXOs); err != nil {
		return nil, err
	}

	feeRate, err := GetFeeRate()
	if err != nil {
		return nil, err
	}
	fee := EstimateFee(len(selectedUTXOs), 2, feeRate)
	log.Printf("Fee: %d", fee)
	changeAmount := totalValue - amount - fee

	if changeAmount > 0 {
		if err := addOutput(tx, w.address, changeAmount); err != nil {
			return nil, err
		}
	} else {
		return nil, errors.New("no change to send")
	}

	// Sign transaction
	if err := signTransaction(tx, w.privateKey, selectedUTXOs); err != nil {
		return nil, err
	}

	// Serialize transaction
	var buf bytes.Buffer
	if err := tx.Serialize(&buf); err != nil {
		return nil, fmt.Errorf("failed to serialize transaction: %v", err)
	}

	return buf.Bytes(), nil
}

func addOutput(tx *wire.MsgTx, receiverAddress string, amount int64) error {
	addr, err := btcutil.DecodeAddress(receiverAddress, &CHAIN_CONFIG)
	if err != nil {
		return fmt.Errorf("failed to decode address: %v", err)
	}

	pkScript, err := txscript.PayToAddrScript(addr)
	if err != nil {
		return fmt.Errorf("failed to create pay-to-address script: %v", err)
	}

	tx.AddTxOut(wire.NewTxOut(amount, pkScript))
	return nil
}

func selectUTXOs(address string, amount int64) ([]UTXO, int64, error) {
	utxos, err := GetUTXOs(address)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get UTXOs: %v", err)
	}

	sort.Slice(utxos, func(i, j int) bool {
		return utxos[i].Value > utxos[j].Value
	})

	var selectedUTXOs []UTXO
	var totalValue int64
	for _, utxo := range utxos {
		selectedUTXOs = append(selectedUTXOs, utxo)
		totalValue += utxo.Value
		if totalValue >= amount {
			break
		}
	}

	return selectedUTXOs, totalValue, nil
}

func addInputs(tx *wire.MsgTx, utxos []UTXO) error {
	for _, utxo := range utxos {
		txIn := wire.NewTxIn(&utxo.OutPoint, nil, nil)
		if IsSegwitScript(utxo.PkScript) {
			txIn.SignatureScript = []byte{}
		}
		tx.AddTxIn(txIn)
	}
	return nil
}

// SignTransaction signs the transaction with the provided private key and UTXOs
func signTransaction(tx *wire.MsgTx, privateKeyBytes []byte, utxos []UTXO) error {
	privKey, _ := btcec.PrivKeyFromBytes(privateKeyBytes)
	fetcher := utxoFetcher{utxos: utxos}

	for i, txIn := range tx.TxIn {
		if IsSegwitScript(utxos[i].PkScript) {
			// For segwit inputs, compute the signature hash.
			hashes := txscript.NewTxSigHashes(tx, fetcher)
			// calcWitnessSigHash returns the hash for segwit signing.
			hash, err := txscript.CalcWitnessSigHash(utxos[i].PkScript, hashes, txscript.SigHashAll, tx, i, utxos[i].Value)
			if err != nil {
				return fmt.Errorf("failed to calculate segwit signature hash for input %d: %v", i, err)
			}
			// TODO: Replace with our MPC signature.
			rawSig := ecdsa.Sign(privKey, hash) // Capture r, s
			sig := append(rawSig.Serialize(), byte(txscript.SigHashAll))

			pk := privKey.PubKey()
			pkData := pk.SerializeCompressed()
			txIn.Witness = wire.TxWitness{
				sig,
				pkData,
			}
		} else {
			// TODO: No need to sign for P2PKH, can skip this.
			sig, err := txscript.SignatureScript(tx, i, utxos[i].PkScript, txscript.SigHashAll, privKey, true)
			if err != nil {
				return fmt.Errorf("failed to sign input %d: %v", i, err)
			}
			txIn.SignatureScript = sig
		}
	}
	return nil
}

func main() {
	config := WalletConfig{
		mnemonic:        "ritual about elephant exotic melt tool emotion onion brother need bike coral",
		receiverAddress: "tb1qh0du0lcxqnw2jw2yhjdhcdnzhlztsp96g66qjc",
		amount:          1200,
	}

	wallet, err := NewWallet(config.mnemonic)
	if err != nil {
		log.Fatalf("Failed to create wallet: %v", err)
	}

	log.Printf("Private Key: %x", wallet.privateKey)
	log.Printf("Derived Native SegWit Address: %s", wallet.address)

	tx, err := wallet.CreateTransaction(config.receiverAddress, config.amount)
	if err != nil {
		log.Fatalf("Failed to create transaction: %v", err)
	}

	log.Printf("Transaction created: %x", tx)
	SendTransactionPlain(tx)
}
