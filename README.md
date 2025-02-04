# Bitcoin Transaction Demo

This project is a simple Bitcoin wallet implementation that allows users to create and send Bitcoin transactions on the Testnet. It demonstrates the use of Segregated Witness (SegWit) transactions and interacts with the Blockstream API for fetching UTXOs and broadcasting transactions.

To integrate with MPC, we need to replace the signature with the MPC signature.

## Features

- Generate a Bitcoin wallet from a mnemonic phrase.
- Create and sign Bitcoin transactions.
- Fetch UTXOs for a given address.
- Send transactions to the Bitcoin Testnet.

## Prerequisites

- Go 1.16 or later
- A basic understanding of Bitcoin and how transactions work.

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/yourusername/btc-demo-go.git
   cd btc-demo-go
   ```

2. Install the required Go modules:

   ```bash
   go mod tidy
   ```

## Usage

1. **Set up your mnemonic and receiver address** in the `main` function of `main.go`:

   ```go
   config := WalletConfig{
       mnemonic:        "your mnemonic here",
       receiverAddress: "tb1qyourreceiveraddresshere",
       amount:          100000, // Amount in satoshis
   }
   ```

2. **Run the application**:

   ```bash
   go run main.go helper.go
   ```

3. The application will create a transaction and send it to the Testnet. You will see logs indicating the transaction details.

## Functions

- **NewWallet(mnemonic string)**: Creates a new wallet from the provided mnemonic.
- **CreateTransaction(receiverAddress string, amount int64)**: Creates and signs a new Bitcoin transaction.
- **GetUTXOs(address string)**: Fetches all UTXOs for a given address.
- **SendTransactionPlain(txHex []byte)**: Sends the transaction as raw plain text to the network.

## Notes

- This project is intended for educational purposes and should not be used for real transactions without proper security measures.
- Make sure to use Testnet addresses and funds when testing.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [btcsuite/btcd](https://github.com/btcsuite/btcd) - A full node implementation of Bitcoin in Go.
- [Blockstream API](https://blockstream.info/) - Provides access to Bitcoin blockchain data and transaction broadcasting.
