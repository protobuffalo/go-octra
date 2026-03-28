package cmd

import (
	"flag"
	"fmt"
	"strconv"

	octx "github.com/protobuffalo/go-octra/internal/tx"
)

func runSend(args []string) {
	fs := flag.NewFlagSet("send", flag.ExitOnError)
	to := fs.String("to", "", "Recipient address")
	amountStr := fs.String("amount", "", "Amount to send (e.g., 1.5)")
	message := fs.String("message", "", "Optional message")
	ou := fs.String("ou", "", "Operation units (gas)")
	account := fs.String("account", "", "Account address")
	fs.Parse(args)

	if *to == "" || *amountStr == "" {
		fmt.Println("Error: --to and --amount required")
		return
	}

	s := mustSession(*account)
	defer s.Close()

	if len(*to) != 47 || (*to)[:3] != "oct" {
		fmt.Println("Error: invalid address (must be 47 chars starting with 'oct')")
		return
	}

	raw, err := octx.ParseAmountRaw(*amountStr)
	if err != nil || raw <= 0 {
		fmt.Println("Error: invalid amount (max 6 decimals)")
		return
	}

	bi := octx.GetNonceBalance(s.RPC, s.Wallet)
	if *ou == "" {
		if raw < 1000000000 {
			*ou = "10000"
		} else {
			*ou = "30000"
		}
	}

	tx := &octx.Transaction{
		From:      s.Wallet.Addr,
		To:        *to,
		Amount:    strconv.FormatInt(raw, 10),
		Nonce:     bi.Nonce + 1,
		OU:        *ou,
		Timestamp: octx.NowTS(),
		OpType:    "standard",
		Message:   *message,
	}
	octx.SignTx(tx, s.Wallet.SK, s.Wallet.PubB64)
	txHash, err := octx.SubmitTx(s.RPC, tx)
	if err != nil {
		fmt.Printf("Error: %s\n", err)
		return
	}
	fmt.Printf("Transaction submitted: %s\n", txHash)
}
