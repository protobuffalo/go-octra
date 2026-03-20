package cmd

import (
	"fmt"
	"strconv"

	"github.com/spf13/cobra"

	octx "github.com/protobuffalo/go-octra/internal/tx"
)

var sendCmd = &cobra.Command{
	Use:   "send",
	Short: "Send OCT to an address",
	Run: func(cmd *cobra.Command, args []string) {
		s := mustSession(cmd)
		defer s.Close()

		to, _ := cmd.Flags().GetString("to")
		amountStr, _ := cmd.Flags().GetString("amount")
		message, _ := cmd.Flags().GetString("message")
		ou, _ := cmd.Flags().GetString("ou")

		if to == "" || len(to) != 47 || to[:3] != "oct" {
			fmt.Println("Error: invalid address (must be 47 chars starting with 'oct')")
			return
		}

		raw, err := octx.ParseAmountRaw(amountStr)
		if err != nil || raw <= 0 {
			fmt.Println("Error: invalid amount (max 6 decimals)")
			return
		}

		bi := octx.GetNonceBalance(s.RPC, s.Wallet)
		if ou == "" {
			if raw < 1000000000 {
				ou = "10000"
			} else {
				ou = "30000"
			}
		}

		tx := &octx.Transaction{
			From:      s.Wallet.Addr,
			To:        to,
			Amount:    strconv.FormatInt(raw, 10),
			Nonce:     bi.Nonce + 1,
			OU:        ou,
			Timestamp: octx.NowTS(),
			OpType:    "standard",
			Message:   message,
		}
		octx.SignTx(tx, s.Wallet.SK, s.Wallet.PubB64)
		txHash, err := octx.SubmitTx(s.RPC, tx)
		if err != nil {
			fmt.Printf("Error: %s\n", err)
			return
		}
		fmt.Printf("Transaction submitted: %s\n", txHash)
	},
}

func init() {
	sendCmd.Flags().String("to", "", "Recipient address")
	sendCmd.Flags().String("amount", "", "Amount to send (e.g., 1.5)")
	sendCmd.Flags().String("message", "", "Optional message")
	sendCmd.Flags().String("ou", "", "Operation units (gas)")
	sendCmd.Flags().String("account", "", "Account address")
	sendCmd.MarkFlagRequired("to")
	sendCmd.MarkFlagRequired("amount")
}
