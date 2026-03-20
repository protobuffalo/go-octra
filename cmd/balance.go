package cmd

import (
	"fmt"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/protobuffalo/go-octra/internal/tx"
)

var balanceCmd = &cobra.Command{
	Use:   "balance",
	Short: "Show wallet balance",
	Run: func(cmd *cobra.Command, args []string) {
		s := mustSession(cmd)
		defer s.Close()

		bi := tx.GetNonceBalance(s.RPC, s.Wallet)
		raw, _ := strconv.ParseInt(bi.BalanceRaw, 10, 64)
		whole := raw / 1000000
		frac := raw % 1000000

		fmt.Printf("Address:          %s\n", s.Wallet.Addr)
		fmt.Printf("Public balance:   %d.%06d OCT (%s raw)\n", whole, frac, bi.BalanceRaw)
		fmt.Printf("Nonce:            %d\n", bi.Nonce)

		// Encrypted balance
		_, decrypted := s.GetEncryptedBalance()
		if s.PvacForeign {
			fmt.Printf("Encrypted bal:    (key mismatch - use 'octra keyswitch')\n")
		} else if decrypted != 0 {
			eWhole := decrypted / 1000000
			eFrac := decrypted % 1000000
			if eFrac < 0 {
				eFrac = -eFrac
			}
			fmt.Printf("Encrypted bal:    %d.%06d OCT (%d raw)\n", eWhole, eFrac, decrypted)
		} else {
			fmt.Printf("Encrypted bal:    0\n")
		}
	},
}

func init() {
	balanceCmd.Flags().String("account", "", "Account address")
}
