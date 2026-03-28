package cmd

import (
	"flag"
	"fmt"

	"github.com/protobuffalo/go-octra/internal/tx"
)

func runBalance(args []string) {
	fs := flag.NewFlagSet("balance", flag.ExitOnError)
	account := fs.String("account", "", "Account address")
	fs.Parse(args)

	s := mustSession(*account)
	defer s.Close()

	bi := tx.GetNonceBalance(s.RPC, s.Wallet)
	raw := bi.BalanceRaw
	rawInt := int64(0)
	fmt.Sscanf(raw, "%d", &rawInt)
	whole := rawInt / 1000000
	frac := rawInt % 1000000

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
}
