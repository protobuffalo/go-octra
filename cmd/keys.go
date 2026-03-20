package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/protobuffalo/go-octra/internal/crypto"
	"github.com/protobuffalo/go-octra/internal/stealth"
)

var keysCmd = &cobra.Command{
	Use:   "keys",
	Short: "Key management commands",
}

var keysShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show public keys",
	Run: func(cmd *cobra.Command, args []string) {
		s := mustSession(cmd)
		defer s.Close()

		_, viewPK := stealth.DeriveViewKeypair(s.Wallet.SK[:])
		j, _ := json.MarshalIndent(map[string]interface{}{
			"address":         s.Wallet.Addr,
			"public_key":      s.Wallet.PubB64,
			"view_pubkey":     crypto.Base64Encode(viewPK[:]),
			"has_master_seed": s.Wallet.HasMasterSeed(),
		}, "", "  ")
		fmt.Println(string(j))
	},
}

var keysExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export private key and mnemonic (requires PIN verification)",
	Run: func(cmd *cobra.Command, args []string) {
		s := mustSession(cmd)
		defer s.Close()

		fmt.Printf("Private key: %s\n", s.Wallet.PrivB64)
		if s.Wallet.Mnemonic != "" {
			fmt.Printf("Mnemonic:    %s\n", s.Wallet.Mnemonic)
		}
	},
}

func init() {
	keysCmd.AddCommand(keysShowCmd)
	keysCmd.AddCommand(keysExportCmd)

	keysShowCmd.Flags().String("account", "", "Account address")
	keysExportCmd.Flags().String("account", "", "Account address")
}
