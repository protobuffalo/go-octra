package cmd

import (
	"encoding/json"
	"flag"
	"fmt"

	"github.com/protobuffalo/go-octra/internal/crypto"
	"github.com/protobuffalo/go-octra/internal/stealth"
)

func dispatchKeys(args []string) {
	if len(args) == 0 {
		printKeysHelp()
		return
	}
	switch args[0] {
	case "show":
		runKeysShow(args[1:])
	case "export":
		runKeysExport(args[1:])
	case "help", "--help", "-h":
		printKeysHelp()
	default:
		fmt.Printf("Unknown keys command: %s\n", args[0])
		printKeysHelp()
	}
}

func printKeysHelp() {
	fmt.Println("Key management commands")
	fmt.Println()
	fmt.Println("Usage: octra keys <subcommand> [flags]")
	fmt.Println()
	fmt.Println("Subcommands:")
	fmt.Println("  show    Show public keys")
	fmt.Println("  export  Export private key and mnemonic")
}

func runKeysShow(args []string) {
	fs := flag.NewFlagSet("keys show", flag.ExitOnError)
	account := fs.String("account", "", "Account address")
	fs.Parse(args)

	s := mustSession(*account)
	defer s.Close()

	_, viewPK := stealth.DeriveViewKeypair(s.Wallet.SK[:])
	j, _ := json.MarshalIndent(map[string]interface{}{
		"address":         s.Wallet.Addr,
		"public_key":      s.Wallet.PubB64,
		"view_pubkey":     crypto.Base64Encode(viewPK[:]),
		"has_master_seed": s.Wallet.HasMasterSeed(),
	}, "", "  ")
	fmt.Println(string(j))
}

func runKeysExport(args []string) {
	fs := flag.NewFlagSet("keys export", flag.ExitOnError)
	account := fs.String("account", "", "Account address")
	fs.Parse(args)

	s := mustSession(*account)
	defer s.Close()

	fmt.Printf("Private key: %s\n", s.Wallet.PrivB64)
	if s.Wallet.Mnemonic != "" {
		fmt.Printf("Mnemonic:    %s\n", s.Wallet.Mnemonic)
	}
}
