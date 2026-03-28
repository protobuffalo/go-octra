package cmd

import (
	"encoding/json"
	"flag"
	"fmt"

	"github.com/protobuffalo/go-octra/internal/config"
	"github.com/protobuffalo/go-octra/internal/session"
	"github.com/protobuffalo/go-octra/internal/wallet"
)

func dispatchConfig(args []string) {
	if len(args) == 0 {
		printConfigHelp()
		return
	}
	switch args[0] {
	case "show":
		runConfigShow()
	case "set":
		runConfigSet(args[1:])
	case "change-pin":
		runConfigChangePin(args[1:])
	case "help", "--help", "-h":
		printConfigHelp()
	default:
		fmt.Printf("Unknown config command: %s\n", args[0])
		printConfigHelp()
	}
}

func printConfigHelp() {
	fmt.Println("Configuration commands")
	fmt.Println()
	fmt.Println("Usage: octra config <subcommand> [flags]")
	fmt.Println()
	fmt.Println("Subcommands:")
	fmt.Println("  show        Show current configuration")
	fmt.Println("  set         Update settings (RPC URL, explorer URL, data dir)")
	fmt.Println("  change-pin  Change wallet PIN")
	fmt.Println()
	fmt.Println("Environment variables:")
	fmt.Println("  OCTRA_RPC_URL       Override RPC endpoint")
	fmt.Println("  OCTRA_EXPLORER_URL  Override explorer URL")
	fmt.Println("  OCTRA_DATA_DIR      Override data directory")
	fmt.Println("  OCTRA_PIN           Wallet PIN (for scripting)")
}

func runConfigShow() {
	c := config.Load()
	j, _ := json.MarshalIndent(map[string]string{
		"rpc_url":      c.RPCURL,
		"explorer_url": c.ExplorerURL,
		"data_dir":     c.DataDir,
	}, "", "  ")
	fmt.Println(string(j))
}

func runConfigSet(args []string) {
	fs := flag.NewFlagSet("config set", flag.ExitOnError)
	rpcURL := fs.String("rpc-url", "", "New RPC URL")
	explorerURL := fs.String("explorer-url", "", "New explorer URL")
	dataDir := fs.String("data-dir", "", "New data directory")
	account := fs.String("account", "", "Account address (also updates wallet-level RPC)")
	fs.Parse(args)

	if *rpcURL == "" && *explorerURL == "" && *dataDir == "" {
		fmt.Println("Error: at least one of --rpc-url, --explorer-url, --data-dir required")
		return
	}

	// Update global config file
	c := config.Load()
	if *rpcURL != "" {
		c.RPCURL = *rpcURL
	}
	if *explorerURL != "" {
		c.ExplorerURL = *explorerURL
	}
	if *dataDir != "" {
		c.DataDir = *dataDir
	}
	if err := c.Save(); err != nil {
		fmt.Printf("Error saving config: %s\n", err)
		return
	}

	fmt.Printf("RPC URL:      %s\n", c.RPCURL)
	fmt.Printf("Explorer URL: %s\n", c.ExplorerURL)
	fmt.Printf("Data dir:     %s\n", c.DataDir)

	// Also update wallet-level settings if a wallet is available
	if *rpcURL != "" || *explorerURL != "" {
		pin := readPin("Enter PIN to update wallet (or press enter to skip): ")
		if pin != "" && validatePin(pin) {
			var s *session.Session
			var err error
			if *account != "" {
				s, err = loadSessionForAddr(*account, pin)
			} else {
				s, err = loadSession(pin)
			}
			if err == nil {
				defer s.Close()
				oldRPC := s.Wallet.RPCURL
				if *rpcURL != "" {
					s.Wallet.RPCURL = *rpcURL
				}
				if *explorerURL != "" {
					s.Wallet.ExplorerURL = *explorerURL
				}
				if err := wallet.SaveWalletEncrypted(s.WalletPath, s.Wallet, s.Pin); err != nil {
					fmt.Printf("Error updating wallet: %s\n", err)
					return
				}
				fmt.Println("Wallet updated")
				if oldRPC != s.Wallet.RPCURL && s.Cache.IsOpen() {
					s.Cache.Clear()
					s.Cache.Put("meta:rpc_url", s.Wallet.RPCURL)
					fmt.Println("Transaction cache cleared (RPC changed)")
				}
			}
		}
	}
}

func runConfigChangePin(args []string) {
	fs := flag.NewFlagSet("config change-pin", flag.ExitOnError)
	account := fs.String("account", "", "Account address")
	fs.Parse(args)

	s := mustSession(*account)
	defer s.Close()

	newPin := readPin("Enter new PIN (6 digits): ")
	if !validatePin(newPin) {
		fmt.Println("Error: new PIN must be exactly 6 digits")
		return
	}
	confirmPin := readPin("Confirm new PIN: ")
	if newPin != confirmPin {
		fmt.Println("Error: PINs do not match")
		return
	}

	if err := wallet.SaveWalletEncrypted(s.WalletPath, s.Wallet, newPin); err != nil {
		fmt.Printf("Error: %s\n", err)
		return
	}
	fmt.Println("PIN changed successfully")
}
