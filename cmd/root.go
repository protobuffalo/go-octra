package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/protobuffalo/go-octra/internal/session"
	"github.com/protobuffalo/go-octra/internal/wallet"
)

var rootCmd = &cobra.Command{
	Use:   "octra",
	Short: "Octra Wallet CLI",
	Long:  "Command-line wallet for the Octra blockchain network",
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.AddCommand(walletCmd)
	rootCmd.AddCommand(balanceCmd)
	rootCmd.AddCommand(historyCmd)
	rootCmd.AddCommand(feeCmd)
	rootCmd.AddCommand(sendCmd)
	rootCmd.AddCommand(txCmd)
	rootCmd.AddCommand(keysCmd)
	rootCmd.AddCommand(fheCmd)
	rootCmd.AddCommand(stealthCmd)
	rootCmd.AddCommand(contractCmd)
	rootCmd.AddCommand(tokenCmd)
	rootCmd.AddCommand(configCmd)
	rootCmd.AddCommand(keyswitchCmd)
}

func readPin(prompt string) string {
	if pin := os.Getenv("OCTRA_PIN"); pin != "" {
		return pin
	}
	fmt.Print(prompt)
	b, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func validatePin(pin string) bool {
	if len(pin) != 6 {
		return false
	}
	for _, c := range pin {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func loadSession(pin string) (*session.Session, error) {
	entries := wallet.LoadManifest()
	if len(entries) == 0 {
		// Try default wallet file
		if wallet.HasEncryptedWallet() {
			return session.Load(wallet.WalletFile, pin)
		}
		return nil, fmt.Errorf("no wallet found. Use 'octra wallet create' first")
	}
	// Use first entry by default
	return session.Load(entries[0].File, pin)
}

func loadSessionForAddr(addr, pin string) (*session.Session, error) {
	entries := wallet.LoadManifest()
	for _, e := range entries {
		if e.Addr == addr {
			return session.Load(e.File, pin)
		}
	}
	return nil, fmt.Errorf("account %s not found in manifest", addr)
}

func mustSession(cmd *cobra.Command) *session.Session {
	pin := readPin("Enter PIN: ")
	if !validatePin(pin) {
		fmt.Println("Error: PIN must be exactly 6 digits")
		os.Exit(1)
	}
	addr, _ := cmd.Flags().GetString("account")
	var s *session.Session
	var err error
	if addr != "" {
		s, err = loadSessionForAddr(addr, pin)
	} else {
		s, err = loadSession(pin)
	}
	if err != nil {
		fmt.Printf("Error: %s\n", err)
		os.Exit(1)
	}
	return s
}
