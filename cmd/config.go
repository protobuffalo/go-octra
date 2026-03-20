package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/protobuffalo/go-octra/internal/wallet"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Configuration commands",
}

var configSetCmd = &cobra.Command{
	Use:   "set",
	Short: "Update wallet settings (RPC URL, explorer URL)",
	Run: func(cmd *cobra.Command, args []string) {
		s := mustSession(cmd)
		defer s.Close()

		rpcURL, _ := cmd.Flags().GetString("rpc-url")
		explorerURL, _ := cmd.Flags().GetString("explorer-url")

		if rpcURL == "" {
			fmt.Println("Error: --rpc-url required")
			return
		}

		oldRPC := s.Wallet.RPCURL
		s.Wallet.RPCURL = rpcURL
		if explorerURL != "" {
			s.Wallet.ExplorerURL = explorerURL
		}

		if err := wallet.SaveWalletEncrypted(s.WalletPath, s.Wallet, s.Pin); err != nil {
			fmt.Printf("Error: %s\n", err)
			return
		}

		fmt.Printf("RPC URL:      %s\n", s.Wallet.RPCURL)
		fmt.Printf("Explorer URL: %s\n", s.Wallet.ExplorerURL)

		if oldRPC != s.Wallet.RPCURL && s.Cache.IsOpen() {
			s.Cache.Clear()
			s.Cache.Put("meta:rpc_url", s.Wallet.RPCURL)
			fmt.Println("Transaction cache cleared (RPC changed)")
		}
	},
}

var configChangePinCmd = &cobra.Command{
	Use:   "change-pin",
	Short: "Change wallet PIN",
	Run: func(cmd *cobra.Command, args []string) {
		s := mustSession(cmd)
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
	},
}

func init() {
	configCmd.AddCommand(configSetCmd)
	configCmd.AddCommand(configChangePinCmd)

	configSetCmd.Flags().String("rpc-url", "", "New RPC URL")
	configSetCmd.Flags().String("explorer-url", "", "New explorer URL")
	configSetCmd.Flags().String("account", "", "Account address")

	configChangePinCmd.Flags().String("account", "", "Account address")
}
