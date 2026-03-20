package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/protobuffalo/go-octra/internal/crypto"
	"github.com/protobuffalo/go-octra/internal/rpc"
	"github.com/protobuffalo/go-octra/internal/wallet"
)

var walletCmd = &cobra.Command{
	Use:   "wallet",
	Short: "Wallet management commands",
}

var walletStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Check wallet status",
	Run: func(cmd *cobra.Command, args []string) {
		hasLeg := wallet.HasLegacyWallet()
		all := wallet.ScanAndMergeOctFiles()
		hasAnyOct := len(all) > 0

		fmt.Printf("Loaded: false (CLI mode - per-command unlock)\n")
		fmt.Printf("Has legacy wallet: %v\n", !hasAnyOct && hasLeg)
		fmt.Printf("Needs PIN: %v\n", hasAnyOct || hasLeg)
		fmt.Printf("Needs create: %v\n", !hasAnyOct && !hasLeg)

		if hasAnyOct {
			fmt.Printf("\nWallets:\n")
			for _, e := range all {
				name := e.Name
				if name == "" {
					name = "(unnamed)"
				}
				fmt.Printf("  %s  %s  [%s]\n", name, e.Addr, e.File)
			}
		}
	},
}

var walletCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new wallet",
	Run: func(cmd *cobra.Command, args []string) {
		pin := readPin("Set PIN (6 digits): ")
		if !validatePin(pin) {
			fmt.Println("Error: PIN must be exactly 6 digits")
			return
		}
		pin2 := readPin("Confirm PIN: ")
		if pin != pin2 {
			fmt.Println("Error: PINs do not match")
			return
		}
		name, _ := cmd.Flags().GetString("name")
		if name == "" {
			name = "wallet"
		}

		tmpPath := wallet.WalletDir + "/wallet_new.tmp"
		w, mnemonic, err := wallet.CreateWallet(tmpPath, pin)
		if err != nil {
			fmt.Printf("Error: %s\n", err)
			return
		}
		namedPath := wallet.WalletPathFor(w.Addr)
		if os.Rename(tmpPath, namedPath) == nil {
			// update path
		} else {
			namedPath = tmpPath
		}

		me := wallet.ManifestEntry{
			Name:           name,
			File:           namedPath,
			Addr:           w.Addr,
			HD:             true,
			HDVersion:      2,
			HDIndex:        0,
			MasterSeedHash: crypto.ComputeSeedHash(w.MasterSeedB64),
		}
		wallet.ManifestUpsert(me)

		fmt.Printf("Address:  %s\n", w.Addr)
		fmt.Printf("Pubkey:   %s\n", w.PubB64)
		fmt.Printf("\n!!! SAVE YOUR MNEMONIC - IT WILL NOT BE SHOWN AGAIN !!!\n")
		fmt.Printf("Mnemonic: %s\n", mnemonic)
	},
}

var walletImportCmd = &cobra.Command{
	Use:   "import",
	Short: "Import wallet from mnemonic or private key",
	Run: func(cmd *cobra.Command, args []string) {
		privKey, _ := cmd.Flags().GetString("key")
		mnemonic, _ := cmd.Flags().GetString("mnemonic")
		if privKey == "" && mnemonic == "" {
			fmt.Println("Error: --key or --mnemonic required")
			return
		}
		pin := readPin("Set PIN (6 digits): ")
		if !validatePin(pin) {
			fmt.Println("Error: PIN must be exactly 6 digits")
			return
		}
		name, _ := cmd.Flags().GetString("name")
		if name == "" {
			name = "imported"
		}

		tmpPath := wallet.WalletDir + "/wallet_imp.tmp"
		var w *wallet.Wallet
		var err error
		isMnemonic := false

		input := mnemonic
		if input == "" {
			input = privKey
		}
		if mnemonic != "" || crypto.LooksLikeMnemonic(input) {
			mn := input
			if mnemonic != "" {
				mn = mnemonic
			}
			// Auto-detect HD version
			hdVersion := 2
			addrV2 := wallet.AddrFromMnemonic(mn, 2)
			addrV1 := wallet.AddrFromMnemonic(mn, 1)
			probe := rpc.NewClient("http://46.101.86.250:8080")
			r2 := probe.GetBalance(addrV2)
			r1 := probe.GetBalance(addrV1)
			bal2, bal1 := int64(0), int64(0)
			if r2.OK {
				m := r2.Map()
				if v, ok := m["balance"].(float64); ok {
					bal2 = int64(v)
				}
			}
			if r1.OK {
				m := r1.Map()
				if v, ok := m["balance"].(float64); ok {
					bal1 = int64(v)
				}
			}
			if bal1 > 0 && bal2 == 0 {
				hdVersion = 1
			}
			fmt.Printf("Auto-detect: v2=%s (bal=%d) v1=%s (bal=%d) -> v%d\n",
				addrV2, bal2, addrV1, bal1, hdVersion)

			w, err = wallet.ImportWalletMnemonic(tmpPath, mn, pin, hdVersion)
			isMnemonic = true
		} else {
			w, err = wallet.ImportWalletPrivkey(tmpPath, privKey, pin)
		}
		if err != nil {
			fmt.Printf("Error: %s\n", err)
			return
		}

		namedPath := wallet.WalletPathFor(w.Addr)
		if os.Rename(tmpPath, namedPath) == nil {
			// ok
		} else {
			namedPath = tmpPath
		}

		me := wallet.ManifestEntry{
			Name:      name,
			File:      namedPath,
			Addr:      w.Addr,
			HD:        isMnemonic,
			HDVersion: w.HDVersion,
			HDIndex:   0,
		}
		if isMnemonic {
			me.MasterSeedHash = crypto.ComputeSeedHash(w.MasterSeedB64)
		}
		wallet.ManifestUpsert(me)

		fmt.Printf("Address: %s\n", w.Addr)
		fmt.Printf("Imported successfully\n")
	},
}

var walletUnlockCmd = &cobra.Command{
	Use:   "unlock",
	Short: "Unlock and display wallet info",
	Run: func(cmd *cobra.Command, args []string) {
		s := mustSession(cmd)
		defer s.Close()
		fmt.Printf("Address:         %s\n", s.Wallet.Addr)
		fmt.Printf("Public key:      %s\n", s.Wallet.PubB64)
		fmt.Printf("Has master seed: %v\n", s.Wallet.HasMasterSeed())
		fmt.Printf("HD version:      %d\n", s.Wallet.HDVersion)
		fmt.Printf("HD index:        %d\n", s.Wallet.HDIndex)
		fmt.Printf("RPC URL:         %s\n", s.Wallet.RPCURL)
	},
}

var walletLockCmd = &cobra.Command{
	Use:   "lock",
	Short: "Display lock confirmation (CLI auto-locks after each command)",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("CLI mode: wallet is locked after each command automatically.")
	},
}

var walletInfoCmd = &cobra.Command{
	Use:   "info",
	Short: "Show wallet details",
	Run: func(cmd *cobra.Command, args []string) {
		s := mustSession(cmd)
		defer s.Close()
		j, _ := json.MarshalIndent(map[string]interface{}{
			"address":         s.Wallet.Addr,
			"public_key":      s.Wallet.PubB64,
			"rpc_url":         s.Wallet.RPCURL,
			"explorer_url":    s.Wallet.ExplorerURL,
			"has_master_seed": s.Wallet.HasMasterSeed(),
			"hd_index":        s.Wallet.HDIndex,
			"hd_version":      s.Wallet.HDVersion,
		}, "", "  ")
		fmt.Println(string(j))
	},
}

var walletAccountsCmd = &cobra.Command{
	Use:   "accounts",
	Short: "List all saved accounts",
	Run: func(cmd *cobra.Command, args []string) {
		entries := wallet.LoadManifest()
		if len(entries) == 0 {
			fmt.Println("No accounts found")
			return
		}
		for _, e := range entries {
			name := e.Name
			if name == "" {
				name = "(unnamed)"
			}
			hd := ""
			if e.HD {
				hd = fmt.Sprintf(" [HD v%d #%d]", e.HDVersion, e.HDIndex)
			}
			fmt.Printf("  %-15s %s%s\n", name, e.Addr, hd)
		}
	},
}

var walletSwitchCmd = &cobra.Command{
	Use:   "switch",
	Short: "Switch active wallet (verifies PIN for target account)",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		addr := args[0]
		pin := readPin("Enter PIN: ")
		if !validatePin(pin) {
			fmt.Println("Error: PIN must be exactly 6 digits")
			return
		}
		s, err := loadSessionForAddr(addr, pin)
		if err != nil {
			fmt.Printf("Error: %s\n", err)
			return
		}
		defer s.Close()
		fmt.Printf("Switched to: %s\n", s.Wallet.Addr)
		fmt.Printf("Public key:  %s\n", s.Wallet.PubB64)
	},
}

var walletDeriveCmd = &cobra.Command{
	Use:   "derive",
	Short: "Derive a new HD child account",
	Run: func(cmd *cobra.Command, args []string) {
		s := mustSession(cmd)
		defer s.Close()
		if !s.Wallet.HasMasterSeed() {
			fmt.Println("Error: wallet has no master seed (imported via private key)")
			return
		}
		name, _ := cmd.Flags().GetString("name")
		nextIndex := wallet.ManifestNextHDIndex(s.Wallet.MasterSeedB64)
		if name == "" {
			name = "account " + strconv.Itoa(nextIndex)
		}

		w, err := wallet.DeriveHDAccount(
			s.Wallet.MasterSeedB64, uint32(nextIndex),
			s.Wallet.RPCURL, s.Wallet.ExplorerURL, s.Pin,
			s.Wallet.HDVersion,
		)
		if err != nil {
			fmt.Printf("Error: %s\n", err)
			return
		}

		me := wallet.ManifestEntry{
			Name:           name,
			File:           wallet.WalletPathFor(w.Addr),
			Addr:           w.Addr,
			HD:             true,
			HDVersion:      s.Wallet.HDVersion,
			HDIndex:        nextIndex,
			ParentAddr:     s.Wallet.Addr,
			MasterSeedHash: crypto.ComputeSeedHash(s.Wallet.MasterSeedB64),
		}
		wallet.ManifestUpsert(me)

		fmt.Printf("Derived HD account #%d\n", nextIndex)
		fmt.Printf("Address: %s\n", w.Addr)
		fmt.Printf("Name:    %s\n", name)
	},
}

var walletRenameCmd = &cobra.Command{
	Use:   "rename [addr] [name]",
	Short: "Rename an account",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		wallet.ManifestRename(args[0], args[1])
		fmt.Println("Renamed successfully")
	},
}

var walletDeleteCmd = &cobra.Command{
	Use:   "delete [addr]",
	Short: "Remove an account from manifest",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		wallet.ManifestRemove(args[0])
		fmt.Println("Account removed from manifest")
	},
}

func init() {
	walletCmd.AddCommand(walletStatusCmd)
	walletCmd.AddCommand(walletCreateCmd)
	walletCmd.AddCommand(walletImportCmd)
	walletCmd.AddCommand(walletUnlockCmd)
	walletCmd.AddCommand(walletLockCmd)
	walletCmd.AddCommand(walletInfoCmd)
	walletCmd.AddCommand(walletAccountsCmd)
	walletCmd.AddCommand(walletSwitchCmd)
	walletCmd.AddCommand(walletDeriveCmd)
	walletCmd.AddCommand(walletRenameCmd)
	walletCmd.AddCommand(walletDeleteCmd)

	walletCreateCmd.Flags().StringP("name", "n", "wallet", "Account name")
	walletImportCmd.Flags().StringP("key", "k", "", "Private key (base64)")
	walletImportCmd.Flags().StringP("mnemonic", "m", "", "Mnemonic seed phrase")
	walletImportCmd.Flags().StringP("name", "n", "imported", "Account name")

	walletUnlockCmd.Flags().String("account", "", "Account address to unlock")
	walletInfoCmd.Flags().String("account", "", "Account address")
	walletDeriveCmd.Flags().String("account", "", "Account address")
	walletDeriveCmd.Flags().StringP("name", "n", "", "Name for derived account")
}
