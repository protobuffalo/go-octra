package cmd

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strconv"

	"github.com/protobuffalo/go-octra/internal/config"
	"github.com/protobuffalo/go-octra/internal/crypto"
	"github.com/protobuffalo/go-octra/internal/rpc"
	"github.com/protobuffalo/go-octra/internal/wallet"
)

func dispatchWallet(args []string) {
	if len(args) == 0 {
		printWalletHelp()
		return
	}
	switch args[0] {
	case "status":
		runWalletStatus(args[1:])
	case "create":
		runWalletCreate(args[1:])
	case "import":
		runWalletImport(args[1:])
	case "unlock":
		runWalletUnlock(args[1:])
	case "lock":
		runWalletLock(args[1:])
	case "info":
		runWalletInfo(args[1:])
	case "accounts":
		runWalletAccounts(args[1:])
	case "switch":
		runWalletSwitch(args[1:])
	case "derive":
		runWalletDerive(args[1:])
	case "rename":
		runWalletRename(args[1:])
	case "delete":
		runWalletDelete(args[1:])
	case "help", "--help", "-h":
		printWalletHelp()
	default:
		fmt.Printf("Unknown wallet command: %s\n", args[0])
		printWalletHelp()
	}
}

func printWalletHelp() {
	fmt.Println("Wallet management commands")
	fmt.Println()
	fmt.Println("Usage: octra wallet <subcommand> [flags]")
	fmt.Println()
	fmt.Println("Subcommands:")
	fmt.Println("  status    Check wallet status")
	fmt.Println("  create    Create a new wallet")
	fmt.Println("  import    Import wallet from mnemonic or private key")
	fmt.Println("  unlock    Unlock and display wallet info")
	fmt.Println("  lock      Display lock confirmation")
	fmt.Println("  info      Show wallet details")
	fmt.Println("  accounts  List all saved accounts")
	fmt.Println("  switch    Switch active wallet")
	fmt.Println("  derive    Derive a new HD child account")
	fmt.Println("  rename    Rename an account")
	fmt.Println("  delete    Remove an account from manifest")
}

func runWalletStatus(args []string) {
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
}

func runWalletCreate(args []string) {
	fs := flag.NewFlagSet("wallet create", flag.ExitOnError)
	name := fs.String("name", "wallet", "Account name")
	fs.Parse(args)

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
		Name:           *name,
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
}

func runWalletImport(args []string) {
	fs := flag.NewFlagSet("wallet import", flag.ExitOnError)
	privKey := fs.String("key", "", "Private key (base64)")
	mnemonic := fs.String("mnemonic", "", "Mnemonic seed phrase")
	name := fs.String("name", "imported", "Account name")
	fs.Parse(args)

	if *privKey == "" && *mnemonic == "" {
		fmt.Println("Error: --key or --mnemonic required")
		return
	}
	pin := readPin("Set PIN (6 digits): ")
	if !validatePin(pin) {
		fmt.Println("Error: PIN must be exactly 6 digits")
		return
	}

	tmpPath := wallet.WalletDir + "/wallet_imp.tmp"
	var w *wallet.Wallet
	var err error
	isMnemonic := false

	input := *mnemonic
	if input == "" {
		input = *privKey
	}
	if *mnemonic != "" || crypto.LooksLikeMnemonic(input) {
		mn := input
		if *mnemonic != "" {
			mn = *mnemonic
		}
		// Auto-detect HD version
		hdVersion := 2
		addrV2 := wallet.AddrFromMnemonic(mn, 2)
		addrV1 := wallet.AddrFromMnemonic(mn, 1)
		probe := rpc.NewClient(config.Load().RPCURL)
		r2, err2 := probe.GetBalance(addrV2)
		r1, err1 := probe.GetBalance(addrV1)
		bal2, bal1 := int64(0), int64(0)
		if err2 == nil {
			bal2 = r2.Balance.Int64()
		}
		if err1 == nil {
			bal1 = r1.Balance.Int64()
		}
		if bal1 > 0 && bal2 == 0 {
			hdVersion = 1
		}
		fmt.Printf("Auto-detect: v2=%s (bal=%d) v1=%s (bal=%d) -> v%d\n",
			addrV2, bal2, addrV1, bal1, hdVersion)

		w, err = wallet.ImportWalletMnemonic(tmpPath, mn, pin, hdVersion)
		isMnemonic = true
	} else {
		w, err = wallet.ImportWalletPrivkey(tmpPath, *privKey, pin)
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
		Name:      *name,
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
}

func runWalletUnlock(args []string) {
	fs := flag.NewFlagSet("wallet unlock", flag.ExitOnError)
	account := fs.String("account", "", "Account address")
	fs.Parse(args)

	s := mustSession(*account)
	defer s.Close()
	fmt.Printf("Address:         %s\n", s.Wallet.Addr)
	fmt.Printf("Public key:      %s\n", s.Wallet.PubB64)
	fmt.Printf("Has master seed: %v\n", s.Wallet.HasMasterSeed())
	fmt.Printf("HD version:      %d\n", s.Wallet.HDVersion)
	fmt.Printf("HD index:        %d\n", s.Wallet.HDIndex)
	fmt.Printf("RPC URL:         %s\n", s.Wallet.RPCURL)
}

func runWalletLock(args []string) {
	fmt.Println("CLI mode: wallet is locked after each command automatically.")
}

func runWalletInfo(args []string) {
	fs := flag.NewFlagSet("wallet info", flag.ExitOnError)
	account := fs.String("account", "", "Account address")
	fs.Parse(args)

	s := mustSession(*account)
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
}

func runWalletAccounts(args []string) {
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
}

func runWalletSwitch(args []string) {
	fs := flag.NewFlagSet("wallet switch", flag.ExitOnError)
	fs.Parse(args)
	if fs.NArg() != 1 {
		fmt.Println("Usage: octra wallet switch <address>")
		return
	}
	addr := fs.Arg(0)
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
}

func runWalletDerive(args []string) {
	fs := flag.NewFlagSet("wallet derive", flag.ExitOnError)
	account := fs.String("account", "", "Account address")
	name := fs.String("name", "", "Name for derived account")
	fs.Parse(args)

	s := mustSession(*account)
	defer s.Close()
	if !s.Wallet.HasMasterSeed() {
		fmt.Println("Error: wallet has no master seed (imported via private key)")
		return
	}
	nextIndex := wallet.ManifestNextHDIndex(s.Wallet.MasterSeedB64)
	if *name == "" {
		*name = "account " + strconv.Itoa(nextIndex)
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
		Name:           *name,
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
	fmt.Printf("Name:    %s\n", *name)
}

func runWalletRename(args []string) {
	fs := flag.NewFlagSet("wallet rename", flag.ExitOnError)
	fs.Parse(args)
	if fs.NArg() != 2 {
		fmt.Println("Usage: octra wallet rename <address> <name>")
		return
	}
	wallet.ManifestRename(fs.Arg(0), fs.Arg(1))
	fmt.Println("Renamed successfully")
}

func runWalletDelete(args []string) {
	fs := flag.NewFlagSet("wallet delete", flag.ExitOnError)
	fs.Parse(args)
	if fs.NArg() != 1 {
		fmt.Println("Usage: octra wallet delete <address>")
		return
	}
	wallet.ManifestRemove(fs.Arg(0))
	fmt.Println("Account removed from manifest")
}
