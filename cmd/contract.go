package cmd

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	octx "github.com/protobuffalo/go-octra/internal/tx"
)

func dispatchContract(args []string) {
	if len(args) == 0 {
		printContractHelp()
		return
	}
	switch args[0] {
	case "compile":
		runContractCompile(args[1:])
	case "compile-aml":
		runContractCompileAml(args[1:])
	case "address":
		runContractAddress(args[1:])
	case "deploy":
		runContractDeploy(args[1:])
	case "verify":
		runContractVerify(args[1:])
	case "call":
		runContractCall(args[1:])
	case "view":
		runContractView(args[1:])
	case "info":
		runContractInfo(args[1:])
	case "receipt":
		runContractReceipt(args[1:])
	case "storage":
		runContractStorage(args[1:])
	case "help", "--help", "-h":
		printContractHelp()
	default:
		fmt.Printf("Unknown contract command: %s\n", args[0])
		printContractHelp()
	}
}

func printContractHelp() {
	fmt.Println("Smart contract commands")
	fmt.Println()
	fmt.Println("Usage: octra contract <subcommand> [flags]")
	fmt.Println()
	fmt.Println("Subcommands:")
	fmt.Println("  compile      Compile assembly bytecode")
	fmt.Println("  compile-aml  Compile AML source code")
	fmt.Println("  address      Compute contract address")
	fmt.Println("  deploy       Deploy a smart contract")
	fmt.Println("  verify       Verify contract source")
	fmt.Println("  call         Call a contract method (state-changing)")
	fmt.Println("  view         Call a contract method (read-only)")
	fmt.Println("  info         Get contract info")
	fmt.Println("  receipt      Get contract execution receipt")
	fmt.Println("  storage      Read contract storage by key")
}

func runContractCompile(args []string) {
	fs := flag.NewFlagSet("contract compile", flag.ExitOnError)
	source := fs.String("source", "", "Assembly source")
	file := fs.String("file", "", "Source file path")
	account := fs.String("account", "", "Account address")
	fs.Parse(args)

	s := mustSession(*account)
	defer s.Close()

	if *source == "" && *file != "" {
		data, err := os.ReadFile(*file)
		if err != nil {
			fmt.Printf("Error reading file: %s\n", err)
			return
		}
		*source = string(data)
	}
	if *source == "" {
		fmt.Println("Error: --source or --file required")
		return
	}

	resp, err := s.RPC.CompileAssembly(*source)
	if err != nil {
		fmt.Printf("Error: %s\n", err)
		return
	}
	j, _ := json.MarshalIndent(map[string]interface{}{
		"bytecode":     resp.Bytecode,
		"size":         resp.Size,
		"instructions": resp.Instructions,
	}, "", "  ")
	fmt.Println(string(j))
}

func runContractCompileAml(args []string) {
	fs := flag.NewFlagSet("contract compile-aml", flag.ExitOnError)
	source := fs.String("source", "", "AML source")
	file := fs.String("file", "", "Source file path")
	account := fs.String("account", "", "Account address")
	fs.Parse(args)

	s := mustSession(*account)
	defer s.Close()

	if *source == "" && *file != "" {
		data, err := os.ReadFile(*file)
		if err != nil {
			fmt.Printf("Error reading file: %s\n", err)
			return
		}
		*source = string(data)
	}
	if *source == "" {
		fmt.Println("Error: --source or --file required")
		return
	}

	resp, err := s.RPC.CompileAml(*source)
	if err != nil {
		fmt.Printf("Error: %s\n", err)
		return
	}
	result := map[string]interface{}{
		"bytecode":     resp.Bytecode,
		"size":         resp.Size,
		"instructions": resp.Instructions,
		"version":      resp.Version,
	}
	if resp.ABI != nil {
		result["abi"] = json.RawMessage(resp.ABI)
	}
	j, _ := json.MarshalIndent(result, "", "  ")
	fmt.Println(string(j))
}

func runContractAddress(args []string) {
	fs := flag.NewFlagSet("contract address", flag.ExitOnError)
	bytecode := fs.String("bytecode", "", "Bytecode (base64)")
	account := fs.String("account", "", "Account address")
	fs.Parse(args)

	if *bytecode == "" {
		fmt.Println("Error: --bytecode required")
		return
	}

	s := mustSession(*account)
	defer s.Close()

	bi := octx.GetNonceBalance(s.RPC, s.Wallet)
	resp, err := s.RPC.ComputeContractAddress(*bytecode, s.Wallet.Addr, bi.Nonce+1)
	if err != nil {
		fmt.Printf("Error: %s\n", err)
		return
	}
	j, _ := json.MarshalIndent(map[string]interface{}{
		"address":  resp.Address,
		"deployer": resp.Deployer,
		"nonce":    resp.Nonce,
	}, "", "  ")
	fmt.Println(string(j))
}

func runContractDeploy(args []string) {
	fs := flag.NewFlagSet("contract deploy", flag.ExitOnError)
	bytecode := fs.String("bytecode", "", "Bytecode (base64)")
	params := fs.String("params", "", "Constructor params")
	ou := fs.String("ou", "", "Operation units")
	account := fs.String("account", "", "Account address")
	fs.Parse(args)

	if *bytecode == "" {
		fmt.Println("Error: --bytecode required")
		return
	}

	s := mustSession(*account)
	defer s.Close()

	if *ou == "" {
		*ou = "50000000"
	}

	bi := octx.GetNonceBalance(s.RPC, s.Wallet)
	ar, err := s.RPC.ComputeContractAddress(*bytecode, s.Wallet.Addr, bi.Nonce+1)
	if err != nil {
		fmt.Printf("Error: %s\n", err)
		return
	}

	tx := &octx.Transaction{
		From:          s.Wallet.Addr,
		To:            ar.Address,
		Amount:        "0",
		Nonce:         bi.Nonce + 1,
		OU:            *ou,
		Timestamp:     octx.NowTS(),
		OpType:        "deploy",
		EncryptedData: *bytecode,
		Message:       *params,
	}
	octx.SignTx(tx, s.Wallet.SK, s.Wallet.PubB64)
	txHash, err := octx.SubmitTx(s.RPC, tx)
	if err != nil {
		fmt.Printf("Error: %s\n", err)
		return
	}
	fmt.Printf("Contract deployed: %s\n", ar.Address)
	fmt.Printf("Transaction: %s\n", txHash)
}

func runContractVerify(args []string) {
	fs := flag.NewFlagSet("contract verify", flag.ExitOnError)
	addr := fs.String("address", "", "Contract address")
	source := fs.String("source", "", "Source code")
	file := fs.String("file", "", "Source file path")
	account := fs.String("account", "", "Account address")
	fs.Parse(args)

	s := mustSession(*account)
	defer s.Close()

	if *source == "" && *file != "" {
		data, err := os.ReadFile(*file)
		if err != nil {
			fmt.Printf("Error: %s\n", err)
			return
		}
		*source = string(data)
	}
	if *addr == "" || *source == "" {
		fmt.Println("Error: --address and (--source or --file) required")
		return
	}

	r := s.RPC.ContractVerify(*addr, *source)
	if !r.OK {
		fmt.Printf("Verification failed: %s\n", r.Error)
		return
	}
	fmt.Println("Verification passed")
	fmt.Println(string(r.Data))
}

func runContractCall(args []string) {
	fs := flag.NewFlagSet("contract call", flag.ExitOnError)
	addr := fs.String("address", "", "Contract address")
	method := fs.String("method", "", "Method name")
	params := fs.String("params", "", "JSON params array")
	amount := fs.String("amount", "0", "Amount to send")
	ou := fs.String("ou", "", "Operation units")
	account := fs.String("account", "", "Account address")
	fs.Parse(args)

	if *addr == "" || *method == "" {
		fmt.Println("Error: --address and --method required")
		return
	}

	s := mustSession(*account)
	defer s.Close()

	if *amount == "" {
		*amount = "0"
	}
	if *ou == "" {
		*ou = "1000"
	}
	if *params == "" {
		*params = "[]"
	}

	bi := octx.GetNonceBalance(s.RPC, s.Wallet)
	tx := &octx.Transaction{
		From:          s.Wallet.Addr,
		To:            *addr,
		Amount:        *amount,
		Nonce:         bi.Nonce + 1,
		OU:            *ou,
		Timestamp:     octx.NowTS(),
		OpType:        "call",
		EncryptedData: *method,
		Message:       *params,
	}
	octx.SignTx(tx, s.Wallet.SK, s.Wallet.PubB64)
	txHash, err := octx.SubmitTx(s.RPC, tx)
	if err != nil {
		fmt.Printf("Error: %s\n", err)
		return
	}
	fmt.Printf("Transaction: %s\n", txHash)
}

func runContractView(args []string) {
	fs := flag.NewFlagSet("contract view", flag.ExitOnError)
	addr := fs.String("address", "", "Contract address")
	method := fs.String("method", "", "Method name")
	params := fs.String("params", "", "JSON params array")
	account := fs.String("account", "", "Account address")
	fs.Parse(args)

	if *addr == "" || *method == "" {
		fmt.Println("Error: --address and --method required")
		return
	}

	s := mustSession(*account)
	defer s.Close()

	var parsedParams interface{}
	if *params != "" {
		json.Unmarshal([]byte(*params), &parsedParams)
	}
	if parsedParams == nil {
		parsedParams = []interface{}{}
	}

	r := s.RPC.ContractCallView(*addr, *method, parsedParams, s.Wallet.Addr)
	if !r.OK {
		fmt.Printf("Error: %s\n", r.Error)
		return
	}
	fmt.Println(string(r.Data))
}

func runContractInfo(args []string) {
	fs := flag.NewFlagSet("contract info", flag.ExitOnError)
	addr := fs.String("address", "", "Contract address")
	account := fs.String("account", "", "Account address")
	fs.Parse(args)

	if *addr == "" {
		fmt.Println("Error: --address required")
		return
	}

	s := mustSession(*account)
	defer s.Close()

	r := s.RPC.VMContract(*addr)
	if !r.OK {
		fmt.Printf("Error: %s\n", r.Error)
		return
	}
	fmt.Println(string(r.Data))
}

func runContractReceipt(args []string) {
	fs := flag.NewFlagSet("contract receipt", flag.ExitOnError)
	hash := fs.String("hash", "", "Transaction hash")
	account := fs.String("account", "", "Account address")
	fs.Parse(args)

	if *hash == "" && fs.NArg() > 0 {
		*hash = fs.Arg(0)
	}
	if *hash == "" {
		fmt.Println("Error: --hash required")
		return
	}

	s := mustSession(*account)
	defer s.Close()

	r := s.RPC.ContractReceipt(*hash)
	if !r.OK {
		fmt.Printf("Error: %s\n", r.Error)
		return
	}
	fmt.Println(string(r.Data))
}

func runContractStorage(args []string) {
	fs := flag.NewFlagSet("contract storage", flag.ExitOnError)
	addr := fs.String("address", "", "Contract address")
	key := fs.String("key", "", "Storage key")
	account := fs.String("account", "", "Account address")
	fs.Parse(args)

	if *addr == "" || *key == "" {
		fmt.Println("Error: --address and --key required")
		return
	}

	s := mustSession(*account)
	defer s.Close()

	resp, err := s.RPC.ContractStorage(*addr, *key)
	if err != nil {
		fmt.Printf("Error: %s\n", err)
		return
	}
	if resp.Value != nil {
		fmt.Printf("%v\n", resp.Value)
	} else {
		fmt.Println("null")
	}
}
