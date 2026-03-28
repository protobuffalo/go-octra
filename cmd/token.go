package cmd

import (
	"encoding/json"
	"flag"
	"fmt"
	"strconv"

	octx "github.com/protobuffalo/go-octra/internal/tx"
)

func dispatchToken(args []string) {
	if len(args) == 0 {
		printTokenHelp()
		return
	}
	switch args[0] {
	case "list":
		runTokenList(args[1:])
	case "transfer":
		runTokenTransfer(args[1:])
	case "help", "--help", "-h":
		printTokenHelp()
	default:
		fmt.Printf("Unknown token command: %s\n", args[0])
		printTokenHelp()
	}
}

func printTokenHelp() {
	fmt.Println("Token commands")
	fmt.Println()
	fmt.Println("Usage: octra token <subcommand> [flags]")
	fmt.Println()
	fmt.Println("Subcommands:")
	fmt.Println("  list      List tokens with balances")
	fmt.Println("  transfer  Transfer tokens")
}

func runTokenList(args []string) {
	fs := flag.NewFlagSet("token list", flag.ExitOnError)
	account := fs.String("account", "", "Account address")
	fs.Parse(args)

	s := mustSession(*account)
	defer s.Close()

	lr, err := s.RPC.ListContracts()
	if err != nil {
		fmt.Println("Error: could not list contracts")
		return
	}

	type tokenInfo struct {
		Address  string `json:"address"`
		Name     string `json:"name"`
		Symbol   string `json:"symbol"`
		Balance  string `json:"balance"`
		Decimals string `json:"decimals"`
	}

	var tokens []tokenInfo
	for _, c := range lr.Contracts {
		addr := c.Address
		if addr == "" {
			continue
		}
		sr, err := s.RPC.ContractStorage(addr, "symbol")
		if err != nil {
			continue
		}
		sym := sr.StringValue()
		if sym == "" || sym == "0" {
			continue
		}

		br := s.RPC.ContractCallView(addr, "balance_of",
			[]interface{}{s.Wallet.Addr}, s.Wallet.Addr)
		bal := "0"
		if br.OK {
			var res struct {
				Result string `json:"result"`
			}
			if br.Unmarshal(&res) == nil && res.Result != "" {
				bal = res.Result
			}
		}
		if bal == "0" || bal == "" {
			continue
		}

		nr, err := s.RPC.ContractStorage(addr, "name")
		name := sym
		if err == nil {
			if n := nr.StringValue(); n != "" {
				name = n
			}
		}

		dr, err := s.RPC.ContractStorage(addr, "decimals")
		decimals := "0"
		if err == nil {
			decimals = dr.StringValue()
			if decimals == "" {
				decimals = "0"
			}
		}

		tokens = append(tokens, tokenInfo{
			Address:  addr,
			Name:     name,
			Symbol:   sym,
			Balance:  bal,
			Decimals: decimals,
		})
	}

	if len(tokens) == 0 {
		fmt.Println("No tokens found with balance")
		return
	}
	j, _ := json.MarshalIndent(tokens, "", "  ")
	fmt.Println(string(j))
}

func runTokenTransfer(args []string) {
	fs := flag.NewFlagSet("token transfer", flag.ExitOnError)
	token := fs.String("token", "", "Token contract address")
	to := fs.String("to", "", "Recipient address")
	amountStr := fs.String("amount", "", "Amount (raw units)")
	ou := fs.String("ou", "", "Operation units")
	account := fs.String("account", "", "Account address")
	fs.Parse(args)

	if *token == "" || *to == "" || *amountStr == "" {
		fmt.Println("Error: --token, --to, and --amount required")
		return
	}

	amount, err := strconv.ParseInt(*amountStr, 10, 64)
	if err != nil || amount <= 0 {
		fmt.Println("Error: invalid amount")
		return
	}

	s := mustSession(*account)
	defer s.Close()

	if *ou == "" {
		*ou = "1000"
	}

	bi := octx.GetNonceBalance(s.RPC, s.Wallet)
	params, _ := json.Marshal([]interface{}{*to, amount})
	tx := &octx.Transaction{
		From:          s.Wallet.Addr,
		To:            *token,
		Amount:        "0",
		Nonce:         bi.Nonce + 1,
		OU:            *ou,
		Timestamp:     octx.NowTS(),
		OpType:        "call",
		EncryptedData: "transfer",
		Message:       string(params),
	}
	octx.SignTx(tx, s.Wallet.SK, s.Wallet.PubB64)
	txHash, err2 := octx.SubmitTx(s.RPC, tx)
	if err2 != nil {
		fmt.Printf("Error: %s\n", err2)
		return
	}
	fmt.Printf("Transaction: %s\n", txHash)
}
