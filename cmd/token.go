package cmd

import (
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/protobuffalo/go-octra/internal/rpc"
	octx "github.com/protobuffalo/go-octra/internal/tx"
)

var tokenCmd = &cobra.Command{
	Use:   "token",
	Short: "Token commands",
}

var tokenListCmd = &cobra.Command{
	Use:   "list",
	Short: "List tokens with balances",
	Run: func(cmd *cobra.Command, args []string) {
		s := mustSession(cmd)
		defer s.Close()

		lr := s.RPC.ListContracts()
		if !lr.OK {
			fmt.Println("Error: could not list contracts")
			return
		}
		m := lr.Map()
		contracts, ok := m["contracts"].([]interface{})
		if !ok {
			fmt.Println("No tokens found")
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
		for _, c := range contracts {
			cm, ok := c.(map[string]interface{})
			if !ok {
				continue
			}
			addr := rpc.MapString(cm, "address", "")
			if addr == "" {
				continue
			}
			sr := s.RPC.ContractStorage(addr, "symbol")
			if !sr.OK {
				continue
			}
			sm := sr.Map()
			sym := rpc.MapString(sm, "value", "")
			if sym == "" || sym == "0" {
				continue
			}

			br := s.RPC.ContractCallView(addr, "balance_of",
				[]interface{}{s.Wallet.Addr}, s.Wallet.Addr)
			bal := "0"
			if br.OK {
				bm := br.Map()
				bal = rpc.MapString(bm, "result", "0")
			}
			if bal == "0" || bal == "" {
				continue
			}

			nr := s.RPC.ContractStorage(addr, "name")
			name := sym
			if nr.OK {
				nm := nr.Map()
				if n := rpc.MapString(nm, "value", ""); n != "" {
					name = n
				}
			}

			dr := s.RPC.ContractStorage(addr, "decimals")
			decimals := "0"
			if dr.OK {
				dm := dr.Map()
				decimals = rpc.MapString(dm, "value", "0")
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
	},
}

var tokenTransferCmd = &cobra.Command{
	Use:   "transfer",
	Short: "Transfer tokens",
	Run: func(cmd *cobra.Command, args []string) {
		s := mustSession(cmd)
		defer s.Close()

		token, _ := cmd.Flags().GetString("token")
		to, _ := cmd.Flags().GetString("to")
		amountStr, _ := cmd.Flags().GetString("amount")
		ou, _ := cmd.Flags().GetString("ou")

		if token == "" || to == "" || amountStr == "" {
			fmt.Println("Error: --token, --to, and --amount required")
			return
		}

		amount, err := strconv.ParseInt(amountStr, 10, 64)
		if err != nil || amount <= 0 {
			fmt.Println("Error: invalid amount")
			return
		}
		if ou == "" {
			ou = "1000"
		}

		bi := octx.GetNonceBalance(s.RPC, s.Wallet)
		params, _ := json.Marshal([]interface{}{to, amount})
		tx := &octx.Transaction{
			From:          s.Wallet.Addr,
			To:            token,
			Amount:        "0",
			Nonce:         bi.Nonce + 1,
			OU:            ou,
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
	},
}

func init() {
	tokenCmd.AddCommand(tokenListCmd)
	tokenCmd.AddCommand(tokenTransferCmd)

	tokenListCmd.Flags().String("account", "", "Account address")

	tokenTransferCmd.Flags().String("token", "", "Token contract address")
	tokenTransferCmd.Flags().String("to", "", "Recipient address")
	tokenTransferCmd.Flags().String("amount", "", "Amount (raw units)")
	tokenTransferCmd.Flags().String("ou", "", "Operation units")
	tokenTransferCmd.Flags().String("account", "", "Account address")
	tokenTransferCmd.MarkFlagRequired("token")
	tokenTransferCmd.MarkFlagRequired("to")
	tokenTransferCmd.MarkFlagRequired("amount")
}
