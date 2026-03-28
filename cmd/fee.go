package cmd

import (
	"encoding/json"
	"flag"
	"fmt"
)

func runFee(args []string) {
	fs := flag.NewFlagSet("fee", flag.ExitOnError)
	account := fs.String("account", "", "Account address")
	fs.Parse(args)

	s := mustSession(*account)
	defer s.Close()

	ops := []string{"standard", "encrypt", "decrypt", "stealth", "claim", "deploy", "call"}
	fees := make(map[string]interface{})
	for _, op := range ops {
		resp, err := s.RPC.RecommendedFee(op)
		if err == nil {
			fees[op] = map[string]interface{}{
				"minimum":     resp.Minimum,
				"recommended": resp.Recommended,
				"fast":        resp.Fast,
			}
		} else {
			fees[op] = map[string]interface{}{
				"minimum":     "1000",
				"recommended": "1000",
				"fast":        "2000",
			}
		}
	}
	j, _ := json.MarshalIndent(fees, "", "  ")
	fmt.Println(string(j))
}

func runTx(args []string) {
	fs := flag.NewFlagSet("tx", flag.ExitOnError)
	account := fs.String("account", "", "Account address")
	fs.Parse(args)

	if fs.NArg() != 1 {
		fmt.Println("Usage: octra tx <hash>")
		return
	}
	hash := fs.Arg(0)

	s := mustSession(*account)
	defer s.Close()

	resp, err := s.RPC.GetTransaction(hash)
	if err != nil {
		fmt.Printf("Error: transaction not found\n")
		return
	}
	result := map[string]interface{}{
		"hash":       resp.EffectiveHash(),
		"from":       resp.From,
		"to_":        resp.Recipient(),
		"amount_raw": resp.EffectiveAmountRaw(),
		"op_type":    resp.OpType,
		"status":     resp.Status,
		"nonce":      resp.Nonce,
	}
	if resp.Timestamp != 0 {
		result["timestamp"] = resp.Timestamp
	}
	if msg := resp.MessageStr(); msg != "" {
		result["message"] = msg
	}
	j, _ := json.MarshalIndent(result, "", "  ")
	fmt.Println(string(j))
}
