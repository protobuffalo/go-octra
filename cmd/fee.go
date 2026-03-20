package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/protobuffalo/go-octra/internal/rpc"
)

var feeCmd = &cobra.Command{
	Use:   "fee",
	Short: "Show recommended fees",
	Run: func(cmd *cobra.Command, args []string) {
		s := mustSession(cmd)
		defer s.Close()

		ops := []string{"standard", "encrypt", "decrypt", "stealth", "claim", "deploy", "call"}
		fees := make(map[string]interface{})
		for _, op := range ops {
			r := s.RPC.RecommendedFee(op)
			if r.OK {
				fees[op] = r.Map()
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
	},
}

var txCmd = &cobra.Command{
	Use:   "tx [hash]",
	Short: "Get transaction details",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		s := mustSession(cmd)
		defer s.Close()

		r := s.RPC.GetTransaction(args[0])
		if !r.OK {
			fmt.Printf("Error: transaction not found\n")
			return
		}
		m := r.Map()
		result := map[string]interface{}{
			"hash":       rpc.MapString(m, "tx_hash", args[0]),
			"from":       rpc.MapString(m, "from", ""),
			"to_":        rpc.MapString(m, "to", rpc.MapString(m, "to_", "")),
			"amount_raw": rpc.MapString(m, "amount_raw", rpc.MapString(m, "amount", "0")),
			"op_type":    rpc.MapString(m, "op_type", "standard"),
			"status":     rpc.MapString(m, "status", "pending"),
			"nonce":      rpc.MapInt(m, "nonce", 0),
		}
		if v := rpc.MapFloat(m, "timestamp", 0); v != 0 {
			result["timestamp"] = v
		}
		if v := rpc.MapString(m, "message", ""); v != "" {
			result["message"] = v
		}
		j, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(j))
	},
}

func init() {
	feeCmd.Flags().String("account", "", "Account address")
	txCmd.Flags().String("account", "", "Account address")
}
