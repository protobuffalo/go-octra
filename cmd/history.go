package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/protobuffalo/go-octra/internal/rpc"
)

var historyCmd = &cobra.Command{
	Use:   "history",
	Short: "Show transaction history",
	Run: func(cmd *cobra.Command, args []string) {
		s := mustSession(cmd)
		defer s.Close()

		limit, _ := cmd.Flags().GetInt("limit")
		offset, _ := cmd.Flags().GetInt("offset")

		convertRow := func(row map[string]interface{}, status string) map[string]interface{} {
			return map[string]interface{}{
				"hash":       rpc.MapString(row, "hash", ""),
				"from":       rpc.MapString(row, "from", ""),
				"to_":        rpc.MapString(row, "to", rpc.MapString(row, "to_", "")),
				"amount_raw": rpc.MapString(row, "amount", rpc.MapString(row, "amount_raw", "0")),
				"op_type":    rpc.MapString(row, "op_type", "standard"),
				"status":     status,
			}
		}

		if s.Cache.IsOpen() {
			r := s.RPC.GetTxsByAddress(s.Wallet.Addr, 1, 0)
			nodeTotal := 0
			if r.OK {
				m := r.Map()
				nodeTotal = rpc.MapInt(m, "total", 0)
			}
			cached := s.Cache.GetTotal(s.Wallet.Addr)
			if nodeTotal > cached {
				delta := nodeTotal - cached
				dr := s.RPC.GetTxsByAddress(s.Wallet.Addr, delta, 0)
				if dr.OK {
					m := dr.Map()
					if txsRaw, ok := m["transactions"].([]interface{}); ok {
						var toStore []map[string]interface{}
						for _, raw := range txsRaw {
							row, ok := raw.(map[string]interface{})
							if !ok {
								continue
							}
							h := rpc.MapString(row, "hash", "")
							if h != "" && !s.Cache.HasTx(h) {
								toStore = append(toStore, convertRow(row, "confirmed"))
							}
						}
						if len(toStore) > 0 {
							s.Cache.StoreTxs(toStore)
							s.Cache.SetTotal(s.Wallet.Addr, cached+len(toStore))
						}
					}
				}
			}
			cachedTxs := s.Cache.LoadPage(limit, offset)
			for _, t := range cachedTxs {
				printTxRow(t)
			}
		} else {
			r := s.RPC.GetTxsByAddress(s.Wallet.Addr, limit, offset)
			if r.OK {
				m := r.Map()
				if txsRaw, ok := m["transactions"].([]interface{}); ok {
					for _, raw := range txsRaw {
						if row, ok := raw.(map[string]interface{}); ok {
							printTxRow(convertRow(row, "confirmed"))
						}
					}
				}
				if txsRaw, ok := m["rejected"].([]interface{}); ok {
					for _, raw := range txsRaw {
						if row, ok := raw.(map[string]interface{}); ok {
							printTxRow(convertRow(row, "rejected"))
						}
					}
				}
			}
		}
	},
}

func printTxRow(t map[string]interface{}) {
	hash := rpc.MapString(t, "hash", "?")
	from := rpc.MapString(t, "from", "?")
	to := rpc.MapString(t, "to_", "?")
	amount := rpc.MapString(t, "amount_raw", "0")
	opType := rpc.MapString(t, "op_type", "standard")
	status := rpc.MapString(t, "status", "?")
	hashStr := hash
	if len(hash) > 12 {
		hashStr = hash[:12] + "..."
	}
	fromStr := from
	if len(from) > 11 {
		fromStr = from[:11] + "..."
	}
	toStr := to
	if len(to) > 11 {
		toStr = to[:11] + "..."
	}
	fmt.Printf("  %s  %s -> %s  %s  [%s] %s\n", hashStr, fromStr, toStr, amount, opType, status)
}

func init() {
	historyCmd.Flags().Int("limit", 20, "Number of transactions")
	historyCmd.Flags().Int("offset", 0, "Offset")
	historyCmd.Flags().String("account", "", "Account address")
}
