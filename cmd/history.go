package cmd

import (
	"flag"
	"fmt"

	"github.com/protobuffalo/go-octra/internal/rpc"
)

func runHistory(args []string) {
	fs := flag.NewFlagSet("history", flag.ExitOnError)
	limit := fs.Int("limit", 20, "Number of transactions")
	offset := fs.Int("offset", 0, "Offset")
	account := fs.String("account", "", "Account address")
	fs.Parse(args)

	s := mustSession(*account)
	defer s.Close()

	convertRow := func(row rpc.TxRow, status string) map[string]interface{} {
		return map[string]interface{}{
			"hash":       row.Hash,
			"from":       row.From,
			"to_":        row.Recipient(),
			"amount_raw": row.EffectiveAmountRaw(),
			"op_type":    row.OpType,
			"status":     status,
			"timestamp":  row.Timestamp,
		}
	}

	if s.Cache.IsOpen() {
		resp, err := s.RPC.GetTxsByAddress(s.Wallet.Addr, 1, 0)
		nodeTotal := 0
		if err == nil {
			nodeTotal = resp.Total
		}
		cached := s.Cache.GetTotal(s.Wallet.Addr)
		if nodeTotal > cached {
			delta := nodeTotal - cached
			dr, err := s.RPC.GetTxsByAddress(s.Wallet.Addr, delta, 0)
			if err == nil {
				var toStore []map[string]interface{}
				for _, row := range dr.Transactions {
					if row.Hash != "" && !s.Cache.HasTx(row.Hash) {
						toStore = append(toStore, convertRow(row, "confirmed"))
					}
				}
				if len(toStore) > 0 {
					s.Cache.StoreTxs(toStore)
					s.Cache.SetTotal(s.Wallet.Addr, cached+len(toStore))
				}
			}
		}
		cachedTxs := s.Cache.LoadPage(*limit, *offset)
		for _, t := range cachedTxs {
			printTxRow(t)
		}
	} else {
		resp, err := s.RPC.GetTxsByAddress(s.Wallet.Addr, *limit, *offset)
		if err == nil {
			for _, row := range resp.Transactions {
				printTxRow(convertRow(row, "confirmed"))
			}
			for _, row := range resp.Rejected {
				printTxRow(convertRow(row, "rejected"))
			}
		}
	}
}

func printTxRow(t map[string]interface{}) {
	str := func(key string) string {
		if v, ok := t[key]; ok {
			if s, ok := v.(string); ok {
				return s
			}
			return fmt.Sprintf("%v", v)
		}
		return "?"
	}
	hash := str("hash")
	from := str("from")
	to := str("to_")
	amount := str("amount_raw")
	opType := str("op_type")
	status := str("status")
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
