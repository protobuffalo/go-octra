package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/protobuffalo/go-octra/internal/crypto"
	octx "github.com/protobuffalo/go-octra/internal/tx"
)

var keyswitchCmd = &cobra.Command{
	Use:   "keyswitch",
	Short: "Reset encryption key (resolve PVAC key mismatch)",
	Run: func(cmd *cobra.Command, args []string) {
		s := mustSession(cmd)
		defer s.Close()

		pkB64 := s.Pvac.SerializePubkeyB64()
		aesKat := s.Pvac.AESKatHex()

		encData, _ := json.Marshal(map[string]string{
			"new_pubkey": pkB64,
			"aes_kat":    aesKat,
		})

		// Generate a fingerprint of the new key
		pkRaw := s.Pvac.SerializePubkey()
		pkHash := crypto.SHA256(pkRaw)
		fingerprint := crypto.HexEncode(pkHash[:8])

		bi := octx.GetNonceBalance(s.RPC, s.Wallet)
		tx := &octx.Transaction{
			From:          s.Wallet.Addr,
			To:            s.Wallet.Addr,
			Amount:        "0",
			Nonce:         bi.Nonce + 1,
			OU:            "3000",
			Timestamp:     octx.NowTS(),
			OpType:        "key_switch",
			EncryptedData: string(encData),
			Message:       "encryption key switch | new_key:" + fingerprint,
		}
		octx.SignTx(tx, s.Wallet.SK, s.Wallet.PubB64)
		txHash, err := octx.SubmitTx(s.RPC, tx)
		if err != nil {
			fmt.Printf("Error: %s\n", err)
			return
		}
		fmt.Printf("Key switch submitted: %s\n", txHash)
	},
}

func init() {
	keyswitchCmd.Flags().String("account", "", "Account address")
}
