package cmd

import (
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/protobuffalo/go-octra/internal/crypto"
	octx "github.com/protobuffalo/go-octra/internal/tx"
)

var fheCmd = &cobra.Command{
	Use:   "fhe",
	Short: "FHE encrypt/decrypt balance operations",
}

var fheEncryptCmd = &cobra.Command{
	Use:   "encrypt",
	Short: "Encrypt funds (move to encrypted balance)",
	Run: func(cmd *cobra.Command, args []string) {
		s := mustSession(cmd)
		defer s.Close()

		amountStr, _ := cmd.Flags().GetString("amount")
		ou, _ := cmd.Flags().GetString("ou")
		raw, err := octx.ParseAmountRaw(amountStr)
		if err != nil || raw <= 0 {
			fmt.Println("Error: invalid amount")
			return
		}

		if ou == "" {
			ou = "10000"
		}

		if s.PvacForeign {
			fmt.Println("Error: PVAC key mismatch - use 'octra keyswitch' to reset encryption key")
			return
		}

		s.EnsurePvacRegistered()

		// Generate FHE cipher
		var seed [32]byte
		copy(seed[:], crypto.RandomBytes(32))
		ct := s.Pvac.Encrypt(uint64(raw), seed)
		cipherStr := s.Pvac.EncodeCipher(ct)

		// Pedersen commitment
		var blinding [32]byte
		copy(blinding[:], crypto.RandomBytes(32))
		amtCommit := s.Pvac.PedersenCommit(uint64(raw), blinding)
		amtCommitB64 := crypto.Base64Encode(amtCommit[:])

		// Zero-knowledge proof
		zkp := s.Pvac.MakeZeroProofBound(ct, uint64(raw), blinding)
		zpStr := s.Pvac.EncodeZeroProof(zkp)
		s.Pvac.FreeZeroProof(zkp)
		s.Pvac.FreeCipher(ct)

		encData, _ := json.Marshal(map[string]string{
			"cipher":            cipherStr,
			"amount_commitment": amtCommitB64,
			"zero_proof":        zpStr,
			"blinding":          crypto.Base64Encode(blinding[:]),
		})

		bi := octx.GetNonceBalance(s.RPC, s.Wallet)
		tx := &octx.Transaction{
			From:          s.Wallet.Addr,
			To:            s.Wallet.Addr,
			Amount:        strconv.FormatInt(raw, 10),
			Nonce:         bi.Nonce + 1,
			OU:            ou,
			Timestamp:     octx.NowTS(),
			OpType:        "encrypt",
			EncryptedData: string(encData),
		}
		octx.SignTx(tx, s.Wallet.SK, s.Wallet.PubB64)
		txHash, err := octx.SubmitTx(s.RPC, tx)
		if err != nil {
			fmt.Printf("Error: %s\n", err)
			return
		}
		fmt.Printf("Transaction submitted: %s\n", txHash)
	},
}

var fheDecryptCmd = &cobra.Command{
	Use:   "decrypt",
	Short: "Decrypt funds (move to public balance)",
	Run: func(cmd *cobra.Command, args []string) {
		s := mustSession(cmd)
		defer s.Close()

		amountStr, _ := cmd.Flags().GetString("amount")
		ou, _ := cmd.Flags().GetString("ou")
		raw, err := octx.ParseAmountRaw(amountStr)
		if err != nil || raw <= 0 {
			fmt.Println("Error: invalid amount")
			return
		}

		if ou == "" {
			ou = "10000"
		}

		if s.PvacForeign {
			fmt.Println("Error: PVAC key mismatch - use 'octra keyswitch' to reset encryption key")
			return
		}

		// Check encrypted balance
		ebCipher, ebDecrypted := s.GetEncryptedBalance()
		if ebDecrypted < raw {
			fmt.Printf("Error: insufficient encrypted balance: have %d, need %d\n", ebDecrypted, raw)
			return
		}

		s.EnsurePvacRegistered()

		// Generate FHE cipher for the amount
		var seed [32]byte
		copy(seed[:], crypto.RandomBytes(32))
		ct := s.Pvac.Encrypt(uint64(raw), seed)
		cipherStr := s.Pvac.EncodeCipher(ct)

		// Pedersen commitment
		var blinding [32]byte
		copy(blinding[:], crypto.RandomBytes(32))
		amtCommit := s.Pvac.PedersenCommit(uint64(raw), blinding)
		amtCommitB64 := crypto.Base64Encode(amtCommit[:])

		// Zero-knowledge proof
		zkp := s.Pvac.MakeZeroProofBound(ct, uint64(raw), blinding)
		zpStr := s.Pvac.EncodeZeroProof(zkp)
		s.Pvac.FreeZeroProof(zkp)

		// Compute new balance cipher and range proof
		currentCt := s.Pvac.DecodeCipher(ebCipher)
		newBalCt := s.Pvac.CTSub(currentCt, ct)
		newBalValue := uint64(ebDecrypted - raw)
		arp := s.Pvac.MakeAggRangeProof(newBalCt, newBalValue)
		rpBalStr := s.Pvac.EncodeAggRangeProof(arp)
		s.Pvac.FreeAggRangeProof(arp)
		s.Pvac.FreeCipher(newBalCt)
		s.Pvac.FreeCipher(currentCt)
		s.Pvac.FreeCipher(ct)

		encData, _ := json.Marshal(map[string]string{
			"cipher":              cipherStr,
			"amount_commitment":   amtCommitB64,
			"zero_proof":          zpStr,
			"blinding":            crypto.Base64Encode(blinding[:]),
			"range_proof_balance": rpBalStr,
		})

		bi := octx.GetNonceBalance(s.RPC, s.Wallet)
		tx := &octx.Transaction{
			From:          s.Wallet.Addr,
			To:            s.Wallet.Addr,
			Amount:        strconv.FormatInt(raw, 10),
			Nonce:         bi.Nonce + 1,
			OU:            ou,
			Timestamp:     octx.NowTS(),
			OpType:        "decrypt",
			EncryptedData: string(encData),
		}
		octx.SignTx(tx, s.Wallet.SK, s.Wallet.PubB64)
		txHash, err := octx.SubmitTx(s.RPC, tx)
		if err != nil {
			fmt.Printf("Error: %s\n", err)
			return
		}
		fmt.Printf("Transaction submitted: %s\n", txHash)
	},
}

var fheEncryptValueCmd = &cobra.Command{
	Use:   "encrypt-value",
	Short: "Encrypt a raw value (FHE only, no transaction)",
	Run: func(cmd *cobra.Command, args []string) {
		s := mustSession(cmd)
		defer s.Close()

		value, _ := cmd.Flags().GetInt64("value")
		var seed [32]byte
		copy(seed[:], crypto.RandomBytes(32))
		ct := s.Pvac.Encrypt(uint64(value), seed)
		b64 := s.Pvac.SerializeCipherB64(ct)
		s.Pvac.FreeCipher(ct)

		j, _ := json.MarshalIndent(map[string]interface{}{
			"ciphertext": b64,
		}, "", "  ")
		fmt.Println(string(j))
	},
}

var fheDecryptValueCmd = &cobra.Command{
	Use:   "decrypt-value",
	Short: "Decrypt an FHE ciphertext",
	Run: func(cmd *cobra.Command, args []string) {
		s := mustSession(cmd)
		defer s.Close()

		ciphertext, _ := cmd.Flags().GetString("ciphertext")
		if ciphertext == "" {
			fmt.Println("Error: --ciphertext required")
			return
		}

		// Try as prefixed cipher first, then as raw base64
		var val int64
		if ct := s.Pvac.DecodeCipher(ciphertext); ct != 0 {
			val = s.Pvac.GetBalance(ciphertext)
			s.Pvac.FreeCipher(ct)
		} else if ct := s.Pvac.DeserializeCipherFromB64(ciphertext); ct != 0 {
			b64 := s.Pvac.SerializeCipherB64(ct)
			val = s.Pvac.GetBalance("hfhe_v1|" + b64)
			s.Pvac.FreeCipher(ct)
		} else {
			fmt.Println("Error: invalid ciphertext")
			return
		}

		j, _ := json.MarshalIndent(map[string]interface{}{
			"value": val,
		}, "", "  ")
		fmt.Println(string(j))
	},
}

func init() {
	fheCmd.AddCommand(fheEncryptCmd)
	fheCmd.AddCommand(fheDecryptCmd)
	fheCmd.AddCommand(fheEncryptValueCmd)
	fheCmd.AddCommand(fheDecryptValueCmd)

	fheEncryptCmd.Flags().String("amount", "", "Amount to encrypt")
	fheEncryptCmd.Flags().String("ou", "", "Operation units")
	fheEncryptCmd.Flags().String("account", "", "Account address")
	fheEncryptCmd.MarkFlagRequired("amount")

	fheDecryptCmd.Flags().String("amount", "", "Amount to decrypt")
	fheDecryptCmd.Flags().String("ou", "", "Operation units")
	fheDecryptCmd.Flags().String("account", "", "Account address")
	fheDecryptCmd.MarkFlagRequired("amount")

	fheEncryptValueCmd.Flags().Int64("value", 0, "Value to encrypt")
	fheEncryptValueCmd.Flags().String("account", "", "Account address")

	fheDecryptValueCmd.Flags().String("ciphertext", "", "Ciphertext to decrypt")
	fheDecryptValueCmd.Flags().String("account", "", "Account address")
}
