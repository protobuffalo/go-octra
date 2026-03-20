package cmd

import (
	"encoding/json"
	"fmt"
	"sync"

	"github.com/spf13/cobra"

	"github.com/protobuffalo/go-octra/internal/crypto"
	"github.com/protobuffalo/go-octra/internal/nacl"
	"github.com/protobuffalo/go-octra/internal/rpc"
	st "github.com/protobuffalo/go-octra/internal/stealth"
	octx "github.com/protobuffalo/go-octra/internal/tx"
)

var stealthCmd = &cobra.Command{
	Use:   "stealth",
	Short: "Stealth transfer commands",
}

var stealthSendCmd = &cobra.Command{
	Use:   "send",
	Short: "Send a stealth transfer",
	Run: func(cmd *cobra.Command, args []string) {
		s := mustSession(cmd)
		defer s.Close()

		to, _ := cmd.Flags().GetString("to")
		amountStr, _ := cmd.Flags().GetString("amount")
		ou, _ := cmd.Flags().GetString("ou")

		if to == "" || len(to) != 47 || to[:3] != "oct" {
			fmt.Println("Error: invalid address")
			return
		}
		raw, err := octx.ParseAmountRaw(amountStr)
		if err != nil || raw <= 0 {
			fmt.Println("Error: invalid amount")
			return
		}

		if s.PvacForeign {
			fmt.Println("Error: PVAC key mismatch - use 'octra keyswitch' to reset encryption key")
			return
		}

		// Get recipient view pubkey
		vr := s.RPC.GetViewPubkey(to)
		if !vr.OK {
			fmt.Println("Error: recipient has no view pubkey - they must register pvac first")
			return
		}
		m := vr.Map()
		vpubStr := rpc.MapString(m, "view_pubkey", "")
		if vpubStr == "" {
			fmt.Println("Error: recipient has no view pubkey")
			return
		}
		theirVpub, err := crypto.Base64Decode(vpubStr)
		if err != nil || len(theirVpub) != 32 {
			fmt.Println("Error: invalid view pubkey")
			return
		}

		fmt.Println("[1/8] ECDH x25519 key exchange")

		// Generate ephemeral keypair
		ephSK := crypto.RandomBytes(32)
		ephPK := make([]byte, 32)
		nacl.CryptoScalarmultBase(ephPK, ephSK)
		shared := st.ECDHSharedSecret(ephSK, theirVpub)

		fmt.Println("[2/8] stealth tag + claim key derivation")
		stag := st.ComputeStealthTag(shared)
		claimSec := st.ComputeClaimSecret(shared)
		claimPub := st.ComputeClaimPub(claimSec, to)

		fmt.Println("[3/8] checking encrypted balance")
		ebCipher, ebDecrypted := s.GetEncryptedBalance()
		if ebDecrypted < raw {
			fmt.Printf("Error: insufficient encrypted balance: have %d, need %d\n", ebDecrypted, raw)
			return
		}

		fmt.Println("[4/8] FHE encrypt delta (PVAC-HFHE)")
		s.EnsurePvacRegistered()

		var rBlind [32]byte
		copy(rBlind[:], crypto.RandomBytes(32))
		encAmount, err := st.EncryptStealthAmount(shared, uint64(raw), rBlind)
		if err != nil {
			fmt.Printf("Error encrypting stealth amount: %s\n", err)
			return
		}

		var seed [32]byte
		copy(seed[:], crypto.RandomBytes(32))
		ctDelta := s.Pvac.Encrypt(uint64(raw), seed)
		deltaCipherStr := s.Pvac.EncodeCipher(ctDelta)
		commitment := s.Pvac.CommitCT(ctDelta)
		commitmentB64 := crypto.Base64Encode(commitment[:])

		fmt.Println("[5/8] range proofs (parallel) - Bulletproofs R1CS")
		currentCt := s.Pvac.DecodeCipher(ebCipher)
		newCt := s.Pvac.CTSub(currentCt, ctDelta)
		newVal := uint64(ebDecrypted - raw)

		var rpDeltaStr, rpBalStr string
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			rpDelta := s.Pvac.MakeRangeProof(ctDelta, uint64(raw))
			rpDeltaStr = s.Pvac.EncodeRangeProof(rpDelta)
			s.Pvac.FreeRangeProof(rpDelta)
		}()
		go func() {
			defer wg.Done()
			rpBal := s.Pvac.MakeRangeProof(newCt, newVal)
			rpBalStr = s.Pvac.EncodeRangeProof(rpBal)
			s.Pvac.FreeRangeProof(rpBal)
		}()
		wg.Wait()

		s.Pvac.FreeCipher(ctDelta)
		s.Pvac.FreeCipher(currentCt)
		s.Pvac.FreeCipher(newCt)

		fmt.Println("[6/8] encoding proofs")

		fmt.Println("[7/8] Pedersen commitment + AES-GCM envelope")
		amtCommit := s.Pvac.PedersenCommit(uint64(raw), rBlind)
		amtCommitB64 := crypto.Base64Encode(amtCommit[:])

		fmt.Println("[8/8] building stealth transaction")
		stealthData := map[string]interface{}{
			"version":             5,
			"delta_cipher":        deltaCipherStr,
			"commitment":          commitmentB64,
			"range_proof_delta":   rpDeltaStr,
			"range_proof_balance": rpBalStr,
			"eph_pub":             crypto.Base64Encode(ephPK),
			"stealth_tag":         crypto.HexEncode(stag[:]),
			"enc_amount":          encAmount,
			"claim_pub":           crypto.HexEncode(claimPub[:]),
			"amount_commitment":   amtCommitB64,
		}
		stealthDataJSON, _ := json.Marshal(stealthData)

		if ou == "" {
			ou = "5000"
		}

		bi := octx.GetNonceBalance(s.RPC, s.Wallet)
		tx := &octx.Transaction{
			From:          s.Wallet.Addr,
			To:            "stealth",
			Amount:        "0",
			Nonce:         bi.Nonce + 1,
			OU:            ou,
			Timestamp:     octx.NowTS(),
			OpType:        "stealth",
			EncryptedData: string(stealthDataJSON),
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

var stealthScanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan for incoming stealth transfers",
	Run: func(cmd *cobra.Command, args []string) {
		s := mustSession(cmd)
		defer s.Close()

		viewSK, _ := st.DeriveViewKeypair(s.Wallet.SK[:])
		r := s.RPC.GetStealthOutputs(0)
		if !r.OK {
			fmt.Println("No stealth outputs found")
			return
		}

		var resp struct {
			Outputs []map[string]interface{} `json:"outputs"`
		}
		r.Unmarshal(&resp)

		found := 0
		for _, out := range resp.Outputs {
			claimed := rpc.MapInt(out, "claimed", 0)
			if claimed != 0 {
				continue
			}
			ephB64 := rpc.MapString(out, "eph_pub", "")
			ephRaw, err := crypto.Base64Decode(ephB64)
			if err != nil || len(ephRaw) != 32 {
				continue
			}
			shared := st.ECDHSharedSecret(viewSK[:], ephRaw)
			myTag := st.ComputeStealthTag(shared)
			myTagHex := crypto.HexEncode(myTag[:])
			if myTagHex != rpc.MapString(out, "stealth_tag", "") {
				continue
			}
			encAmount := rpc.MapString(out, "enc_amount", "")
			dec, err := st.DecryptStealthAmount(shared, encAmount)
			if err != nil {
				continue
			}
			cs := st.ComputeClaimSecret(shared)
			found++
			fmt.Printf("  Output #%s: amount=%d claim_secret=%s blinding=%s\n",
				rpc.MapString(out, "id", "?"),
				dec.Amount,
				crypto.HexEncode(cs[:]),
				crypto.Base64Encode(dec.Blinding[:]),
			)
		}
		if found == 0 {
			fmt.Println("No stealth outputs addressed to you")
		} else {
			fmt.Printf("\nFound %d claimable outputs\n", found)
		}
	},
}

var stealthClaimCmd = &cobra.Command{
	Use:   "claim",
	Short: "Claim stealth outputs",
	Run: func(cmd *cobra.Command, args []string) {
		s := mustSession(cmd)
		defer s.Close()

		ids, _ := cmd.Flags().GetStringSlice("ids")
		ou, _ := cmd.Flags().GetString("ou")
		if len(ids) == 0 {
			fmt.Println("Error: --ids required")
			return
		}

		if s.PvacForeign {
			fmt.Println("Error: PVAC key mismatch - use 'octra keyswitch' to reset encryption key")
			return
		}

		viewSK, _ := st.DeriveViewKeypair(s.Wallet.SK[:])
		sr := s.RPC.GetStealthOutputs(0)
		if !sr.OK {
			fmt.Println("Error: failed to fetch stealth outputs")
			return
		}

		s.EnsurePvacRegistered()

		var resp struct {
			Outputs []map[string]interface{} `json:"outputs"`
		}
		sr.Unmarshal(&resp)

		if ou == "" {
			ou = "3000"
		}

		bi := octx.GetNonceBalance(s.RPC, s.Wallet)
		nonce := bi.Nonce

		for _, out := range resp.Outputs {
			outID := rpc.MapString(out, "id", "")
			wanted := false
			for _, rid := range ids {
				if rid == outID {
					wanted = true
					break
				}
			}
			if !wanted {
				continue
			}

			claimed := rpc.MapInt(out, "claimed", 0)
			if claimed != 0 {
				fmt.Printf("Output %s: already claimed\n", outID)
				continue
			}

			ephB64 := rpc.MapString(out, "eph_pub", "")
			ephRaw, err := crypto.Base64Decode(ephB64)
			if err != nil || len(ephRaw) != 32 {
				fmt.Printf("Output %s: invalid eph_pub\n", outID)
				continue
			}

			shared := st.ECDHSharedSecret(viewSK[:], ephRaw)
			encAmount := rpc.MapString(out, "enc_amount", "")
			dec, err := st.DecryptStealthAmount(shared, encAmount)
			if err != nil {
				fmt.Printf("Output %s: decrypt failed\n", outID)
				continue
			}
			cs := st.ComputeClaimSecret(shared)

			// FHE encrypt claim amount
			var seed [32]byte
			copy(seed[:], crypto.RandomBytes(32))
			ctClaim := s.Pvac.Encrypt(dec.Amount, seed)
			claimCipherStr := s.Pvac.EncodeCipher(ctClaim)
			commit := s.Pvac.CommitCT(ctClaim)
			commitB64 := crypto.Base64Encode(commit[:])

			// Zero proof
			zkp := s.Pvac.MakeZeroProofBound(ctClaim, dec.Amount, dec.Blinding)
			zpStr := s.Pvac.EncodeZeroProof(zkp)
			s.Pvac.FreeCipher(ctClaim)
			s.Pvac.FreeZeroProof(zkp)

			claimData := map[string]interface{}{
				"version":      5,
				"output_id":    outID,
				"claim_cipher": claimCipherStr,
				"commitment":   commitB64,
				"claim_secret": crypto.HexEncode(cs[:]),
				"zero_proof":   zpStr,
			}
			claimDataJSON, _ := json.Marshal(claimData)

			nonce++
			tx := &octx.Transaction{
				From:          s.Wallet.Addr,
				To:            s.Wallet.Addr,
				Amount:        "0",
				Nonce:         nonce,
				OU:            ou,
				Timestamp:     octx.NowTS(),
				OpType:        "claim",
				EncryptedData: string(claimDataJSON),
			}
			octx.SignTx(tx, s.Wallet.SK, s.Wallet.PubB64)
			txHash, err := octx.SubmitTx(s.RPC, tx)
			if err != nil {
				fmt.Printf("Output %s: error: %s\n", outID, err)
			} else {
				fmt.Printf("Output %s: claimed, tx=%s\n", outID, txHash)
			}
		}
	},
}

func init() {
	stealthCmd.AddCommand(stealthSendCmd)
	stealthCmd.AddCommand(stealthScanCmd)
	stealthCmd.AddCommand(stealthClaimCmd)

	stealthSendCmd.Flags().String("to", "", "Recipient address")
	stealthSendCmd.Flags().String("amount", "", "Amount to send")
	stealthSendCmd.Flags().String("ou", "", "Operation units")
	stealthSendCmd.Flags().String("account", "", "Account address")
	stealthSendCmd.MarkFlagRequired("to")
	stealthSendCmd.MarkFlagRequired("amount")

	stealthScanCmd.Flags().String("account", "", "Account address")

	stealthClaimCmd.Flags().StringSlice("ids", nil, "Output IDs to claim")
	stealthClaimCmd.Flags().String("ou", "", "Operation units")
	stealthClaimCmd.Flags().String("account", "", "Account address")
	stealthClaimCmd.MarkFlagRequired("ids")
}
