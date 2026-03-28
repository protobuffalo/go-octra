package cmd

import (
	"encoding/json"
	"flag"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/protobuffalo/go-octra/internal/crypto"
	"github.com/protobuffalo/go-octra/internal/nacl"
	st "github.com/protobuffalo/go-octra/internal/stealth"
	octx "github.com/protobuffalo/go-octra/internal/tx"
)

func dispatchStealth(args []string) {
	if len(args) == 0 {
		printStealthHelp()
		return
	}
	switch args[0] {
	case "send":
		runStealthSend(args[1:])
	case "scan":
		runStealthScan(args[1:])
	case "claim":
		runStealthClaim(args[1:])
	case "help", "--help", "-h":
		printStealthHelp()
	default:
		fmt.Printf("Unknown stealth command: %s\n", args[0])
		printStealthHelp()
	}
}

func printStealthHelp() {
	fmt.Println("Stealth transfer commands")
	fmt.Println()
	fmt.Println("Usage: octra stealth <subcommand> [flags]")
	fmt.Println()
	fmt.Println("Subcommands:")
	fmt.Println("  send   Send a stealth transfer")
	fmt.Println("  scan   Scan for incoming stealth transfers")
	fmt.Println("  claim  Claim stealth outputs")
}

func runStealthSend(args []string) {
	fs := flag.NewFlagSet("stealth send", flag.ExitOnError)
	to := fs.String("to", "", "Recipient address")
	amountStr := fs.String("amount", "", "Amount to send")
	ou := fs.String("ou", "", "Operation units")
	account := fs.String("account", "", "Account address")
	fs.Parse(args)

	if *to == "" || *amountStr == "" {
		fmt.Println("Error: --to and --amount required")
		return
	}

	s := mustSession(*account)
	defer s.Close()

	if len(*to) != 47 || (*to)[:3] != "oct" {
		fmt.Println("Error: invalid address")
		return
	}
	raw, err := octx.ParseAmountRaw(*amountStr)
	if err != nil || raw <= 0 {
		fmt.Println("Error: invalid amount")
		return
	}

	if s.PvacForeign {
		fmt.Println("Error: PVAC key mismatch - use 'octra keyswitch' to reset encryption key")
		return
	}

	// Get recipient view pubkey
	vr, err := s.RPC.GetViewPubkey(*to)
	if err != nil || !vr.HasPubkey() {
		fmt.Println("Error: recipient has no view pubkey - they must register pvac first")
		return
	}
	theirVpub, err := crypto.Base64Decode(*vr.ViewPubkey)
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
	claimPub := st.ComputeClaimPub(claimSec, *to)

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

	if *ou == "" {
		*ou = "5000"
	}

	bi := octx.GetNonceBalance(s.RPC, s.Wallet)
	tx := &octx.Transaction{
		From:          s.Wallet.Addr,
		To:            "stealth",
		Amount:        "0",
		Nonce:         bi.Nonce + 1,
		OU:            *ou,
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
}

func runStealthScan(args []string) {
	fs := flag.NewFlagSet("stealth scan", flag.ExitOnError)
	account := fs.String("account", "", "Account address")
	fs.Parse(args)

	s := mustSession(*account)
	defer s.Close()

	viewSK, _ := st.DeriveViewKeypair(s.Wallet.SK[:])
	resp, err := s.RPC.GetStealthOutputs(0)
	if err != nil {
		fmt.Println("No stealth outputs found")
		return
	}

	found := 0
	for _, out := range resp.Outputs {
		if out.Claimed != 0 {
			continue
		}
		ephRaw, err := crypto.Base64Decode(out.EphPub)
		if err != nil || len(ephRaw) != 32 {
			continue
		}
		shared := st.ECDHSharedSecret(viewSK[:], ephRaw)
		myTag := st.ComputeStealthTag(shared)
		myTagHex := crypto.HexEncode(myTag[:])
		if myTagHex != out.StealthTag {
			continue
		}
		dec, err := st.DecryptStealthAmount(shared, out.EncAmount)
		if err != nil {
			continue
		}
		cs := st.ComputeClaimSecret(shared)
		found++
		fmt.Printf("  Output #%s: amount=%d claim_secret=%s blinding=%s\n",
			out.ID.String(),
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
}

func runStealthClaim(args []string) {
	fs := flag.NewFlagSet("stealth claim", flag.ExitOnError)
	idsStr := fs.String("ids", "", "Output IDs to claim (comma-separated)")
	ou := fs.String("ou", "", "Operation units")
	account := fs.String("account", "", "Account address")
	fs.Parse(args)

	if *idsStr == "" {
		fmt.Println("Error: --ids required")
		return
	}
	ids := strings.Split(*idsStr, ",")

	s := mustSession(*account)
	defer s.Close()

	if s.PvacForeign {
		fmt.Println("Error: PVAC key mismatch - use 'octra keyswitch' to reset encryption key")
		return
	}

	viewSK, _ := st.DeriveViewKeypair(s.Wallet.SK[:])
	resp, err := s.RPC.GetStealthOutputs(0)
	if err != nil {
		fmt.Println("Error: failed to fetch stealth outputs")
		return
	}

	s.EnsurePvacRegistered()

	if *ou == "" {
		*ou = "3000"
	}

	bi := octx.GetNonceBalance(s.RPC, s.Wallet)
	nonce := bi.Nonce

	for _, out := range resp.Outputs {
		outID := out.ID.String()
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

		if out.Claimed != 0 {
			fmt.Printf("Output %s: already claimed\n", outID)
			continue
		}

		ephRaw, err := crypto.Base64Decode(out.EphPub)
		if err != nil || len(ephRaw) != 32 {
			fmt.Printf("Output %s: invalid eph_pub\n", outID)
			continue
		}

		shared := st.ECDHSharedSecret(viewSK[:], ephRaw)
		dec, err := st.DecryptStealthAmount(shared, out.EncAmount)
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

		outIDInt, _ := strconv.Atoi(outID)
		claimData := map[string]interface{}{
			"version":      5,
			"output_id":    outIDInt,
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
			OU:            *ou,
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
}
