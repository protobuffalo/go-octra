package cmd

import (
	"encoding/json"
	"flag"
	"fmt"
	"strconv"

	"github.com/protobuffalo/go-octra/internal/crypto"
	octx "github.com/protobuffalo/go-octra/internal/tx"
)

func dispatchFhe(args []string) {
	if len(args) == 0 {
		printFheHelp()
		return
	}
	switch args[0] {
	case "encrypt":
		runFheEncrypt(args[1:])
	case "decrypt":
		runFheDecrypt(args[1:])
	case "encrypt-value":
		runFheEncryptValue(args[1:])
	case "decrypt-value":
		runFheDecryptValue(args[1:])
	case "help", "--help", "-h":
		printFheHelp()
	default:
		fmt.Printf("Unknown fhe command: %s\n", args[0])
		printFheHelp()
	}
}

func printFheHelp() {
	fmt.Println("FHE encrypt/decrypt balance operations")
	fmt.Println()
	fmt.Println("Usage: octra fhe <subcommand> [flags]")
	fmt.Println()
	fmt.Println("Subcommands:")
	fmt.Println("  encrypt        Encrypt funds (move to encrypted balance)")
	fmt.Println("  decrypt        Decrypt funds (move to public balance)")
	fmt.Println("  encrypt-value  Encrypt a raw value (no transaction)")
	fmt.Println("  decrypt-value  Decrypt an FHE ciphertext")
}

func runFheEncrypt(args []string) {
	fs := flag.NewFlagSet("fhe encrypt", flag.ExitOnError)
	amountStr := fs.String("amount", "", "Amount to encrypt")
	ou := fs.String("ou", "", "Operation units")
	account := fs.String("account", "", "Account address")
	fs.Parse(args)

	if *amountStr == "" {
		fmt.Println("Error: --amount required")
		return
	}

	s := mustSession(*account)
	defer s.Close()

	raw, err := octx.ParseAmountRaw(*amountStr)
	if err != nil || raw <= 0 {
		fmt.Println("Error: invalid amount")
		return
	}

	if *ou == "" {
		*ou = "10000"
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
		OU:            *ou,
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
}

func runFheDecrypt(args []string) {
	fs := flag.NewFlagSet("fhe decrypt", flag.ExitOnError)
	amountStr := fs.String("amount", "", "Amount to decrypt")
	ou := fs.String("ou", "", "Operation units")
	account := fs.String("account", "", "Account address")
	fs.Parse(args)

	if *amountStr == "" {
		fmt.Println("Error: --amount required")
		return
	}

	s := mustSession(*account)
	defer s.Close()

	raw, err := octx.ParseAmountRaw(*amountStr)
	if err != nil || raw <= 0 {
		fmt.Println("Error: invalid amount")
		return
	}

	if *ou == "" {
		*ou = "10000"
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
		OU:            *ou,
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
}

func runFheEncryptValue(args []string) {
	fs := flag.NewFlagSet("fhe encrypt-value", flag.ExitOnError)
	value := fs.Int64("value", 0, "Value to encrypt")
	account := fs.String("account", "", "Account address")
	fs.Parse(args)

	s := mustSession(*account)
	defer s.Close()

	var seed [32]byte
	copy(seed[:], crypto.RandomBytes(32))
	ct := s.Pvac.Encrypt(uint64(*value), seed)
	b64 := s.Pvac.SerializeCipherB64(ct)
	s.Pvac.FreeCipher(ct)

	j, _ := json.MarshalIndent(map[string]interface{}{
		"ciphertext": b64,
	}, "", "  ")
	fmt.Println(string(j))
}

func runFheDecryptValue(args []string) {
	fs := flag.NewFlagSet("fhe decrypt-value", flag.ExitOnError)
	ciphertext := fs.String("ciphertext", "", "Ciphertext to decrypt")
	account := fs.String("account", "", "Account address")
	fs.Parse(args)

	if *ciphertext == "" {
		fmt.Println("Error: --ciphertext required")
		return
	}

	s := mustSession(*account)
	defer s.Close()

	// Try as prefixed cipher first, then as raw base64
	var val int64
	if ct := s.Pvac.DecodeCipher(*ciphertext); ct != nil {
		val = s.Pvac.GetBalance(*ciphertext)
		s.Pvac.FreeCipher(ct)
	} else if ct := s.Pvac.DeserializeCipherFromB64(*ciphertext); ct != nil {
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
}
