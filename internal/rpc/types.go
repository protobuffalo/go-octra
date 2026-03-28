package rpc

import (
	"encoding/json"
	"fmt"
	"strconv"
)

// FlexNumber handles JSON values that may be either a number or a string.
// Unmarshals both `123` and `"123"` into a string representation.
type FlexNumber string

func (f *FlexNumber) UnmarshalJSON(data []byte) error {
	if len(data) == 0 || string(data) == "null" {
		return nil
	}
	// Try as string first
	var s string
	if json.Unmarshal(data, &s) == nil {
		*f = FlexNumber(s)
		return nil
	}
	// Must be a raw number
	*f = FlexNumber(string(data))
	return nil
}

func (f FlexNumber) String() string {
	return string(f)
}

func (f FlexNumber) Int64() int64 {
	if f == "" {
		return 0
	}
	v, _ := strconv.ParseInt(string(f), 10, 64)
	return v
}

func (f FlexNumber) Float64() float64 {
	if f == "" {
		return 0
	}
	v, _ := strconv.ParseFloat(string(f), 64)
	return v
}

// --- Balance ---

type BalanceResponse struct {
	Balance      FlexNumber `json:"balance"`
	BalanceRaw   FlexNumber `json:"balance_raw"`
	Nonce        int        `json:"nonce"`
	PendingNonce int        `json:"pending_nonce"`
}

// EffectiveNonce returns pending_nonce if set, otherwise nonce.
func (b *BalanceResponse) EffectiveNonce() int {
	if b.PendingNonce > 0 {
		return b.PendingNonce
	}
	return b.Nonce
}

// EffectiveBalanceRaw returns balance_raw if available, else computes from balance float.
func (b *BalanceResponse) EffectiveBalanceRaw() string {
	if b.BalanceRaw != "" {
		return b.BalanceRaw.String()
	}
	if b.Balance != "" {
		f := b.Balance.Float64()
		if f != 0 {
			return strconv.FormatInt(int64(f*1000000), 10)
		}
	}
	return "0"
}

// --- Transaction ---

type TransactionResponse struct {
	TxHash    string     `json:"tx_hash"`
	Hash      string     `json:"hash"`
	From      string     `json:"from"`
	To        string     `json:"to"`
	ToField   string     `json:"to_"`
	Amount    FlexNumber `json:"amount"`
	AmountRaw FlexNumber `json:"amount_raw"`
	OpType    string     `json:"op_type"`
	Status    string     `json:"status"`
	Nonce     int        `json:"nonce"`
	Timestamp float64    `json:"timestamp"`
	Message   *string    `json:"message"`
}

func (t *TransactionResponse) EffectiveHash() string {
	if t.TxHash != "" {
		return t.TxHash
	}
	return t.Hash
}

func (t *TransactionResponse) Recipient() string {
	if t.To != "" {
		return t.To
	}
	return t.ToField
}

func (t *TransactionResponse) EffectiveAmountRaw() string {
	if t.AmountRaw != "" {
		return t.AmountRaw.String()
	}
	if t.Amount != "" {
		return t.Amount.String()
	}
	return "0"
}

func (t *TransactionResponse) MessageStr() string {
	if t.Message != nil {
		return *t.Message
	}
	return ""
}

// --- Submit ---

type SubmitResponse struct {
	TxHash string `json:"tx_hash"`
}

// --- View Pubkey ---

type ViewPubkeyResponse struct {
	ViewPubkey *string `json:"view_pubkey"`
}

func (v *ViewPubkeyResponse) HasPubkey() bool {
	return v.ViewPubkey != nil && *v.ViewPubkey != ""
}

// --- Encrypted Balance ---

type EncryptedBalanceResponse struct {
	Cipher string `json:"cipher"`
}

// --- PVAC Pubkey ---

type PvacPubkeyResponse struct {
	PvacPubkey string `json:"pvac_pubkey"`
}

// --- Stealth ---

type StealthOutput struct {
	ID         FlexNumber `json:"id"`
	EphPub     string     `json:"eph_pub"`
	StealthTag string     `json:"stealth_tag"`
	EncAmount  string     `json:"enc_amount"`
	ClaimPub   string     `json:"claim_pub"`
	Claimed    int        `json:"claimed"`
}

type StealthOutputsResponse struct {
	Outputs []StealthOutput `json:"outputs"`
}

// --- Staging ---

type StagingTx struct {
	From  string `json:"from"`
	Nonce int    `json:"nonce"`
}

type StagingResponse struct {
	Transactions []StagingTx `json:"transactions"`
}

// --- Compile ---

type CompileResponse struct {
	Bytecode     string `json:"bytecode"`
	Size         int    `json:"size"`
	Instructions int    `json:"instructions"`
}

type CompileAmlResponse struct {
	Bytecode     string          `json:"bytecode"`
	Size         int             `json:"size"`
	Instructions int             `json:"instructions"`
	Version      string          `json:"version"`
	ABI          json.RawMessage `json:"abi,omitempty"`
}

// --- Contract Address ---

type ContractAddressResponse struct {
	Address  string `json:"address"`
	Deployer string `json:"deployer"`
	Nonce    int    `json:"nonce"`
}

// --- List Contracts ---

type ContractEntry struct {
	Address string `json:"address"`
}

type ListContractsResponse struct {
	Contracts []ContractEntry `json:"contracts"`
}

// --- Contract Storage ---

type StorageResponse struct {
	Value interface{} `json:"value"`
}

func (s *StorageResponse) StringValue() string {
	if s.Value == nil {
		return ""
	}
	switch v := s.Value.(type) {
	case string:
		return v
	default:
		return fmt.Sprintf("%v", v)
	}
}

// --- Transactions by Address ---

type TxRow struct {
	Hash      string     `json:"hash"`
	From      string     `json:"from"`
	To        string     `json:"to"`
	ToField   string     `json:"to_"`
	Amount    FlexNumber `json:"amount"`
	AmountRaw FlexNumber `json:"amount_raw"`
	OpType    string     `json:"op_type"`
	Timestamp float64    `json:"timestamp"`
	Reason    string     `json:"reason,omitempty"`
}

func (t *TxRow) Recipient() string {
	if t.To != "" {
		return t.To
	}
	return t.ToField
}

func (t *TxRow) EffectiveAmountRaw() string {
	if t.Amount != "" {
		return t.Amount.String()
	}
	if t.AmountRaw != "" {
		return t.AmountRaw.String()
	}
	return "0"
}

type TxsByAddressResponse struct {
	Total        int     `json:"total"`
	Transactions []TxRow `json:"transactions"`
	Rejected     []TxRow `json:"rejected"`
}

// --- Fee ---

type FeeResponse struct {
	Minimum     string `json:"minimum"`
	Recommended string `json:"recommended"`
	Fast        string `json:"fast"`
}
