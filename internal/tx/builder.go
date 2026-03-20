package tx

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/protobuffalo/go-octra/internal/crypto"
	"github.com/protobuffalo/go-octra/internal/rpc"
	"github.com/protobuffalo/go-octra/internal/wallet"
)

type Transaction struct {
	From          string
	To            string
	Amount        string
	Nonce         int
	OU            string
	Timestamp     float64
	OpType        string
	Signature     string
	PublicKey     string
	EncryptedData string
	Message       string
}

func NowTS() float64 {
	return float64(time.Now().UnixNano()) / 1e9
}

func jsonEscape(s string) string {
	b, _ := json.Marshal(s)
	// Remove surrounding quotes
	return string(b[1 : len(b)-1])
}

func formatTimestamp(ts float64) string {
	b, _ := json.Marshal(ts)
	return string(b)
}

func CanonicalJSON(tx *Transaction) string {
	opType := tx.OpType
	if opType == "" {
		opType = "standard"
	}
	var sb strings.Builder
	sb.WriteString(`{"from":"`)
	sb.WriteString(jsonEscape(tx.From))
	sb.WriteString(`","to_":"`)
	sb.WriteString(jsonEscape(tx.To))
	sb.WriteString(`","amount":"`)
	sb.WriteString(jsonEscape(tx.Amount))
	sb.WriteString(`","nonce":`)
	sb.WriteString(strconv.Itoa(tx.Nonce))
	sb.WriteString(`,"ou":"`)
	sb.WriteString(jsonEscape(tx.OU))
	sb.WriteString(`","timestamp":`)
	sb.WriteString(formatTimestamp(tx.Timestamp))
	sb.WriteString(`,"op_type":"`)
	sb.WriteString(jsonEscape(opType))
	sb.WriteString(`"`)
	if tx.EncryptedData != "" {
		sb.WriteString(`,"encrypted_data":"`)
		sb.WriteString(jsonEscape(tx.EncryptedData))
		sb.WriteString(`"`)
	}
	if tx.Message != "" {
		sb.WriteString(`,"message":"`)
		sb.WriteString(jsonEscape(tx.Message))
		sb.WriteString(`"`)
	}
	sb.WriteString(`}`)
	return sb.String()
}

func SignTx(tx *Transaction, sk [64]byte, pubB64 string) {
	msg := CanonicalJSON(tx)
	tx.Signature = crypto.Ed25519SignDetached([]byte(msg), sk[:])
	tx.PublicKey = pubB64
}

func SubmitTx(client *rpc.Client, tx *Transaction) (string, error) {
	j := map[string]interface{}{
		"from":      tx.From,
		"to_":       tx.To,
		"amount":    tx.Amount,
		"nonce":     tx.Nonce,
		"ou":        tx.OU,
		"timestamp": tx.Timestamp,
		"signature": tx.Signature,
		"public_key": tx.PublicKey,
	}
	if tx.OpType != "" {
		j["op_type"] = tx.OpType
	}
	if tx.EncryptedData != "" {
		j["encrypted_data"] = tx.EncryptedData
	}
	if tx.Message != "" {
		j["message"] = tx.Message
	}
	r := client.SubmitTx(j)
	if !r.OK {
		return "", fmt.Errorf("%s", r.Error)
	}
	m := r.Map()
	return rpc.MapString(m, "tx_hash", ""), nil
}

type BalanceInfo struct {
	Nonce      int
	BalanceRaw string
}

func GetNonceBalance(client *rpc.Client, w *wallet.Wallet) BalanceInfo {
	r := client.GetBalance(w.Addr)
	if !r.OK {
		return BalanceInfo{0, "0"}
	}
	m := r.Map()
	nonce := rpc.MapInt(m, "pending_nonce", rpc.MapInt(m, "nonce", 0))
	raw := "0"
	if v, ok := m["balance_raw"]; ok {
		switch bv := v.(type) {
		case string:
			raw = bv
		case float64:
			raw = strconv.FormatInt(int64(bv), 10)
		}
	} else if v, ok := m["balance"]; ok {
		switch bv := v.(type) {
		case float64:
			raw = strconv.FormatInt(int64(bv*1000000), 10)
		case string:
			raw = bv
		}
	}

	// Check staging for pending nonce
	pr := client.StagingView()
	if pr.OK {
		var staging struct {
			Transactions []map[string]interface{} `json:"transactions"`
		}
		pr.Unmarshal(&staging)
		for _, stx := range staging.Transactions {
			if rpc.MapString(stx, "from", "") == w.Addr {
				pn := rpc.MapInt(stx, "nonce", 0)
				if pn > nonce {
					nonce = pn
				}
			}
		}
	}
	return BalanceInfo{Nonce: nonce, BalanceRaw: raw}
}

func ParseAmountRaw(amountStr string) (int64, error) {
	if amountStr == "" {
		return -1, fmt.Errorf("empty amount")
	}
	dot := strings.Index(amountStr, ".")
	if dot == -1 {
		for _, c := range amountStr {
			if c < '0' || c > '9' {
				return -1, fmt.Errorf("invalid amount")
			}
		}
		v, err := strconv.ParseInt(amountStr, 10, 64)
		if err != nil {
			return -1, err
		}
		const maxRaw = int64(1000000000) * 1000000
		if v > maxRaw/1000000 {
			return -1, fmt.Errorf("amount too large")
		}
		return v * 1000000, nil
	}
	intPart := amountStr[:dot]
	fracPart := amountStr[dot+1:]
	for _, c := range intPart {
		if c < '0' || c > '9' {
			return -1, fmt.Errorf("invalid amount")
		}
	}
	for _, c := range fracPart {
		if c < '0' || c > '9' {
			return -1, fmt.Errorf("invalid amount")
		}
	}
	if len(fracPart) > 6 {
		fracPart = fracPart[:6]
	}
	for len(fracPart) < 6 {
		fracPart += "0"
	}
	ip := int64(0)
	if intPart != "" {
		var err error
		ip, err = strconv.ParseInt(intPart, 10, 64)
		if err != nil {
			return -1, err
		}
	}
	fp, _ := strconv.ParseInt(fracPart, 10, 64)
	return ip*1000000 + fp, nil
}

func SignBalanceRequest(addr string, sk [64]byte) string {
	msg := "octra_encryptedBalance|" + addr
	return crypto.Ed25519SignDetached([]byte(msg), sk[:])
}

func SignRegisterRequest(addr, pkBlob string, sk [64]byte) string {
	pkHash := crypto.SHA256Hex(pkBlob)
	msg := "register_pvac|" + addr + "|" + pkHash
	return crypto.Ed25519SignDetached([]byte(msg), sk[:])
}
