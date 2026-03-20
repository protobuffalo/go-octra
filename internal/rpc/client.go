package rpc

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync/atomic"
	"time"
)

type Result struct {
	OK     bool
	Data   json.RawMessage
	Error  string
}

func (r *Result) Unmarshal(v interface{}) error {
	return json.Unmarshal(r.Data, v)
}

func (r *Result) Map() map[string]interface{} {
	var m map[string]interface{}
	json.Unmarshal(r.Data, &m)
	return m
}

type Client struct {
	url string
	id  atomic.Int64
	http *http.Client
}

func NewClient(url string) *Client {
	return &Client{
		url: url,
		http: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		},
	}
}

func (c *Client) SetURL(url string) {
	c.url = url
}

func (c *Client) URL() string {
	return c.url
}

func (c *Client) Call(method string, params interface{}, timeoutSec ...int) *Result {
	if params == nil {
		params = []interface{}{}
	}
	reqBody := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  method,
		"params":  params,
		"id":      c.id.Add(1),
	}
	body, _ := json.Marshal(reqBody)

	timeout := 30 * time.Second
	if len(timeoutSec) > 0 && timeoutSec[0] > 0 {
		timeout = time.Duration(timeoutSec[0]) * time.Second
	}

	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	url := c.url
	if url[len(url)-1] != '/' {
		// ensure /rpc path if not present
		if len(url) < 4 || url[len(url)-4:] != "/rpc" {
			url += "/rpc"
		}
	}

	resp, err := client.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return &Result{OK: false, Error: "connection failed: " + err.Error()}
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return &Result{OK: false, Error: "read error: " + err.Error()}
	}

	var rpcResp struct {
		Result json.RawMessage `json:"result"`
		Error  interface{}     `json:"error"`
	}
	if err := json.Unmarshal(respBody, &rpcResp); err != nil {
		return &Result{OK: false, Error: "parse error: " + err.Error()}
	}

	if rpcResp.Error != nil {
		errMsg := "rpc error"
		switch e := rpcResp.Error.(type) {
		case map[string]interface{}:
			if msg, ok := e["message"].(string); ok {
				errMsg = msg
			}
		case string:
			errMsg = e
		default:
			b, _ := json.Marshal(e)
			errMsg = string(b)
		}
		return &Result{OK: false, Error: errMsg}
	}

	if rpcResp.Result != nil {
		return &Result{OK: true, Data: rpcResp.Result}
	}

	return &Result{OK: false, Error: "unknown rpc response"}
}

// Convenience methods

func (c *Client) GetBalance(addr string) *Result {
	return c.Call("octra_balance", []interface{}{addr})
}

func (c *Client) GetAccount(addr string, limit int) *Result {
	return c.Call("octra_account", []interface{}{addr, limit})
}

func (c *Client) GetTransaction(hash string) *Result {
	return c.Call("octra_transaction", []interface{}{hash})
}

func (c *Client) SubmitTx(tx map[string]interface{}) *Result {
	return c.Call("octra_submit", []interface{}{tx})
}

func (c *Client) GetViewPubkey(addr string) *Result {
	return c.Call("octra_viewPubkey", []interface{}{addr})
}

func (c *Client) GetEncryptedBalance(addr, sigB64, pubB64 string) *Result {
	return c.Call("octra_encryptedBalance", []interface{}{addr, sigB64, pubB64})
}

func (c *Client) GetEncryptedCipher(addr string) *Result {
	return c.Call("octra_encryptedCipher", []interface{}{addr})
}

func (c *Client) RegisterPvacPubkey(addr, pkB64, sigB64, pubB64, aesKatHex string) *Result {
	return c.Call("octra_registerPvacPubkey", []interface{}{addr, pkB64, sigB64, pubB64, aesKatHex})
}

func (c *Client) GetPvacPubkey(addr string) *Result {
	return c.Call("octra_pvacPubkey", []interface{}{addr})
}

func (c *Client) RegisterPublicKey(addr, pubB64, sigB64 string) *Result {
	return c.Call("octra_registerPublicKey", []interface{}{addr, pubB64, sigB64})
}

func (c *Client) GetStealthOutputs(fromEpoch int) *Result {
	return c.Call("octra_stealthOutputs", []interface{}{fromEpoch})
}

func (c *Client) StagingView() *Result {
	return c.Call("staging_view", []interface{}{}, 5)
}

func (c *Client) CompileAssembly(source string) *Result {
	return c.Call("octra_compileAssembly", []interface{}{source}, 10)
}

func (c *Client) CompileAml(source string) *Result {
	return c.Call("octra_compileAml", []interface{}{source}, 10)
}

func (c *Client) ComputeContractAddress(bytecodeB64, deployer string, nonce int) *Result {
	return c.Call("octra_computeContractAddress", []interface{}{bytecodeB64, deployer, nonce})
}

func (c *Client) VMContract(addr string) *Result {
	return c.Call("vm_contract", []interface{}{addr})
}

func (c *Client) ContractReceipt(hash string) *Result {
	return c.Call("contract_receipt", []interface{}{hash})
}

func (c *Client) ContractCallView(addr, method string, params interface{}, caller string) *Result {
	return c.Call("contract_call", []interface{}{addr, method, params, caller}, 15)
}

func (c *Client) ListContracts() *Result {
	return c.Call("octra_listContracts", []interface{}{}, 10)
}

func (c *Client) ContractStorage(addr, key string) *Result {
	return c.Call("octra_contractStorage", []interface{}{addr, key})
}

func (c *Client) ContractAbi(addr string) *Result {
	return c.Call("octra_contractAbi", []interface{}{addr})
}

func (c *Client) SaveAbi(addr, abi string) *Result {
	return c.Call("contract_saveAbi", []interface{}{addr, abi})
}

func (c *Client) GetTxsByAddress(addr string, limit, offset int) *Result {
	return c.Call("octra_transactionsByAddress", []interface{}{addr, limit, offset}, 15)
}

func (c *Client) RecommendedFee(opType string) *Result {
	return c.Call("octra_recommendedFee", []interface{}{opType}, 5)
}

func (c *Client) ContractVerify(addr, source string) *Result {
	return c.Call("contract_verify", []interface{}{addr, source}, 15)
}

func MapString(m map[string]interface{}, key, def string) string {
	if v, ok := m[key]; ok && v != nil {
		if s, ok := v.(string); ok {
			return s
		}
		return fmt.Sprintf("%v", v)
	}
	return def
}

func MapInt(m map[string]interface{}, key string, def int) int {
	if v, ok := m[key]; ok {
		switch n := v.(type) {
		case float64:
			return int(n)
		case int:
			return n
		}
	}
	return def
}

func MapFloat(m map[string]interface{}, key string, def float64) float64 {
	if v, ok := m[key]; ok {
		if n, ok := v.(float64); ok {
			return n
		}
	}
	return def
}
