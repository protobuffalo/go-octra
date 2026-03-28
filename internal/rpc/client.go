package rpc

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync/atomic"
	"time"
)

type Result struct {
	OK    bool
	Data  json.RawMessage
	Error string
}

func (r *Result) Unmarshal(v interface{}) error {
	return json.Unmarshal(r.Data, v)
}

type Client struct {
	url  string
	id   atomic.Int64
	http *http.Client
}

func NewClient(url string) *Client {
	return &Client{
		url: url,
		http: &http.Client{
			Timeout: 60 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        10,
				IdleConnTimeout:     90 * time.Second,
				DisableKeepAlives:   false,
				MaxIdleConnsPerHost: 5,
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

	url := c.url
	if len(url) > 0 && url[len(url)-1] != '/' {
		if len(url) < 4 || url[len(url)-4:] != "/rpc" {
			url += "/rpc"
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return &Result{OK: false, Error: "request error: " + err.Error()}
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
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

// --- Typed RPC methods ---

func (c *Client) GetBalance(addr string) (*BalanceResponse, error) {
	r := c.Call("octra_balance", []interface{}{addr})
	if !r.OK {
		return nil, fmt.Errorf("%s", r.Error)
	}
	var resp BalanceResponse
	if err := r.Unmarshal(&resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) GetTransaction(hash string) (*TransactionResponse, error) {
	r := c.Call("octra_transaction", []interface{}{hash})
	if !r.OK {
		return nil, fmt.Errorf("%s", r.Error)
	}
	var resp TransactionResponse
	if err := r.Unmarshal(&resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) SubmitTx(tx map[string]interface{}) (*SubmitResponse, error) {
	r := c.Call("octra_submit", []interface{}{tx})
	if !r.OK {
		return nil, fmt.Errorf("%s", r.Error)
	}
	var resp SubmitResponse
	if err := r.Unmarshal(&resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) GetViewPubkey(addr string) (*ViewPubkeyResponse, error) {
	r := c.Call("octra_viewPubkey", []interface{}{addr})
	if !r.OK {
		return nil, fmt.Errorf("%s", r.Error)
	}
	var resp ViewPubkeyResponse
	if err := r.Unmarshal(&resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) GetEncryptedBalance(addr, sigB64, pubB64 string) (*EncryptedBalanceResponse, error) {
	r := c.Call("octra_encryptedBalance", []interface{}{addr, sigB64, pubB64})
	if !r.OK {
		return nil, fmt.Errorf("%s", r.Error)
	}
	var resp EncryptedBalanceResponse
	if err := r.Unmarshal(&resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) RegisterPvacPubkey(addr, pkB64, sigB64, pubB64, aesKatHex string) error {
	r := c.Call("octra_registerPvacPubkey", []interface{}{addr, pkB64, sigB64, pubB64, aesKatHex})
	if !r.OK {
		return fmt.Errorf("%s", r.Error)
	}
	return nil
}

func (c *Client) GetPvacPubkey(addr string) (*PvacPubkeyResponse, error) {
	r := c.Call("octra_pvacPubkey", []interface{}{addr})
	if !r.OK {
		return nil, fmt.Errorf("%s", r.Error)
	}
	var resp PvacPubkeyResponse
	if err := r.Unmarshal(&resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) RegisterPublicKey(addr, pubB64, sigB64 string) error {
	r := c.Call("octra_registerPublicKey", []interface{}{addr, pubB64, sigB64})
	if !r.OK {
		return fmt.Errorf("%s", r.Error)
	}
	return nil
}

func (c *Client) GetStealthOutputs(fromEpoch int) (*StealthOutputsResponse, error) {
	r := c.Call("octra_stealthOutputs", []interface{}{fromEpoch})
	if !r.OK {
		return nil, fmt.Errorf("%s", r.Error)
	}
	var resp StealthOutputsResponse
	if err := r.Unmarshal(&resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) StagingView() (*StagingResponse, error) {
	r := c.Call("staging_view", []interface{}{}, 5)
	if !r.OK {
		return nil, fmt.Errorf("%s", r.Error)
	}
	var resp StagingResponse
	if err := r.Unmarshal(&resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) CompileAssembly(source string) (*CompileResponse, error) {
	r := c.Call("octra_compileAssembly", []interface{}{source}, 10)
	if !r.OK {
		return nil, fmt.Errorf("%s", r.Error)
	}
	var resp CompileResponse
	if err := r.Unmarshal(&resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) CompileAml(source string) (*CompileAmlResponse, error) {
	r := c.Call("octra_compileAml", []interface{}{source}, 10)
	if !r.OK {
		return nil, fmt.Errorf("%s", r.Error)
	}
	var resp CompileAmlResponse
	if err := r.Unmarshal(&resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) ComputeContractAddress(bytecodeB64, deployer string, nonce int) (*ContractAddressResponse, error) {
	r := c.Call("octra_computeContractAddress", []interface{}{bytecodeB64, deployer, nonce})
	if !r.OK {
		return nil, fmt.Errorf("%s", r.Error)
	}
	var resp ContractAddressResponse
	if err := r.Unmarshal(&resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// VMContract returns raw JSON (pass-through).
func (c *Client) VMContract(addr string) *Result {
	return c.Call("vm_contract", []interface{}{addr})
}

// ContractReceipt returns raw JSON (pass-through).
func (c *Client) ContractReceipt(hash string) *Result {
	return c.Call("contract_receipt", []interface{}{hash})
}

// ContractCallView returns raw JSON (response shape varies by contract).
func (c *Client) ContractCallView(addr, method string, params interface{}, caller string) *Result {
	return c.Call("contract_call", []interface{}{addr, method, params, caller}, 15)
}

func (c *Client) ListContracts() (*ListContractsResponse, error) {
	r := c.Call("octra_listContracts", []interface{}{}, 10)
	if !r.OK {
		return nil, fmt.Errorf("%s", r.Error)
	}
	var resp ListContractsResponse
	if err := r.Unmarshal(&resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) ContractStorage(addr, key string) (*StorageResponse, error) {
	r := c.Call("octra_contractStorage", []interface{}{addr, key})
	if !r.OK {
		return nil, fmt.Errorf("%s", r.Error)
	}
	var resp StorageResponse
	if err := r.Unmarshal(&resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) GetTxsByAddress(addr string, limit, offset int) (*TxsByAddressResponse, error) {
	r := c.Call("octra_transactionsByAddress", []interface{}{addr, limit, offset}, 15)
	if !r.OK {
		return nil, fmt.Errorf("%s", r.Error)
	}
	var resp TxsByAddressResponse
	if err := r.Unmarshal(&resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) RecommendedFee(opType string) (*FeeResponse, error) {
	r := c.Call("octra_recommendedFee", []interface{}{opType}, 5)
	if !r.OK {
		return nil, fmt.Errorf("%s", r.Error)
	}
	var resp FeeResponse
	if err := r.Unmarshal(&resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ContractVerify returns raw JSON (pass-through).
func (c *Client) ContractVerify(addr, source string) *Result {
	return c.Call("contract_verify", []interface{}{addr, source}, 15)
}
