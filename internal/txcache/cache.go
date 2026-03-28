package txcache

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
)

type cacheStore struct {
	Txs    map[string]json.RawMessage `json:"txs"`
	Order  []string                   `json:"order"`
	Totals map[string]int             `json:"totals"`
	Meta   map[string]string          `json:"meta"`
}

type TxCache struct {
	path  string
	store *cacheStore
}

func New() *TxCache {
	return &TxCache{}
}

func (c *TxCache) Open(path string) error {
	os.MkdirAll(filepath.Dir(path), 0700)
	c.path = path
	c.store = &cacheStore{
		Txs:    make(map[string]json.RawMessage),
		Totals: make(map[string]int),
		Meta:   make(map[string]string),
	}
	data, err := os.ReadFile(path)
	if err != nil {
		// New cache, save empty
		return c.save()
	}
	if err := json.Unmarshal(data, c.store); err != nil {
		// Corrupt, reset
		c.store = &cacheStore{
			Txs:    make(map[string]json.RawMessage),
			Totals: make(map[string]int),
			Meta:   make(map[string]string),
		}
	}
	if c.store.Txs == nil {
		c.store.Txs = make(map[string]json.RawMessage)
	}
	if c.store.Totals == nil {
		c.store.Totals = make(map[string]int)
	}
	if c.store.Meta == nil {
		c.store.Meta = make(map[string]string)
	}
	return nil
}

func (c *TxCache) save() error {
	if c.store == nil {
		return nil
	}
	data, err := json.Marshal(c.store)
	if err != nil {
		return err
	}
	return os.WriteFile(c.path, data, 0600)
}

func (c *TxCache) Close() {
	if c.store != nil {
		c.save()
		c.store = nil
		c.path = ""
	}
}

func (c *TxCache) IsOpen() bool {
	return c.store != nil
}

func (c *TxCache) Put(key, val string) {
	if c.store != nil {
		c.store.Meta[key] = val
		c.save()
	}
}

func (c *TxCache) Get(key string) string {
	if c.store == nil {
		return ""
	}
	return c.store.Meta[key]
}

func (c *TxCache) GetTotal(addr string) int {
	if c.store == nil {
		return 0
	}
	return c.store.Totals[addr]
}

func (c *TxCache) SetTotal(addr string, total int) {
	if c.store != nil {
		c.store.Totals[addr] = total
		c.save()
	}
}

func (c *TxCache) HasTx(hash string) bool {
	if c.store == nil {
		return false
	}
	_, ok := c.store.Txs[hash]
	return ok
}

func (c *TxCache) StoreTxs(txs []map[string]interface{}) {
	if c.store == nil {
		return
	}
	type entry struct {
		hash string
		ts   float64
		data json.RawMessage
	}
	var newEntries []entry
	for _, tx := range txs {
		hash, _ := tx["hash"].(string)
		if hash == "" {
			continue
		}
		if _, exists := c.store.Txs[hash]; exists {
			continue
		}
		data, _ := json.Marshal(tx)
		ts := 0.0
		if v, ok := tx["timestamp"].(float64); ok {
			ts = v
		}
		newEntries = append(newEntries, entry{hash, ts, data})
	}
	// Sort new entries by timestamp descending
	sort.Slice(newEntries, func(i, j int) bool {
		return newEntries[i].ts > newEntries[j].ts
	})
	for _, e := range newEntries {
		c.store.Txs[e.hash] = e.data
	}
	// Rebuild order: prepend new hashes
	var newOrder []string
	for _, e := range newEntries {
		newOrder = append(newOrder, e.hash)
	}
	c.store.Order = append(newOrder, c.store.Order...)
	c.save()
}

func (c *TxCache) LoadPage(limit, offset int) []map[string]interface{} {
	if c.store == nil {
		return nil
	}
	var result []map[string]interface{}
	for i := offset; i < len(c.store.Order); i++ {
		hash := c.store.Order[i]
		data, ok := c.store.Txs[hash]
		if !ok {
			continue
		}
		var tx map[string]interface{}
		if json.Unmarshal(data, &tx) == nil {
			result = append(result, tx)
		}
		if limit > 0 && len(result) >= limit {
			break
		}
	}
	return result
}

func (c *TxCache) Clear() {
	if c.store == nil {
		return
	}
	c.store.Txs = make(map[string]json.RawMessage)
	c.store.Order = nil
	c.store.Totals = make(map[string]int)
	c.store.Meta = make(map[string]string)
	c.save()
}

func (c *TxCache) EnsureRPC(rpcURL string) {
	stored := c.Get("meta:rpc_url")
	if stored != rpcURL {
		if stored != "" {
			c.Clear()
		}
		c.Put("meta:rpc_url", rpcURL)
	}
}

