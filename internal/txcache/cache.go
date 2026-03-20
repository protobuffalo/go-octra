package txcache

import (
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/util"
)

type TxCache struct {
	db   *leveldb.DB
	path string
}

func New() *TxCache {
	return &TxCache{}
}

func (c *TxCache) Open(path string) error {
	db, err := leveldb.OpenFile(path, nil)
	if err != nil {
		return err
	}
	c.db = db
	c.path = path
	return nil
}

func (c *TxCache) Close() {
	if c.db != nil {
		c.db.Close()
		c.db = nil
		c.path = ""
	}
}

func (c *TxCache) IsOpen() bool {
	return c.db != nil
}

func (c *TxCache) Put(key, val string) {
	if c.db != nil {
		c.db.Put([]byte(key), []byte(val), nil)
	}
}

func (c *TxCache) Get(key string) string {
	if c.db == nil {
		return ""
	}
	val, err := c.db.Get([]byte(key), nil)
	if err != nil {
		return ""
	}
	return string(val)
}

func (c *TxCache) GetTotal(addr string) int {
	v := c.Get("total:" + addr)
	if v == "" {
		return 0
	}
	n, _ := strconv.Atoi(v)
	return n
}

func (c *TxCache) SetTotal(addr string, total int) {
	c.Put("total:"+addr, strconv.Itoa(total))
}

func (c *TxCache) HasTx(hash string) bool {
	if c.db == nil {
		return false
	}
	has, _ := c.db.Has([]byte("tx:"+hash), nil)
	return has
}

func (c *TxCache) StoreTxs(txs []map[string]interface{}) {
	if c.db == nil {
		return
	}
	batch := new(leveldb.Batch)
	for _, tx := range txs {
		hash, _ := tx["hash"].(string)
		if hash == "" {
			continue
		}
		data, _ := json.Marshal(tx)
		batch.Put([]byte("tx:"+hash), data)
		ts := 0.0
		if v, ok := tx["timestamp"].(float64); ok {
			ts = v
		}
		idx := fmt.Sprintf("idx:%020.6f:%s", 9999999999.0-ts, hash)
		batch.Put([]byte(idx), []byte(hash))
	}
	c.db.Write(batch, nil)
}

func (c *TxCache) LoadPage(limit, offset int) []map[string]interface{} {
	if c.db == nil {
		return nil
	}
	iter := c.db.NewIterator(util.BytesPrefix([]byte("idx:")), nil)
	defer iter.Release()

	var result []map[string]interface{}
	pos := 0
	for iter.Next() {
		if pos < offset {
			pos++
			continue
		}
		hash := string(iter.Value())
		val, err := c.db.Get([]byte("tx:"+hash), nil)
		if err == nil {
			var tx map[string]interface{}
			if json.Unmarshal(val, &tx) == nil {
				result = append(result, tx)
			}
		}
		pos++
		if limit > 0 && (pos-offset) >= limit {
			break
		}
	}
	return result
}

func (c *TxCache) Clear() {
	if c.db == nil {
		return
	}
	p := c.path
	c.Close()
	if p != "" {
		// Destroy and reopen
		leveldb.RecoverFile(p, nil)
		c.Open(p)
	}
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
