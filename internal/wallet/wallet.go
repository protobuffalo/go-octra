package wallet

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/protobuffalo/go-octra/internal/crypto"
)

const (
	WalletDir    = "data"
	WalletFile   = "data/wallet.oct"
	WalletLegacy = "wallet.json"
	ManifestFile = "data/accounts.json"
)

type Wallet struct {
	PrivB64       string   `json:"priv"`
	Addr          string   `json:"addr"`
	RPCURL        string   `json:"rpc"`
	ExplorerURL   string   `json:"explorer"`
	SK            [64]byte `json:"-"`
	PK            [32]byte `json:"-"`
	PubB64        string   `json:"-"`
	MasterSeedB64 string   `json:"master_seed,omitempty"`
	Mnemonic      string   `json:"mnemonic,omitempty"`
	HDIndex       int      `json:"hd_index,omitempty"`
	HDVersion     int      `json:"hd_version,omitempty"`
}

func (w *Wallet) HasMasterSeed() bool {
	return w.MasterSeedB64 != ""
}

type ManifestEntry struct {
	Name           string `json:"name"`
	File           string `json:"file"`
	Addr           string `json:"addr"`
	HD             bool   `json:"hd"`
	HDVersion      int    `json:"hd_version"`
	HDIndex        int    `json:"hd_index"`
	ParentAddr     string `json:"parent_addr,omitempty"`
	MasterSeedHash string `json:"seed_hash,omitempty"`
}

func EnsureDataDir() {
	os.MkdirAll(WalletDir, 0700)
}

func WalletPathFor(addr string) string {
	prefix := "unknown"
	if len(addr) > 11 {
		prefix = addr[3:11]
	}
	return filepath.Join(WalletDir, "wallet_"+prefix+".oct")
}

func HasEncryptedWallet() bool {
	_, err := os.Stat(WalletFile)
	return err == nil
}

func HasLegacyWallet() bool {
	_, err := os.Stat(WalletLegacy)
	return err == nil
}

func LoadManifest() []ManifestEntry {
	data, err := os.ReadFile(ManifestFile)
	if err != nil {
		return nil
	}
	var entries []ManifestEntry
	json.Unmarshal(data, &entries)
	return entries
}

func SaveManifest(entries []ManifestEntry) {
	EnsureDataDir()
	data, _ := json.MarshalIndent(entries, "", "  ")
	os.WriteFile(ManifestFile, data, 0600)
}

func ManifestUpsert(entry ManifestEntry) {
	entries := LoadManifest()
	found := false
	for i := range entries {
		if entries[i].Addr == entry.Addr {
			if entry.Name != "" {
				entries[i].Name = entry.Name
			}
			entries[i].File = entry.File
			entries[i].HD = entry.HD
			entries[i].HDVersion = entry.HDVersion
			entries[i].HDIndex = entry.HDIndex
			if entry.ParentAddr != "" {
				entries[i].ParentAddr = entry.ParentAddr
			}
			if entry.MasterSeedHash != "" {
				entries[i].MasterSeedHash = entry.MasterSeedHash
			}
			found = true
			break
		}
	}
	if !found {
		entries = append(entries, entry)
	}
	SaveManifest(entries)
}

func ManifestRemove(addr string) {
	entries := LoadManifest()
	var filtered []ManifestEntry
	for _, e := range entries {
		if e.Addr != addr {
			filtered = append(filtered, e)
		}
	}
	SaveManifest(filtered)
}

func ManifestRename(addr, name string) {
	entries := LoadManifest()
	for i := range entries {
		if entries[i].Addr == addr {
			entries[i].Name = name
			break
		}
	}
	SaveManifest(entries)
}

func ManifestNextHDIndex(masterSeedB64 string) int {
	sh := crypto.ComputeSeedHash(masterSeedB64)
	entries := LoadManifest()
	maxIdx := -1
	for _, e := range entries {
		if e.HD && e.MasterSeedHash == sh && e.HDIndex > maxIdx {
			maxIdx = e.HDIndex
		}
	}
	return maxIdx + 1
}

func SaveWalletEncrypted(path string, w *Wallet, pin string) error {
	EnsureDataDir()
	j := map[string]interface{}{
		"priv":     w.PrivB64,
		"addr":     w.Addr,
		"rpc":      w.RPCURL,
		"explorer": w.ExplorerURL,
	}
	if w.MasterSeedB64 != "" {
		j["master_seed"] = w.MasterSeedB64
		j["hd_index"] = w.HDIndex
		j["hd_version"] = w.HDVersion
		if w.Mnemonic != "" {
			j["mnemonic"] = w.Mnemonic
		}
	}
	plaintext, _ := json.Marshal(j)
	enc, err := crypto.WalletEncrypt(plaintext, pin)
	crypto.SecureZero(plaintext)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, enc, 0600); err != nil {
		return err
	}
	return nil
}

func LoadWalletEncrypted(path, pin string) (*Wallet, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.New("cannot open wallet file")
	}
	plain, err := crypto.WalletDecrypt(data, pin)
	if err != nil {
		return nil, errors.New("wrong pin")
	}
	var j map[string]interface{}
	if err := json.Unmarshal(plain, &j); err != nil {
		return nil, errors.New("corrupt wallet data")
	}
	crypto.SecureZero(plain)

	w := &Wallet{}
	w.PrivB64 = j["priv"].(string)
	w.Addr = j["addr"].(string)
	if v, ok := j["rpc"].(string); ok {
		w.RPCURL = v
	} else {
		w.RPCURL = "http://46.101.86.250:8080"
	}
	if v, ok := j["explorer"].(string); ok {
		w.ExplorerURL = v
	} else {
		w.ExplorerURL = "https://octrascan.io"
	}
	if v, ok := j["master_seed"].(string); ok {
		w.MasterSeedB64 = v
	}
	if v, ok := j["mnemonic"].(string); ok {
		w.Mnemonic = v
	}
	if v, ok := j["hd_index"].(float64); ok {
		w.HDIndex = int(v)
	}
	if v, ok := j["hd_version"].(float64); ok {
		w.HDVersion = int(v)
	}

	raw, err := crypto.Base64Decode(w.PrivB64)
	if err != nil {
		return nil, errors.New("invalid private key encoding")
	}
	if len(raw) >= 64 {
		copy(w.SK[:], raw[:64])
		copy(w.PK[:], raw[32:64])
	} else if len(raw) >= 32 {
		w.SK, w.PK = crypto.KeypairFromSeed(raw[:32])
	} else {
		return nil, errors.New("invalid private key")
	}
	w.PubB64 = crypto.Base64Encode(w.PK[:])
	return w, nil
}

func CreateWallet(path, pin string) (*Wallet, string, error) {
	mnemonic := crypto.GenerateMnemonic12()
	seed := crypto.MnemonicToSeed(mnemonic)
	hdSeed := crypto.DeriveHDSeed(seed[:], 0, 2)
	w := &Wallet{}
	w.SK, w.PK = crypto.KeypairFromSeed(hdSeed[:])
	w.Addr = crypto.DeriveAddress(w.PK)
	if len(w.Addr) != 47 || w.Addr[:3] != "oct" {
		return nil, "", errors.New("derived address is invalid")
	}
	w.PrivB64 = crypto.Base64Encode(w.SK[:32])
	w.PubB64 = crypto.Base64Encode(w.PK[:])
	w.RPCURL = "http://46.101.86.250:8080"
	w.ExplorerURL = "https://octrascan.io"
	w.MasterSeedB64 = crypto.Base64Encode(seed[:])
	w.Mnemonic = mnemonic
	w.HDIndex = 0
	w.HDVersion = 2
	if err := SaveWalletEncrypted(path, w, pin); err != nil {
		return nil, "", err
	}
	return w, mnemonic, nil
}

func ImportWalletMnemonic(path, mnemonic, pin string, hdVersion int) (*Wallet, error) {
	if !crypto.ValidateMnemonic(mnemonic) {
		return nil, errors.New("invalid seed phrase")
	}
	seed := crypto.MnemonicToSeed(mnemonic)
	hdSeed := crypto.DeriveHDSeed(seed[:], 0, hdVersion)
	w := &Wallet{}
	w.SK, w.PK = crypto.KeypairFromSeed(hdSeed[:])
	w.Addr = crypto.DeriveAddress(w.PK)
	if len(w.Addr) != 47 || w.Addr[:3] != "oct" {
		return nil, errors.New("derived address is invalid")
	}
	w.PrivB64 = crypto.Base64Encode(w.SK[:32])
	w.PubB64 = crypto.Base64Encode(w.PK[:])
	w.RPCURL = "http://46.101.86.250:8080"
	w.ExplorerURL = "https://octrascan.io"
	w.MasterSeedB64 = crypto.Base64Encode(seed[:])
	w.Mnemonic = mnemonic
	w.HDIndex = 0
	w.HDVersion = hdVersion
	if err := SaveWalletEncrypted(path, w, pin); err != nil {
		return nil, err
	}
	return w, nil
}

func ImportWalletPrivkey(path, privB64Raw, pin string) (*Wallet, error) {
	clean := strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == ' ' || r == '\t' {
			return -1
		}
		return r
	}, privB64Raw)
	raw, err := crypto.Base64Decode(clean)
	if err != nil {
		return nil, errors.New("invalid base64")
	}
	w := &Wallet{}
	if len(raw) >= 64 {
		copy(w.SK[:], raw[:64])
		copy(w.PK[:], raw[32:64])
	} else if len(raw) >= 32 {
		w.SK, w.PK = crypto.KeypairFromSeed(raw[:32])
	} else {
		return nil, errors.New("invalid private key length")
	}
	w.Addr = crypto.DeriveAddress(w.PK)
	if len(w.Addr) != 47 || w.Addr[:3] != "oct" {
		return nil, errors.New("derived address is invalid")
	}
	w.PrivB64 = crypto.Base64Encode(w.SK[:32])
	w.PubB64 = crypto.Base64Encode(w.PK[:])
	w.RPCURL = "http://46.101.86.250:8080"
	w.ExplorerURL = "https://octrascan.io"
	if err := SaveWalletEncrypted(path, w, pin); err != nil {
		return nil, err
	}
	return w, nil
}

func AddrFromMnemonic(mnemonic string, hdVersion int) string {
	seed := crypto.MnemonicToSeed(mnemonic)
	hdSeed := crypto.DeriveHDSeed(seed[:], 0, hdVersion)
	_, pk := crypto.KeypairFromSeed(hdSeed[:])
	return crypto.DeriveAddress(pk)
}

func DeriveHDAccount(masterSeedB64 string, index uint32, rpcURL, explorerURL, pin string, hdVersion int) (*Wallet, error) {
	masterRaw, err := crypto.Base64Decode(masterSeedB64)
	if err != nil || len(masterRaw) != 64 {
		return nil, errors.New("invalid master seed")
	}
	hdSeed := crypto.DeriveHDSeed(masterRaw, index, hdVersion)
	w := &Wallet{}
	w.SK, w.PK = crypto.KeypairFromSeed(hdSeed[:])
	w.Addr = crypto.DeriveAddress(w.PK)
	if len(w.Addr) != 47 || w.Addr[:3] != "oct" {
		return nil, errors.New("derived address is invalid")
	}
	w.PrivB64 = crypto.Base64Encode(w.SK[:32])
	w.PubB64 = crypto.Base64Encode(w.PK[:])
	w.RPCURL = rpcURL
	w.ExplorerURL = explorerURL
	w.MasterSeedB64 = masterSeedB64
	w.HDIndex = int(index)
	w.HDVersion = hdVersion
	path := WalletPathFor(w.Addr)
	if err := SaveWalletEncrypted(path, w, pin); err != nil {
		return nil, err
	}
	return w, nil
}

func ScanAndMergeOctFiles() []ManifestEntry {
	entries := LoadManifest()
	knownFiles := make(map[string]bool)
	for _, e := range entries {
		knownFiles[e.File] = true
	}
	files, err := os.ReadDir(WalletDir)
	if err != nil {
		return entries
	}
	for _, f := range files {
		name := f.Name()
		if len(name) < 5 || name[len(name)-4:] != ".oct" {
			continue
		}
		if strings.Contains(name, ".tmp") {
			continue
		}
		path := filepath.Join(WalletDir, name)
		if knownFiles[path] {
			continue
		}
		entries = append(entries, ManifestEntry{
			File: path,
		})
	}
	return entries
}
