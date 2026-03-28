package session

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/protobuffalo/go-octra/internal/config"
	"github.com/protobuffalo/go-octra/internal/crypto"
	"github.com/protobuffalo/go-octra/internal/pvac"
	"github.com/protobuffalo/go-octra/internal/rpc"
	"github.com/protobuffalo/go-octra/internal/tx"
	"github.com/protobuffalo/go-octra/internal/txcache"
	"github.com/protobuffalo/go-octra/internal/wallet"
)

type Session struct {
	Wallet        *wallet.Wallet
	WalletPath    string
	Pin           string
	RPC           *rpc.Client
	Cache         *txcache.TxCache
	Pvac          *pvac.Bridge
	PvacConfirmed bool
	PvacForeign   bool
}

func Load(walletPath, pin string) (*Session, error) {
	w, err := wallet.LoadWalletEncrypted(walletPath, pin)
	if err != nil {
		return nil, err
	}

	s := &Session{
		Wallet:     w,
		WalletPath: walletPath,
		Pin:        pin,
		RPC:        rpc.NewClient(w.RPCURL),
		Cache:      txcache.New(),
		Pvac:       pvac.NewBridge(),
	}

	// Register public key
	s.EnsurePubkeyRegistered()

	// Initialize PVAC
	if !s.Pvac.Init(w.PrivB64) {
		fmt.Println("Warning: PVAC initialization failed")
	} else {
		s.EnsurePvacRegistered()
	}

	// Open tx cache
	cachePath := filepath.Join(config.Load().TxCacheDir(), w.Addr[3:11]+".json")
	if err := s.Cache.Open(cachePath); err != nil {
		fmt.Printf("txcache open failed: %s\n", err)
	} else {
		s.Cache.EnsureRPC(w.RPCURL)
	}

	return s, nil
}

func (s *Session) EnsurePubkeyRegistered() {
	vr, err := s.RPC.GetViewPubkey(s.Wallet.Addr)
	if err == nil && vr.HasPubkey() {
		return
	}
	msg := "register_pubkey:" + s.Wallet.Addr
	sig := crypto.Ed25519SignDetached([]byte(msg), s.Wallet.SK[:])
	if err := s.RPC.RegisterPublicKey(s.Wallet.Addr, s.Wallet.PubB64, sig); err == nil {
		fmt.Printf("pubkey registered for %s\n", s.Wallet.Addr)
	}
}

func (s *Session) EnsurePvacRegistered() {
	if s.PvacConfirmed || s.PvacForeign {
		return
	}

	pr, err := s.RPC.GetPvacPubkey(s.Wallet.Addr)
	if err == nil && pr.PvacPubkey != "" {
		localPK := s.Pvac.SerializePubkeyB64()
		if pr.PvacPubkey == localPK {
			s.PvacConfirmed = true
			return
		}
		s.PvacForeign = true
		return
	}

	// Register PVAC pubkey
	pkRaw := s.Pvac.SerializePubkey()
	pkBlob := string(pkRaw)
	pkB64 := s.Pvac.SerializePubkeyB64()
	regSig := tx.SignRegisterRequest(s.Wallet.Addr, pkBlob, s.Wallet.SK)
	aesKat := s.Pvac.AESKatHex()
	err = s.RPC.RegisterPvacPubkey(s.Wallet.Addr, pkB64, regSig, s.Wallet.PubB64, aesKat)
	if err == nil {
		s.PvacConfirmed = true
	} else {
		if strings.Contains(err.Error(), "already registered") {
			s.PvacForeign = true
		}
	}
}

func (s *Session) GetEncryptedBalance() (cipher string, decrypted int64) {
	sig := tx.SignBalanceRequest(s.Wallet.Addr, s.Wallet.SK)
	er, err := s.RPC.GetEncryptedBalance(s.Wallet.Addr, sig, s.Wallet.PubB64)
	if err != nil {
		return "0", 0
	}
	cipher = er.Cipher
	if cipher == "" || cipher == "0" {
		return cipher, 0
	}
	decrypted = s.Pvac.GetBalance(cipher)
	return cipher, decrypted
}

func (s *Session) Close() {
	if s.Cache != nil {
		s.Cache.Close()
	}
	if s.Pvac != nil {
		s.Pvac.Reset()
	}
	if s.Wallet != nil {
		crypto.SecureZero(s.Wallet.SK[:])
		crypto.SecureZero(s.Wallet.PK[:])
	}
	if s.Pin != "" {
		s.Pin = ""
	}
}
