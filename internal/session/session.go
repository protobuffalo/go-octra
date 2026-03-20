package session

import (
	"fmt"
	"strings"

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
	cacheDir := "data/txcache_" + w.Addr[3:11]
	if err := s.Cache.Open(cacheDir); err != nil {
		fmt.Printf("txcache open failed: %s\n", err)
	} else {
		s.Cache.EnsureRPC(w.RPCURL)
	}

	return s, nil
}

func (s *Session) EnsurePubkeyRegistered() {
	vr := s.RPC.GetViewPubkey(s.Wallet.Addr)
	if vr.OK {
		m := vr.Map()
		if vp, ok := m["view_pubkey"]; ok && vp != nil {
			if _, ok := vp.(string); ok {
				return
			}
		}
	}
	msg := "register_pubkey:" + s.Wallet.Addr
	sig := crypto.Ed25519SignDetached([]byte(msg), s.Wallet.SK[:])
	rr := s.RPC.RegisterPublicKey(s.Wallet.Addr, s.Wallet.PubB64, sig)
	if rr.OK {
		fmt.Printf("pubkey registered for %s\n", s.Wallet.Addr)
	}
}

func (s *Session) EnsurePvacRegistered() {
	if s.PvacConfirmed || s.PvacForeign {
		return
	}

	pr := s.RPC.GetPvacPubkey(s.Wallet.Addr)
	if pr.OK {
		m := pr.Map()
		remotePK := rpc.MapString(m, "pvac_pubkey", "")
		if remotePK != "" {
			localPK := s.Pvac.SerializePubkeyB64()
			if remotePK == localPK {
				s.PvacConfirmed = true
				return
			}
			s.PvacForeign = true
			return
		}
	}

	// Register PVAC pubkey
	pkRaw := s.Pvac.SerializePubkey()
	pkBlob := string(pkRaw)
	pkB64 := s.Pvac.SerializePubkeyB64()
	regSig := tx.SignRegisterRequest(s.Wallet.Addr, pkBlob, s.Wallet.SK)
	aesKat := s.Pvac.AESKatHex()
	rr := s.RPC.RegisterPvacPubkey(s.Wallet.Addr, pkB64, regSig, s.Wallet.PubB64, aesKat)
	if rr.OK {
		s.PvacConfirmed = true
	} else {
		if strings.Contains(rr.Error, "already registered") {
			s.PvacForeign = true
		}
	}
}

func (s *Session) GetEncryptedBalance() (cipher string, decrypted int64) {
	sig := tx.SignBalanceRequest(s.Wallet.Addr, s.Wallet.SK)
	er := s.RPC.GetEncryptedBalance(s.Wallet.Addr, sig, s.Wallet.PubB64)
	if !er.OK {
		return "0", 0
	}
	m := er.Map()
	cipher = rpc.MapString(m, "cipher", "0")
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
