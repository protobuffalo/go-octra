package stealth

import (
	"encoding/binary"
	"errors"

	"github.com/protobuffalo/go-octra/internal/crypto"
	"github.com/protobuffalo/go-octra/internal/nacl"
)

func ECDHSharedSecret(ourSK, theirPub []byte) [32]byte {
	raw := make([]byte, 32)
	nacl.CryptoScalarmult(raw, ourSK, theirPub)
	return crypto.SHA256(raw)
}

func ComputeStealthTag(shared [32]byte) [16]byte {
	domain := []byte("OCTRA_STEALTH_TAG_V1")
	buf := make([]byte, 32+len(domain))
	copy(buf[:32], shared[:])
	copy(buf[32:], domain)
	h := crypto.SHA256(buf)
	var tag [16]byte
	copy(tag[:], h[:16])
	return tag
}

func ComputeClaimSecret(shared [32]byte) [32]byte {
	domain := []byte("OCTRA_CLAIM_SECRET_V1")
	buf := make([]byte, 32+len(domain))
	copy(buf[:32], shared[:])
	copy(buf[32:], domain)
	return crypto.SHA256(buf)
}

func ComputeClaimPub(claimSecret [32]byte, addr string) [32]byte {
	domain := []byte("OCTRA_CLAIM_BIND_V1")
	buf := make([]byte, 32+len(addr)+len(domain))
	copy(buf[:32], claimSecret[:])
	copy(buf[32:], []byte(addr))
	copy(buf[32+len(addr):], domain)
	return crypto.SHA256(buf)
}

func EncryptStealthAmount(shared [32]byte, amount uint64, blinding [32]byte) (string, error) {
	plaintext := make([]byte, 40)
	binary.LittleEndian.PutUint64(plaintext[:8], amount)
	copy(plaintext[8:], blinding[:])

	ct, err := crypto.AESGCMEncrypt(shared[:], plaintext)
	if err != nil {
		return "", err
	}
	return crypto.Base64Encode(ct), nil
}

type StealthDecrypted struct {
	Amount   uint64
	Blinding [32]byte
}

func DecryptStealthAmount(shared [32]byte, encB64 string) (*StealthDecrypted, error) {
	raw, err := crypto.Base64Decode(encB64)
	if err != nil {
		return nil, err
	}
	plaintext, err := crypto.AESGCMDecrypt(shared[:], raw)
	if err != nil {
		return nil, errors.New("decrypt failed")
	}
	if len(plaintext) != 40 {
		return nil, errors.New("invalid plaintext length")
	}
	result := &StealthDecrypted{
		Amount: binary.LittleEndian.Uint64(plaintext[:8]),
	}
	copy(result.Blinding[:], plaintext[8:])
	return result, nil
}

func DeriveViewKeypair(edSK []byte) (viewSK [32]byte, viewPK [32]byte) {
	viewSK = crypto.Ed25519SKToCurve25519(edSK)
	vpk := make([]byte, 32)
	nacl.CryptoScalarmultBase(vpk, viewSK[:])
	copy(viewPK[:], vpk)
	return
}
