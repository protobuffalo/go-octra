package pvac

/*
#cgo amd64 CXXFLAGS: -I${SRCDIR}/clib -I${SRCDIR}/include -std=c++17 -O2 -maes
#cgo arm64 CXXFLAGS: -I${SRCDIR}/clib -I${SRCDIR}/include -std=c++17 -O2 -march=armv8-a+crypto
#cgo LDFLAGS: -lstdc++ -lm
#include "clib/pvac_c_api.h"
#include <stdlib.h>
*/
import "C"
import (
	"fmt"
	"unsafe"

	"github.com/protobuffalo/go-octra/internal/crypto"
)

// Handle is an opaque reference to a PVAC object (cipher, proof, etc.)
type Handle uintptr

type Bridge struct {
	pk C.pvac_pubkey
	sk C.pvac_seckey
}

func NewBridge() *Bridge {
	return &Bridge{}
}

func (b *Bridge) Init(privB64 string) bool {
	raw, err := crypto.Base64Decode(privB64)
	if err != nil || len(raw) < 32 {
		return false
	}
	var seed [32]byte
	copy(seed[:], raw[:32])
	prm := C.pvac_default_params()
	C.pvac_keygen_from_seed(prm, (*C.uint8_t)(unsafe.Pointer(&seed[0])), &b.pk, &b.sk)
	C.pvac_free_params(prm)
	return b.pk != nil && b.sk != nil
}

func (b *Bridge) Reset() {
	if b.pk != nil {
		C.pvac_free_pubkey(b.pk)
		b.pk = nil
	}
	if b.sk != nil {
		C.pvac_free_seckey(b.sk)
		b.sk = nil
	}
}

func (b *Bridge) GetBalance(cipherStr string) int64 {
	if cipherStr == "" || cipherStr == "0" {
		return 0
	}
	ct := b.decodeCipherC(cipherStr)
	if ct == nil {
		return 0
	}
	defer C.pvac_free_cipher(ct)
	var clo, chi C.uint64_t
	C.pvac_dec_value_fp(b.pk, b.sk, ct, &clo, &chi)
	if chi == 0 {
		return int64(clo)
	}
	return int64(clo)
}

func (b *Bridge) Encrypt(value uint64, seed [32]byte) Handle {
	ct := C.pvac_enc_value_seeded(b.pk, b.sk, C.uint64_t(value),
		(*C.uint8_t)(unsafe.Pointer(&seed[0])))
	return Handle(uintptr(ct))
}

func (b *Bridge) CTSub(a, bh Handle) Handle {
	ct := C.pvac_ct_sub(b.pk, toC(a), toC(bh))
	return Handle(uintptr(ct))
}

func (b *Bridge) CommitCT(ct Handle) [32]byte {
	var out [32]byte
	C.pvac_commit_ct(b.pk, toC(ct), (*C.uint8_t)(unsafe.Pointer(&out[0])))
	return out
}

func (b *Bridge) DecodeCipher(s string) Handle {
	ct := b.decodeCipherC(s)
	return Handle(uintptr(ct))
}

func (b *Bridge) EncodeCipher(ct Handle) string {
	data := b.serializeCipherBytes(ct)
	return "hfhe_v1|" + crypto.Base64Encode(data)
}

func (b *Bridge) SerializeCipherB64(ct Handle) string {
	data := b.serializeCipherBytes(ct)
	return crypto.Base64Encode(data)
}

func (b *Bridge) DeserializeCipherFromB64(b64 string) Handle {
	raw, err := crypto.Base64Decode(b64)
	if err != nil || len(raw) == 0 {
		return 0
	}
	ct := C.pvac_deserialize_cipher((*C.uint8_t)(unsafe.Pointer(&raw[0])), C.size_t(len(raw)))
	return Handle(uintptr(ct))
}

func (b *Bridge) PedersenCommit(amount uint64, blinding [32]byte) [32]byte {
	var out [32]byte
	C.pvac_pedersen_commit(C.uint64_t(amount),
		(*C.uint8_t)(unsafe.Pointer(&blinding[0])),
		(*C.uint8_t)(unsafe.Pointer(&out[0])))
	return out
}

func (b *Bridge) MakeZeroProofBound(ct Handle, amount uint64, blinding [32]byte) Handle {
	zp := C.pvac_make_zero_proof_bound(b.pk, b.sk, toC(ct),
		C.uint64_t(amount), (*C.uint8_t)(unsafe.Pointer(&blinding[0])))
	return Handle(uintptr(zp))
}

func (b *Bridge) MakeRangeProof(ct Handle, value uint64) Handle {
	rp := C.pvac_make_range_proof(b.pk, b.sk, toC(ct), C.uint64_t(value))
	return Handle(uintptr(rp))
}

func (b *Bridge) MakeAggRangeProof(ct Handle, value uint64) Handle {
	arp := C.pvac_make_aggregated_range_proof(b.pk, b.sk, toC(ct), C.uint64_t(value))
	return Handle(uintptr(arp))
}

func (b *Bridge) EncodeRangeProof(rp Handle) string {
	var clen C.size_t
	ptr := C.pvac_serialize_range_proof(toRP(rp), &clen)
	if ptr == nil {
		return ""
	}
	data := C.GoBytes(unsafe.Pointer(ptr), C.int(clen))
	C.pvac_free_bytes(ptr)
	return "rp_v1|" + crypto.Base64Encode(data)
}

func (b *Bridge) EncodeAggRangeProof(arp Handle) string {
	var clen C.size_t
	ptr := C.pvac_serialize_agg_range_proof(toARP(arp), &clen)
	if ptr == nil {
		return ""
	}
	data := C.GoBytes(unsafe.Pointer(ptr), C.int(clen))
	C.pvac_free_bytes(ptr)
	return "rp_v1|" + crypto.Base64Encode(data)
}

func (b *Bridge) EncodeZeroProof(zp Handle) string {
	var clen C.size_t
	ptr := C.pvac_serialize_zero_proof(toZP(zp), &clen)
	if ptr == nil {
		return ""
	}
	data := C.GoBytes(unsafe.Pointer(ptr), C.int(clen))
	C.pvac_free_bytes(ptr)
	return "zkzp_v2|" + crypto.Base64Encode(data)
}

func (b *Bridge) SerializePubkey() []byte {
	var clen C.size_t
	ptr := C.pvac_serialize_pubkey(b.pk, &clen)
	if ptr == nil {
		return nil
	}
	data := C.GoBytes(unsafe.Pointer(ptr), C.int(clen))
	C.pvac_free_bytes(ptr)
	return data
}

func (b *Bridge) SerializePubkeyB64() string {
	data := b.SerializePubkey()
	if data == nil {
		return ""
	}
	return crypto.Base64Encode(data)
}

func (b *Bridge) AESKatHex() string {
	var buf [16]byte
	C.pvac_aes_kat((*C.uint8_t)(unsafe.Pointer(&buf[0])))
	return fmt.Sprintf("%x", buf)
}

func (b *Bridge) FreeCipher(ct Handle) {
	if ct != 0 {
		C.pvac_free_cipher(toC(ct))
	}
}

func (b *Bridge) FreeRangeProof(rp Handle) {
	if rp != 0 {
		C.pvac_free_range_proof(toRP(rp))
	}
}

func (b *Bridge) FreeZeroProof(zp Handle) {
	if zp != 0 {
		C.pvac_free_zero_proof(toZP(zp))
	}
}

func (b *Bridge) FreeAggRangeProof(arp Handle) {
	if arp != 0 {
		C.pvac_free_agg_range_proof(toARP(arp))
	}
}

// internal helpers

func toC(h Handle) C.pvac_cipher {
	return C.pvac_cipher(unsafe.Pointer(uintptr(h)))
}

func toRP(h Handle) C.pvac_range_proof {
	return C.pvac_range_proof(unsafe.Pointer(uintptr(h)))
}

func toZP(h Handle) C.pvac_zero_proof {
	return C.pvac_zero_proof(unsafe.Pointer(uintptr(h)))
}

func toARP(h Handle) C.pvac_agg_range_proof {
	return C.pvac_agg_range_proof(unsafe.Pointer(uintptr(h)))
}

func (b *Bridge) decodeCipherC(s string) C.pvac_cipher {
	const prefix = "hfhe_v1|"
	if len(s) < len(prefix) || s[:len(prefix)] != prefix {
		return nil
	}
	raw, err := crypto.Base64Decode(s[len(prefix):])
	if err != nil || len(raw) == 0 {
		return nil
	}
	return C.pvac_deserialize_cipher((*C.uint8_t)(unsafe.Pointer(&raw[0])), C.size_t(len(raw)))
}

func (b *Bridge) serializeCipherBytes(ct Handle) []byte {
	var clen C.size_t
	ptr := C.pvac_serialize_cipher(toC(ct), &clen)
	if ptr == nil {
		return nil
	}
	data := C.GoBytes(unsafe.Pointer(ptr), C.int(clen))
	C.pvac_free_bytes(ptr)
	return data
}
