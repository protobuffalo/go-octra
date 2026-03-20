package nacl

/*
#cgo CFLAGS: -O2 -Wall
#include "tweetnacl.h"
extern void randombytes(unsigned char *, unsigned long long);

// crypto_sign_seed_keypair is declared in tweetnacl.h
*/
import "C"
import "unsafe"

func CryptoSignSeedKeypair(pk, sk, seed []byte) {
	C.crypto_sign_seed_keypair(
		(*C.uchar)(unsafe.Pointer(&pk[0])),
		(*C.uchar)(unsafe.Pointer(&sk[0])),
		(*C.uchar)(unsafe.Pointer(&seed[0])),
	)
}

func CryptoSign(sm []byte, smlen *uint64, m []byte, mlen uint64, sk []byte) int {
	var csmlen C.ulonglong
	var mp *C.uchar
	if len(m) > 0 {
		mp = (*C.uchar)(unsafe.Pointer(&m[0]))
	}
	r := C.crypto_sign(
		(*C.uchar)(unsafe.Pointer(&sm[0])),
		&csmlen,
		mp,
		C.ulonglong(mlen),
		(*C.uchar)(unsafe.Pointer(&sk[0])),
	)
	*smlen = uint64(csmlen)
	return int(r)
}

func CryptoScalarmult(q, n, p []byte) int {
	return int(C.crypto_scalarmult(
		(*C.uchar)(unsafe.Pointer(&q[0])),
		(*C.uchar)(unsafe.Pointer(&n[0])),
		(*C.uchar)(unsafe.Pointer(&p[0])),
	))
}

func CryptoScalarmultBase(q, n []byte) int {
	return int(C.crypto_scalarmult_base(
		(*C.uchar)(unsafe.Pointer(&q[0])),
		(*C.uchar)(unsafe.Pointer(&n[0])),
	))
}

func CryptoHash(out, m []byte, mlen uint64) int {
	var mp *C.uchar
	if len(m) > 0 {
		mp = (*C.uchar)(unsafe.Pointer(&m[0]))
	}
	return int(C.crypto_hash(
		(*C.uchar)(unsafe.Pointer(&out[0])),
		mp,
		C.ulonglong(mlen),
	))
}

func Randombytes(buf []byte, len uint64) {
	C.randombytes((*C.uchar)(unsafe.Pointer(&buf[0])), C.ulonglong(len))
}
