package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"strings"

	"github.com/protobuffalo/go-octra/internal/nacl"
	"golang.org/x/crypto/pbkdf2"
)

func SHA256(data []byte) [32]byte {
	return sha256.Sum256(data)
}

func SHA256Hex(data string) string {
	h := sha256.Sum256([]byte(data))
	return HexEncode(h[:])
}

func HMACSHA512(key, data []byte) [64]byte {
	mac := hmac.New(sha512.New, key)
	mac.Write(data)
	var out [64]byte
	copy(out[:], mac.Sum(nil))
	return out
}

func DeriveKeyFromPin(pin string, salt []byte, iterations int) [32]byte {
	key := pbkdf2.Key([]byte(pin), salt, iterations, 32, sha256.New)
	var out [32]byte
	copy(out[:], key)
	return out
}

func WalletEncrypt(plaintext []byte, pin string) ([]byte, error) {
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	key := DeriveKeyFromPin(pin, salt, 600000)
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
	// Format: [32 salt][12 nonce][ciphertext+tag]
	// GCM Seal appends 16-byte tag to ciphertext
	out := make([]byte, 0, 32+12+len(ciphertext))
	out = append(out, salt...)
	out = append(out, nonce...)
	out = append(out, ciphertext...)
	return out, nil
}

func WalletDecrypt(data []byte, pin string) ([]byte, error) {
	if len(data) < 60 {
		return nil, errors.New("data too short")
	}
	salt := data[:32]
	nonce := data[32:44]
	ciphertext := data[44:]
	key := DeriveKeyFromPin(pin, salt, 600000)
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, errors.New("wrong pin")
	}
	return plaintext, nil
}

func AESGCMEncrypt(key, plaintext []byte) ([]byte, error) {
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ct := gcm.Seal(nil, nonce, plaintext, nil)
	// nonce + ciphertext + tag
	out := make([]byte, 0, 12+len(ct))
	out = append(out, nonce...)
	out = append(out, ct...)
	return out, nil
}

func AESGCMDecrypt(key, data []byte) ([]byte, error) {
	if len(data) < 28 { // 12 nonce + 16 tag minimum
		return nil, errors.New("data too short")
	}
	nonce := data[:12]
	ct := data[12:]
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ct, nil)
}

func RandomBytes(n int) []byte {
	buf := make([]byte, n)
	rand.Read(buf)
	return buf
}

func SecureZero(buf []byte) {
	for i := range buf {
		buf[i] = 0
	}
}

func KeypairFromSeed(seed []byte) (sk [64]byte, pk [32]byte) {
	pkSlice := make([]byte, 32)
	skSlice := make([]byte, 64)
	nacl.CryptoSignSeedKeypair(pkSlice, skSlice, seed)
	copy(sk[:], skSlice)
	copy(pk[:], pkSlice)
	return
}

func Ed25519SignDetached(msg, sk []byte) string {
	sm := make([]byte, len(msg)+64)
	var smlen uint64
	nacl.CryptoSign(sm, &smlen, msg, uint64(len(msg)), sk)
	return Base64Encode(sm[:64])
}

func Ed25519SKToCurve25519(edSK []byte) [32]byte {
	h := make([]byte, 64)
	nacl.CryptoHash(h, edSK[:32], 32)
	h[0] &= 248
	h[31] &= 127
	h[31] |= 64
	var xsk [32]byte
	copy(xsk[:], h[:32])
	return xsk
}

func Ed25519PKToCurve25519(edSK []byte) [32]byte {
	xsk := Ed25519SKToCurve25519(edSK)
	var xpk [32]byte
	xpkSlice := make([]byte, 32)
	nacl.CryptoScalarmultBase(xpkSlice, xsk[:])
	copy(xpk[:], xpkSlice)
	return xpk
}

func DeriveAddress(pk [32]byte) string {
	h := SHA256(pk[:])
	b58 := Base58Encode(h[:])
	for len(b58) < 44 {
		b58 = "1" + b58
	}
	return "oct" + b58
}

func DeriveHDSeed(masterSeed []byte, index uint32, hdVersion int) [32]byte {
	var result [32]byte
	if hdVersion == 1 && index == 0 {
		copy(result[:], masterSeed[:32])
	} else if hdVersion == 2 && index == 0 {
		key := []byte("Octra seed")
		mac := HMACSHA512(key, masterSeed[:64])
		copy(result[:], mac[:32])
	} else {
		data := make([]byte, 68)
		copy(data[:64], masterSeed[:64])
		data[64] = byte(index & 0xFF)
		data[65] = byte((index >> 8) & 0xFF)
		data[66] = byte((index >> 16) & 0xFF)
		data[67] = byte((index >> 24) & 0xFF)
		key := []byte("Octra seed")
		mac := HMACSHA512(key, data)
		copy(result[:], mac[:32])
	}
	return result
}

func MnemonicToSeed(mnemonic string) [64]byte {
	salt := "mnemonic"
	key := pbkdf2.Key([]byte(mnemonic), []byte(salt), 2048, 64, sha512.New)
	var out [64]byte
	copy(out[:], key)
	return out
}

func ValidateMnemonic(mnemonic string) bool {
	words := strings.Fields(strings.ToLower(mnemonic))
	switch len(words) {
	case 12, 15, 18, 21, 24:
	default:
		return false
	}
	for _, w := range words {
		found := false
		for _, bw := range BIP39Wordlist {
			if bw == w {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func LooksLikeMnemonic(input string) bool {
	spaces := 0
	for _, c := range input {
		if c == ' ' {
			spaces++
		}
	}
	return spaces >= 11
}

func GenerateMnemonic12() string {
	entropy := make([]byte, 16)
	rand.Read(entropy)
	hash := SHA256(entropy)
	bits := make([]byte, 17)
	copy(bits[:16], entropy)
	bits[16] = hash[0]

	var words []string
	for i := 0; i < 12; i++ {
		bitPos := i * 11
		byteIdx := bitPos / 8
		bitOff := bitPos % 8
		val := uint32(bits[byteIdx]) << 16
		val |= uint32(bits[byteIdx+1]) << 8
		if byteIdx+2 < 17 {
			val |= uint32(bits[byteIdx+2])
		}
		val = (val >> uint(24-11-bitOff)) & 0x7FF
		words = append(words, BIP39Wordlist[val])
	}
	return strings.Join(words, " ")
}

func ComputeSeedHash(masterSeedB64 string) string {
	raw, _ := Base64Decode(masterSeedB64)
	h := SHA256(raw)
	return fmt.Sprintf("%x", h[:8])
}
