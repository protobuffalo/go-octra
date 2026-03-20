package crypto

import (
	"encoding/base64"
	"encoding/hex"
	"math/big"
)

func Base64Encode(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

func Base64Decode(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

func HexEncode(data []byte) string {
	return hex.EncodeToString(data)
}

func HexDecode(s string) ([]byte, error) {
	return hex.DecodeString(s)
}

func Base58Encode(data []byte) string {
	const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	zeroes := 0
	for zeroes < len(data) && data[zeroes] == 0 {
		zeroes++
	}
	num := new(big.Int).SetBytes(data)
	mod := new(big.Int)
	base := big.NewInt(58)
	var result []byte
	for num.Sign() > 0 {
		num.DivMod(num, base, mod)
		result = append(result, alphabet[mod.Int64()])
	}
	for i := 0; i < zeroes; i++ {
		result = append(result, '1')
	}
	// reverse
	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}
	return string(result)
}
