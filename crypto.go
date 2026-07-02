package macaroon

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"

	"golang.org/x/crypto/nacl/secretbox"
)

const (
	keyLen   = 32
	nonceLen = 24
	hashLen  = sha256.Size
)

func hmacDigest(key []byte, text []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(text)
	return h.Sum(nil)
}

func hmacConcat(key []byte, d1, d2 []byte) []byte {
	var data [hashLen * 2]byte
	copy(data[:hashLen], hmacDigest(key, d1))
	copy(data[hashLen:], hmacDigest(key, d2))
	return hmacDigest(key, data[:])
}

var macaroonKeySeed = []byte("macaroons-key-generator")

// hashKey derives a fixed length key from a variable length key.
//
// The macaroonKeySeed constant is the same as that used in libmacaroons.
func hashKey(keySeed []byte) []byte {
	return hmacDigest(macaroonKeySeed, keySeed)
}

func generateNonce() (nonce [nonceLen]byte, err error) {
	_, err = rand.Read(nonce[:])
	if err != nil {
		err = fmt.Errorf("generate nonce: %v", err)
	}
	return
}

func encryptKey(key []byte, message []byte) ([]byte, error) {
	arrKey, err := bytesToKey(key)
	if err != nil {
		return nil, err
	}
	nonce, err := generateNonce()
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(nonce)+secretbox.Overhead+len(message))
	out = append(out, nonce[:]...)
	return secretbox.Seal(out, message, &nonce, &arrKey), nil
}

func decryptKey(key []byte, message []byte) ([]byte, error) {
	if len(message) < nonceLen+secretbox.Overhead {
		return nil, fmt.Errorf("message too short")
	}

	arrKey, err := bytesToKey(key)
	if err != nil {
		return nil, err
	}

	var nonce [nonceLen]byte
	copy(nonce[:], message)
	box := message[nonceLen:]

	decryptedKey, ok := secretbox.Open(nil, box, &nonce, &arrKey)
	if !ok {
		return nil, fmt.Errorf("decryption failure")
	}
	if len(decryptedKey) != hashLen {
		return nil, fmt.Errorf("invalid length of a decrypted key: %d", len(decryptedKey))
	}
	return decryptedKey, nil
}

func bytesToKey(b []byte) (key [keyLen]byte, err error) {
	if len(b) != keyLen {
		err = fmt.Errorf("invalid key length %d expected %d", len(b), keyLen)
		return
	}
	copy(key[:], b)
	return
}
