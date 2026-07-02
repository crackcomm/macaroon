package macaroon

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/nacl/secretbox"
)

var testCryptKey = hashKey([]byte("key"))
var testCryptText = hashKey([]byte("text"))

func TestEncDec(t *testing.T) {
	b, err := encryptKey(testCryptKey, testCryptText)
	assert.Nil(t, err)
	p, err := decryptKey(testCryptKey, b)
	assert.Nil(t, err)
	assert.Equal(t, testCryptText, p)
}

func TestBadCiphertext(t *testing.T) {
	buf := randomBytes(nonceLen + secretbox.Overhead)
	for i := range buf {
		_, err := decryptKey(testCryptKey, buf[0:i])
		assert.ErrorContains(t, err, "message too short")
	}
	_, err := decryptKey(testCryptKey, buf)
	assert.ErrorContains(t, err, "decryption failure")
}
