package crypto2

import (
	"crypto"
	"crypto/hmac"
	"testing"
)

var PlainText, _ = GenerateNonce(4096)

var AuthKey256, _ = GenerateNonce(32)
var EncKey256, _ = GenerateNonce(32)
var EncKey128, _ = GenerateNonce(16)

var CipherText256, _ = EncryptCBCHmac(EncKey256, AuthKey256, PlainText, crypto.SHA256.New)
var GcmCipherText, _ = EncryptGCM(EncKey128, PlainText)


func TestEncryptGCM(t *testing.T) {

	// we make the key 32 bytes to test the key to 16 byte truncation
	encKey, _ := GenerateNonce(32)

	encText, err := EncryptGCM(encKey, PlainText)

	if err != nil {
		t.Error(err)
	}

	plainText, err := DecryptGCM(encKey, encText)

	if err != nil {
		t.Error(err)
	}

	if ! hmac.Equal(PlainText, plainText) {
		t.Fail()
	}
}

func TestEncryptCBC(t *testing.T) {

	authKey, _ := GenerateNonce(32)
	encKey, _ := GenerateNonce(32)

	encText, err := EncryptCBCHmac(encKey, authKey, PlainText, crypto.SHA256.New)

	if err != nil {
		t.Error(err)
	}

	plainText, err := DecryptCBCHmac(encKey, authKey, encText, crypto.SHA256.New)

	if err != nil {
		t.Error(err)
	}

	if ! hmac.Equal(PlainText, plainText) {
		t.Fail()
	}
}

func BenchmarkEncryptGCM(b *testing.B) {

	for i := 0; i < b.N; i++ {
		encText, err := EncryptGCM(EncKey128, PlainText)

		if err != nil {
			b.Error(err)
		}

		if encText == nil {
			b.Error("Encrypted text cannot be nil")
		}
	}
}


func BenchmarkDecryptGCM(b *testing.B) {

	for i := 0; i < b.N; i++ {
		text, err := DecryptGCM(EncKey128, GcmCipherText)

		if err != nil {
			b.Error(err)
		}

		if text == nil {
			b.Error("Plain text cannot be nil")
		}
	}
}

func BenchmarkEncryptCBC256(b *testing.B) {

	for i := 0; i < b.N; i++ {
		encText, err := EncryptCBCHmac(EncKey256, AuthKey256, PlainText, crypto.SHA256.New)

		if err != nil {
			b.Error(err)
		}

		if encText == nil {
			b.Error("Encrypted text cannot be nil")
		}
	}
}

func BenchmarkDecryptCBC256(b *testing.B) {

	for i := 0; i < b.N; i++ {
		text, err := DecryptCBCHmac(EncKey256, AuthKey256, CipherText256, crypto.SHA256.New)

		if err != nil {
			b.Error(err)
		}

		if text == nil {
			b.Error("Plain text cannot be nil")
		}
	}
}
