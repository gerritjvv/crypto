package crypto2

import (
	"crypto"
	"fmt"
	"testing"
	"time"
)

var PlainText, _ = GenerateNonce(4096)

var AuthKey256, _ = GenerateNonce(32)
var EncKey256, _ = GenerateNonce(32)
var EncKey128, _ = GenerateNonce(16)

var CipherText256, _ = EncryptCBCHmac(EncKey256, AuthKey256, PlainText, crypto.SHA256.New)
var GcmCipherText, _ = EncryptGCM(EncKey128, PlainText)


func TestNaiveTimesEncryptGCM(b *testing.T) {

	n := 1000000
	//warmup
	NaiveTimesGCMEncrypt(n)

	for i := 0 ; i < 10; i++ {
		elasped := NaiveTimesGCMEncrypt(n)
		fmt.Printf("Run %d. Did %d iterations in %s\n", i, n, elasped)
	}
}

func NaiveTimesGCMEncrypt(n int)  time.Duration{
	startTime := time.Now()

	for i := 0; i < n; i++ {
		encText, err := EncryptGCM(EncKey128, PlainText)

		if err != nil {
			panic(err)
		}

		if encText == nil {
			panic("Encrypted text cannot be nil")
		}
	}


	elapsed := time.Since(startTime)

	return elapsed
}

func TestNaiveTimesDecryptGCM(b *testing.T) {
	n := 1000000
	//warmup
	NaiveTimesGCMEncrypt(n)

	for i := 0 ; i < 10; i++ {
		elasped := NaiveTimesDecryptGCM(n)
		fmt.Printf("Run %d. Did %d iterations in %s\n", i, n, elasped)
	}
}

func NaiveTimesDecryptGCM(n int) time.Duration {
	startTime := time.Now()

	for i := 0; i < n; i++ {
		text, err := DecryptGCM(EncKey128, GcmCipherText)

		if err != nil {
			panic(err)
		}

		if text == nil {
			panic("Plain text cannot be nil")
		}
	}


	elapsed := time.Since(startTime)

	return elapsed
}

func TestNaiveTimesEncryptCBC256(b *testing.T) {
	n := 1000000
	//warmup
	NaiveTimesGCMEncrypt(n)

	for i := 0 ; i < 10; i++ {
		elasped := NaiveTimesEncryptCBC256(n)
		fmt.Printf("Run %d. Did %d iterations in %s\n", i, n, elasped)
	}
}

func NaiveTimesEncryptCBC256(n int) time.Duration {
	startTime := time.Now()

	for i := 0; i < n; i++ {
		encText, err := EncryptCBCHmac(EncKey256, AuthKey256, PlainText, crypto.SHA256.New)

		if err != nil {
			panic(err)
		}

		if encText == nil {
			panic("Encrypted text cannot be nil")
		}
	}

	elapsed := time.Since(startTime)

	return elapsed
}

func TestNaiveTimesDecryptCBC256(b *testing.T) {
	n := 1000000
	//warmup
	NaiveTimesGCMEncrypt(n)

	for i := 0 ; i < 10; i++ {
		elasped := NaiveTimesDecryptCBC256(n)
		fmt.Printf("Run %d. Did %d iterations in %s\n", i, n, elasped)
	}
}

func NaiveTimesDecryptCBC256(n int) time.Duration {
	startTime := time.Now()

	for i := 0; i < n; i++ {
		text, err := DecryptCBCHmac(EncKey256, AuthKey256, CipherText256, crypto.SHA256.New)

		if err != nil {
			panic(err)
		}

		if text == nil {
			panic("Plain text cannot be nil")
		}
	}

	elapsed := time.Since(startTime)

	return elapsed

}