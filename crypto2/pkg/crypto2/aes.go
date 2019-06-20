package crypto2

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"fmt"
	"hash"
	_ "crypto/sha256"
	_ "crypto/sha512"
)

/*
  Encrypt GCM and return
  Returns a byte array with [ ivLen:byte, iv..., cipherText... ]

  Note: The key size must be at least 16bytes.
        See https://crypto.stackexchange.com/questions/26783/ciphertext-and-tag-size-and-iv-transmission-with-aes-in-gcm-mode/26787 for
            an explanation of tag sizes.
        If larger the first 16 bytes are used.

*/
func EncryptGCM(encKey, input []byte) ([]byte, error)  {


	encKeyLen := len(encKey)

	if encKeyLen < 16 {
		return nil, fmt.Errorf("The key must be 16 bytes long")
	}

	encKeySized := encKey

	if encKeyLen > 16 {
		encKeySized = encKey[:16]
	}


	c, err := aes.NewCipher(encKeySized)

	if err != nil {
		return nil, err
	}

	//----------- Create the IV

	// remember that GCM normally takes a 12 byte (96 bit) nounce
	nonceSize := 12
	iv, err := GenerateNonce(nonceSize)
	if err != nil {
		return nil, err
	}

	//----------- Encrypt

	ivLen := len(iv)
	enc, err := cipher.NewGCMWithNonceSize(c, nonceSize)

	if err != nil {
		return nil, err
	}

	cipherText := enc.Seal(nil, iv, input, nil)

	//----------- Pack the message

	// create output tag
	output := make([]byte, 1 + ivLen + len(cipherText))

	i := 0
	output[i] = byte(ivLen)
	i++
	Copy(iv, 0, output, i, ivLen)
	i += ivLen

	Copy(cipherText, 0, output, i, len(cipherText))

	return output, nil
}

/**
Decrypt text that has been encrypted with EncryptGCM.
The encKey must be the same key used during encryption.

Expects the message format: [ ivLen:byte, iv..., cipherText... ]

The must be at least 16 bytes, if larger the first 16 bytes are used.
*/
func DecryptGCM(encKey, input []byte) ([]byte, error) {
	encKeyLen := len(encKey)

	if encKeyLen < 16 {
		return nil, fmt.Errorf("The key must be 16 bytes long")
	}

	encKeySized := encKey

	if encKeyLen > 16 {
		encKeySized = encKey[:16]
	}


	//----------- Unpack the message

	//----------- read the IV
	i := 0
	ivLen := int(input[i])
	i++

	if ivLen != 12 {
		return nil, fmt.Errorf("IV length is not correct, expected 12 but got %d", ivLen)
	}

	iv := make([]byte, ivLen)
	Copy(input, i, iv, 0, ivLen)
	i += ivLen

	//----------- read the cipher text

	cipherTextLen := len(input) - i
	cipherText := make([]byte, cipherTextLen)

	Copy(input, i, cipherText, 0, cipherTextLen)


	//----------- Decrypt

	c, err := aes.NewCipher(encKeySized)

	if err != nil {
		return nil, err
	}

	dec, err := cipher.NewGCMWithNonceSize(c, ivLen)

	if err != nil {
		return nil, err
	}

	output, err := dec.Open(nil, iv, cipherText, nil)

	if err != nil {
		return nil, err
	}

	return output, nil
}

/**
 Decrypt text that has been encrypted with EncryptCBCHmac.
 The encKey, authKey and hash functions should be the same used during the encryption.

 This function tests the hmac before decrypting.

 Expects the message format: [ ivLen:byte, iv..., hmacLen:byte, hmac..., cipherText... ]
 */
func DecryptCBCHmac(encKey, authKey, input []byte, hashFn func() hash.Hash) ([]byte, error) {

	i := 0
	ivLen := int(input[i])
	i++

	if ivLen != 16 {
		return nil, fmt.Errorf("IV length is not correct, expected 16 but got %d", ivLen)
	}

	iv := make([]byte, ivLen)
	Copy(input, i, iv, 0, ivLen)
	i += ivLen

	hmacLen := int(input[i])
	i++
	if hmacLen > len(input) {
		return nil, fmt.Errorf("Invalid hmac length")
	}

	hmacBts := make([]byte, hmacLen)
	Copy(input, i, hmacBts, 0, hmacLen)
	i += hmacLen

	cipherTextLen := len(input) - i
	cipherText := make([]byte, cipherTextLen)

	Copy(input, i, cipherText, 0, cipherTextLen)

	// Important: we need to check the Hmac before decrypting
	// HMac iv + cipher text
	h := hmac.New(hashFn, authKey)
	h.Write(iv)
	h.Write(cipherText)

	hmacSum := h.Sum(nil)

	if !hmac.Equal(hmacSum, hmacBts) {
		return nil, fmt.Errorf("The hmac is not valid")
	}

	// Now we can decrypt
	c, err := aes.NewCipher(encKey)

	if err != nil {
		return nil, err
	}

	output := make([]byte, cipherTextLen)
	dec := cipher.NewCBCDecrypter(c, iv)
	dec.CryptBlocks(output, cipherText)


	return PKCS5UnPadding(output), nil
}


/*
  Encrypt txt using CBC HMAC
  IV keys is 16.
  The hash should be crypto.SHA256.New or crypto.SHA512.New

Returns a byte array with [ ivLen:byte, iv..., hmacLen:byte, hmac..., cipherText... ]
*/
func EncryptCBCHmac(encKey, authKey, txt []byte, hashFn func() hash.Hash) ([]byte, error) {

	c, err := aes.NewCipher(encKey)

	if err != nil {
		return nil, err
	}

	iv, err := GenerateNonce(16)
	if err != nil {
		return nil, err
	}

	ivLen := len(iv)

	enc := cipher.NewCBCEncrypter(c, iv)


	input := PKCS5Padding(txt, c.BlockSize())
	cipherText := make([]byte, len(input))

	enc.CryptBlocks(cipherText, input)

	// HMac iv + cipher text
	h := hmac.New(hashFn, authKey)
	h.Write(iv)
	h.Write(cipherText)

	hmacSum := h.Sum(nil)
	hmacLen := len(hmacSum)

	// create output tag
	output := make([]byte, 1 + len(iv) + 1 + len(hmacSum) + len(cipherText))

	i := 0
	output[i] = byte(ivLen)
	i++
	Copy(iv, 0, output, i, ivLen)
	i += ivLen

	output[i] = byte(hmacLen)
	i++
	Copy(hmacSum, 0, output, i, hmacLen)
	i += hmacLen

	Copy(cipherText, 0, output, i, len(cipherText))

	return output, nil
}

// Create a single random initialised byte array of size.
func GenerateNonce(size int) ([]byte, error) {

	b := make([]byte, size)

	// not checking len here because rand.Read doc reads:
	//             On return, n == len(b) if and only if err == nil.
	_, err := rand.Read(b)


	if err != nil {
		return nil, err
	}

	return b, nil
}

// Copy from pkg into a dest byte array
func Copy(src []byte, srcI int, dest []byte, destI int, copyLen int)  {

	for i := 0; i < copyLen; i++ {
		dest[destI] = src[srcI]
		destI++
		srcI++
	}
}

// Shamelessly taken from https://stackoverflow.com/questions/41579325/golang-how-do-i-decrypt-with-des-cbc-and-pkcs7
func PKCS5Padding(src []byte, blockSize int) []byte {
	padding := blockSize - len(src)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

func PKCS5UnPadding(src []byte) []byte {
	length := len(src)
	unpadding := int(src[length-1])
	return src[:(length - unpadding)]
}
