# Encryption functions for AES CBC-HMAC and GCM

## Overview


This library implements authenticated AES CBC i.e CBC-HMAC.  
CBC should always be used in combination with and authentication method like HMAC.  

GCM is authenticated so do not require any additions.

Both AES authentication modes require a randomised IV, this is important but the most important
for GCM, because is fails catastrophically if IV's are repeated.


## AES CBC 

AES CBC encryption is HMACed and the result message contains   

  * version byte
  * secure random iv
  * hmac
  * cipher message

```go
// this is your password stretched, use something like bcrypt
encKey, _ := GenerateNonce(32)

// this is your password stretched again for authentication, use something like bcrypt
// you can use a 64 byte key then split it into 1 key for auth another for enc
// it is not recommended to use the same key for encryption and authentication.
authKey, _ := GenerateNonce(32)

encText, err := EncryptCBCHmac(encKey, authKey, PlainText, crypto.SHA256.New)

if err != nil {
  panic(err)
}

plainText, err := DecryptCBCHmac(encKey, authKey, encText, crypto.SHA256.New)

if err != nil {
  panic(err)
}
```
## AES GCM

AES GCM encryption is authenticated (so no HMAC is required).  
The result message contains:  

  * version byte
  * secure random iv
  * cipher message
  
```go

// this is your password stretched, use something like bcrypt
encKey, _ := GenerateNonce(32)

encText, err := EncryptGCM(encKey, PlainText)

if err != nil {
	panic(err)
}

plainText, err := DecryptGCM(encKey, encText)

```
## Benchmarks

Note: You should run your own, benchmarks behave differently depending on the platform libs etc...

```bash
BenchmarkEncryptGCM-12            300000              4342 ns/op
BenchmarkDecryptGCM-12            500000              4201 ns/op
BenchmarkEncryptCBC256-12         100000             18620 ns/op
BenchmarkDecryptCBC256-12         100000             18493 ns/op
```

## Compile, test and bench

```bash
./build.sh build
./build.sh test
./build.sh bench
```