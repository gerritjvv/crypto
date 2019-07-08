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
 === RUN   TestNaiveTimesEncryptGCM
Run 0. Did 1000000 iterations in 2.481178232s
Run 1. Did 1000000 iterations in 2.495653698s
Run 2. Did 1000000 iterations in 2.554544033s
Run 3. Did 1000000 iterations in 2.735187669s
Run 4. Did 1000000 iterations in 2.468231834s
Run 5. Did 1000000 iterations in 2.508428888s
Run 6. Did 1000000 iterations in 2.515230338s
Run 7. Did 1000000 iterations in 2.757054756s
Run 8. Did 1000000 iterations in 2.807702375s
Run 9. Did 1000000 iterations in 2.532421898s
--- PASS: TestNaiveTimesEncryptGCM (28.85s)

=== RUN   TestNaiveTimesDecryptGCM
Run 0. Did 1000000 iterations in 2.573020086s
Run 1. Did 1000000 iterations in 2.406950964s
Run 2. Did 1000000 iterations in 2.395980052s
Run 3. Did 1000000 iterations in 2.414534618s
Run 4. Did 1000000 iterations in 2.530799248s
Run 5. Did 1000000 iterations in 2.489241079s
Run 6. Did 1000000 iterations in 2.467342043s
Run 7. Did 1000000 iterations in 2.402141288s
Run 8. Did 1000000 iterations in 2.413835598s
Run 9. Did 1000000 iterations in 2.546055276s
--- PASS: TestNaiveTimesDecryptGCM (27.20s)

=== RUN   TestNaiveTimesEncryptCBC256
Run 0. Did 1000000 iterations in 19.379929934s
Run 1. Did 1000000 iterations in 20.754365315s
Run 2. Did 1000000 iterations in 17.938044597s
Run 3. Did 1000000 iterations in 21.04633964s
Run 4. Did 1000000 iterations in 21.178813978s
Run 5. Did 1000000 iterations in 20.230670516s
Run 6. Did 1000000 iterations in 19.424179754s
Run 7. Did 1000000 iterations in 19.82566766s
Run 8. Did 1000000 iterations in 20.811498588s
Run 9. Did 1000000 iterations in 19.344590244s
--- PASS: TestNaiveTimesEncryptCBC256 (202.42s)

=== RUN   TestNaiveTimesDecryptCBC256
Run 0. Did 1000000 iterations in 17.705503998s
Run 1. Did 1000000 iterations in 17.789986464s
Run 2. Did 1000000 iterations in 16.92886847s
Run 3. Did 1000000 iterations in 17.415068591s
Run 4. Did 1000000 iterations in 19.019705091s
Run 5. Did 1000000 iterations in 18.163566841s
Run 6. Did 1000000 iterations in 17.048639314s
Run 7. Did 1000000 iterations in 18.953794465s
Run 8. Did 1000000 iterations in 20.07039699s
Run 9. Did 1000000 iterations in 18.22400542s
--- PASS: TestNaiveTimesDecryptCBC256 (184.09s)
PASS
ok      crypto/pkg/crypto2      442.571s

```

## Compile, test and bench

```bash
./build.sh build
./build.sh test
```

## References 

Go lang crypto poor performance: https://github.com/goamz/goamz/issues/81
