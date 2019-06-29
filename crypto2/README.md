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
Run 0. Did 1000000 iterations in 4.552525345s
Run 1. Did 1000000 iterations in 4.394497028s
Run 2. Did 1000000 iterations in 4.315440261s
Run 3. Did 1000000 iterations in 4.216099154s
Run 4. Did 1000000 iterations in 4.224905071s
Run 5. Did 1000000 iterations in 4.329739994s
Run 6. Did 1000000 iterations in 4.201837049s
Run 7. Did 1000000 iterations in 4.395699741s
Run 8. Did 1000000 iterations in 4.234307622s
Run 9. Did 1000000 iterations in 4.216855153s
--- PASS: TestNaiveTimesEncryptGCM (47.95s)
237991

=== RUN   TestNaiveTimesDecryptGCM
Run 0. Did 1000000 iterations in 4.238816206s
Run 1. Did 1000000 iterations in 4.321026922s
Run 2. Did 1000000 iterations in 4.333051401s
Run 3. Did 1000000 iterations in 4.284579845s
Run 4. Did 1000000 iterations in 4.388479424s
Run 5. Did 1000000 iterations in 4.214709358s
Run 6. Did 1000000 iterations in 4.333209745s
Run 7. Did 1000000 iterations in 4.227069213s
Run 8. Did 1000000 iterations in 4.194827887s
Run 9. Did 1000000 iterations in 4.338822797s
--- PASS: TestNaiveTimesDecryptGCM (47.23s)

=== RUN   TestNaiveTimesEncryptCBC256
Run 0. Did 1000000 iterations in 18.594550632s
Run 1. Did 1000000 iterations in 18.461138782s
Run 2. Did 1000000 iterations in 18.188842315s
Run 3. Did 1000000 iterations in 18.375593346s
Run 4. Did 1000000 iterations in 18.36304104s
Run 5. Did 1000000 iterations in 18.32109541s
Run 6. Did 1000000 iterations in 18.238426637s
Run 7. Did 1000000 iterations in 18.532891266s
Run 8. Did 1000000 iterations in 18.50271729s
Run 9. Did 1000000 iterations in 18.235587816s
--- PASS: TestNaiveTimesEncryptCBC256 (188.07s)


=== RUN   TestNaiveTimesDecryptCBC256
Run 0. Did 1000000 iterations in 17.640670182s
Run 1. Did 1000000 iterations in 17.76092337s
Run 2. Did 1000000 iterations in 17.690241448s
Run 3. Did 1000000 iterations in 17.589082895s
Run 4. Did 1000000 iterations in 17.617454398s
Run 5. Did 1000000 iterations in 17.849383898s
Run 6. Did 1000000 iterations in 17.765126291s
Run 7. Did 1000000 iterations in 20.085845014s
Run 8. Did 1000000 iterations in 19.152553922s
Run 9. Did 1000000 iterations in 18.902370885s
--- PASS: TestNaiveTimesDecryptCBC256 (186.40s)
PASS
ok      crypto/pkg/crypto2      469.661s


```

## Compile, test and bench

```bash
./build.sh build
./build.sh test
```

## References 

Go lang crypto poor performance: https://github.com/goamz/goamz/issues/81
