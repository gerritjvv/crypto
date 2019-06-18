## Overview

Runs encryption decryption benchmarks for:

  * Vanilla JCE
  * Apache commons crypto
  * Bouncy Castle
  * Clojure buddy


To use run:

```bash
./build.sh build
# then
./build.sh run
```

See [AES Java Encryption Performance Benchmarks](https://medium.com/@gerritjvv/aes-java-encryption-performance-benchmarks-3c2cb19a40e9)

## Results

These were run on my mac 2018 mac.
Please run your own on the servers you expect to deploy on for accurate numbers.


Vanilla Java:

```bash
Benchmark                       Mode  Cnt      Score      Error  Units
AesJce.enc_aes128CbcHmacSha256  thrpt  200  40722.671 ±  739.025  ops/s
AesJce.enc_aes256CbcHmacSha512  thrpt  200  39288.300 ±  979.722  ops/s
AesJce.enc_aes128GCM            thrpt  200  75599.381 ± 1197.385  ops/s

AesJce.dec_aes128CbcHmacSha256  thrpt  200  49830.138 ± 1040.007  ops/s
AesJce.dec_aes256CbcHmacSha512  thrpt  200  51758.272 ±  839.378  ops/s
AesJce.dec_aes128GCM            thrpt  200  76144.372 ± 2626.274  ops/s
```

Commons:
```bash
Benchmark                                Mode  Cnt      Score      Error  Units
AesCommons.enc_aes128CbcHmacSha256       thrpt  200  26567.236 ± 212.846  ops/s
AesCommons.dec_aes128CbcHmacSha256       thrpt  200  25821.145 ± 463.154  ops/s
AesCommons.enc_aes128GCM                 thrpt  200  59517.955 ± 385.987  ops/s
AesCommons.dec_aes128GCM                 thrpt  200  51019.787 ± 1098.928  ops/s

```

Bouncy Castle
```bash
Benchmark                                Mode  Cnt      Score      Error  Units
AesBouncyCastle.enc_aes128CbcHmacSha256  thrpt  200  23981.183 ± 182.650  ops/s
AesBouncyCastle.enc_aes128GCM            thrpt  200  19993.285 ± 167.915  ops/s
AesBouncyCastle.dec_aes128CbcHmacSha256  thrpt  200  24996.014 ± 161.343  ops/s
AesBouncyCastle.dec_aes128GCM            thrpt  200  19743.066 ± 152.837  ops/s
```


Buddy clojure lib (encryption only):
```bash
Benchmark                        Mode  Cnt    Score   Error  Units
AESCBCHMAC.aes128CbcHmacSha256  thrpt  200    482.811 ± 5.144  ops/s {:algorithm :aes128-cbc-hmac-sha256}
AESCBCHMAC.aes256CbcHmacSha512  thrpt  200    487.327 ± 5.476  ops/s {:algorithm :aes256-cbc-hmac-sha512}
AESCBCHMAC.aes256GCM            thrpt  200  15845.017 ± 192.831  ops/s {:algorithm :aes256-gcm}
```
