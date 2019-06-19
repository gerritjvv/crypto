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


### 2018 MacbookPro AES-NI 
These were run on my mac 2018 mac.
Please run your own on the servers you expect to deploy on for accurate numbers.


Vanilla Java:

```bash
Benchmark                       Mode  Cnt      Score      Error  Units
AesJce.dec_aes128CbcHmacSha256           thrpt  200   61900.490 ± 1653.015  ops/s
AesJce.dec_aes128GCM                     thrpt  200  127963.728 ±  971.719  ops/s
AesJce.dec_aes256CbcHmacSha512           thrpt  200   75441.127 ±  582.450  ops/s

AesJce.enc_aes128CbcHmacSha256           thrpt  200   57025.908 ±  391.452  ops/s
AesJce.enc_aes128GCM                     thrpt  200  132084.915 ± 1159.802  ops/s
AesJce.enc_aes256CbcHmacSha512           thrpt  200   59834.589 ±  486.480  ops/s
```

Commons:
```bash
Benchmark                                Mode  Cnt      Score      Error  Units
AesCommons.dec_aes128CbcHmacSha256       thrpt  200   63317.949 ± 1200.566  ops/s
AesCommons.dec_aes128GCM                 thrpt  200   46749.763 ± 2122.694  ops/s
AesCommons.enc_aes128CbcHmacSha256       thrpt  200   46371.713 ± 1817.440  ops/s
AesCommons.enc_aes128GCM                 thrpt  200   44385.064 ± 1898.292  ops/s
```

Bouncy Castle
```bash
Benchmark                                Mode  Cnt      Score      Error  Units
AesBouncyCastle.dec_aes128CbcHmacSha256  thrpt  200   26216.280 ±  547.980  ops/s
AesBouncyCastle.dec_aes128GCM            thrpt  200   20562.354 ±  235.789  ops/s
AesBouncyCastle.enc_aes128CbcHmacSha256  thrpt  200   26301.967 ±  231.023  ops/s
AesBouncyCastle.enc_aes128GCM            thrpt  200   20177.435 ±  575.098  ops/s
```


Buddy clojure lib (encryption only):
```bash
Benchmark                        Mode  Cnt    Score   Error  Units
AesBuddy.aes128CbcHmacSha256             thrpt  200     464.914 ±   16.320  ops/s
AesBuddy.aes256CbcHmacSha512             thrpt  200     459.276 ±   18.494  ops/s
AesBuddy.aes256GCM                       thrpt  200   17798.661 ±  391.205  ops/s
```

### Digital Ocean Droplet AES-NI Java 1.11

```bash
Benchmark                                 Mode  Cnt      Score     Error  Units
AesBouncyCastle.dec_aes128CbcHmacSha256  thrpt  200  10098.168 ± 171.454  ops/s
AesBouncyCastle.dec_aes128GCM            thrpt  200   8077.036 ± 117.080  ops/s
AesBouncyCastle.enc_aes128CbcHmacSha256  thrpt  200  10552.567 ± 185.615  ops/s
AesBouncyCastle.enc_aes128GCM            thrpt  200   8297.211 ± 169.168  ops/s

AesBuddy.aes128CbcHmacSha256             thrpt  200    234.047 ±   4.037  ops/s
AesBuddy.aes256GCM                       thrpt  200   6271.101 ± 174.317  ops/s
AesBuddy.aes256CbcHmacSha512             thrpt  200    226.719 ±   3.197  ops/s

AesCommons.dec_aes128CbcHmacSha256       thrpt  200  19017.686 ± 451.684  ops/s
AesCommons.dec_aes128GCM                 thrpt  200  28913.738 ± 411.470  ops/s
AesCommons.enc_aes128CbcHmacSha256       thrpt  200  15996.684 ± 281.231  ops/s
AesCommons.enc_aes128GCM                 thrpt  200  30378.192 ± 485.382  ops/s

AesJce.dec_aes128CbcHmacSha256           thrpt  200  28816.848 ± 579.586  ops/s
AesJce.dec_aes128GCM                     thrpt  200  51218.554 ± 729.223  ops/s
AesJce.dec_aes256CbcHmacSha512           thrpt  200  29779.423 ± 651.773  ops/s
AesJce.enc_aes128CbcHmacSha256           thrpt  200  21201.612 ± 426.641  ops/s
AesJce.enc_aes128GCM                     thrpt  200  49192.508 ± 837.840  ops/s
AesJce.enc_aes256CbcHmacSha512           thrpt  200  20707.571 ± 373.395  ops/s
```

### Digital Ocean Droplet No AES-NI (java -XX:+UnlockDiagnosticVMOptions -XX:-UseAESIntrinsics )

```bash
Benchmark                                 Mode  Cnt      Score     Error  Units
AesBouncyCastle.dec_aes128CbcHmacSha256  thrpt  200   9067.862 ± 187.208  ops/s
AesBouncyCastle.dec_aes128GCM            thrpt  200   7296.655 ± 145.841  ops/s
AesBouncyCastle.enc_aes128CbcHmacSha256  thrpt  200   9654.405 ± 197.824  ops/s
AesBouncyCastle.enc_aes128GCM            thrpt  200   7485.948 ± 158.881  ops/s

AesBuddy.aes128CbcHmacSha256             thrpt  200    195.845 ±   5.030  ops/s
AesBuddy.aes256GCM                       thrpt  200   6249.484 ± 166.694  ops/s
AesBuddy.aes256CbcHmacSha512             thrpt  200    197.908 ±   3.980  ops/s

AesCommons.dec_aes128CbcHmacSha256       thrpt  200   7799.234 ± 165.025  ops/s
AesCommons.dec_aes128GCM                 thrpt  200   7661.790 ± 124.741  ops/s
AesCommons.enc_aes128CbcHmacSha256       thrpt  200   7483.005 ± 164.859  ops/s
AesCommons.enc_aes128GCM                 thrpt  200   8701.383 ± 162.079  ops/s

AesJce.dec_aes128CbcHmacSha256           thrpt  200   9810.039 ± 232.949  ops/s
AesJce.dec_aes128GCM                     thrpt  200   8536.722 ± 121.247  ops/s
AesJce.dec_aes256CbcHmacSha512           thrpt  200   8082.423 ± 175.164  ops/s
AesJce.enc_aes128CbcHmacSha256           thrpt  200   8748.420 ± 213.887  ops/s
AesJce.enc_aes128GCM                     thrpt  200  10123.005 ± 261.294  ops/s
AesJce.enc_aes256CbcHmacSha512           thrpt  200   8787.481 ± 174.021  ops/s
```