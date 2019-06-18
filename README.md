# crypto

A simple fast encryption library for the JVM uses standard best practices and standard JVM classes


## AES CBC 

AES CBC encryption is HMACed and the result message contains   

  * version byte
  * secure random iv
  * hmac
  * cipher message


```java

import crypto.AES;
import crypto.Key;
import crypto.Util;


// generate some random data to encrypt
byte[] pass = crypto.Util.genData(4096);

byte[] someData = "Some Data".getBytes();

// generate encryption and authentication keys
Key.ExpandedKey key = Ke.KeySize.AES_128.genKeysHmacSha(pass);

// encrypt the data
byte[] encryptedData = crypto.AES.encryptCBC(key, someData);

// decrypt it
byte[] decryptedData = crypto.AES.decryptCBC(key, encryptedData);

```


## AES GCM

AES GCM encryption is authenticated (so no HMAC is required).  
The result message contains:  

  * version byte
  * secure random iv
  * cipher message


```java

import crypto.AES;
import crypto.Key;
import crypto.Util;


// generate some random data to encrypt
byte[] pass = crypto.Util.genData(4096);

byte[] someData = "Some Data".getBytes();

// generate encryption and authentication keys
Key.ExpandedKey key = Ke.KeySize.AES_128.genKeysHmacSha(pass);

// encrypt the data
byte[] encryptedData = crypto.AES.encryptGCM(key, someData);

// decrypt it
byte[] decryptedData = crypto.AES.decryptGCM(key, encryptedData);

```

## More examples:

See: [AESTest.java](https://github.com/gerritjvv/crypto/blob/master/crypto-core/src/test/java/crypto/AESTest.java)