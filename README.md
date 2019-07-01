# crypto

A simple fast encryption library for the JVM uses standard best practices and standard JVM classes


[![Maven Central](https://img.shields.io/maven-central/v/com.github.gerritjvv/crypto-core.svg)](https://search.maven.org/artifact/com.github.gerritjvv/crypto-core/)

[![Javadocs](https://javadoc.io/badge/com.github.gerritjvv/crypto-core.svg)](https://javadoc.io/doc/com.github.gerritjvv/crypto-core)


## Releases


```xml
<dependency>
  <groupId>com.github.gerritjvv</groupId>
  <artifactId>crypto-core</artifactId>
  <version>LATEST</version>
</dependency>
```

## Password derivation

If you're not using an encryption key but directly using the user password, you must first
run a key derivation routine on it.

```java
byte[] pass = Key.deriveHmac256FromPass(null, "user-pass");
```

and then you can use:

```java
byte[] key = Key.KeySize.AES_128.genKeysHmacSha(pass);
```

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
Key.ExpandedKey key = Key.KeySize.AES_128.genKeysHmacSha(pass);

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
Key.ExpandedKey key = Key.KeySize.AES_128.genKeysHmacSha(pass);

// encrypt the data
byte[] encryptedData = crypto.AES.encryptGCM(key, someData);

// decrypt it
byte[] decryptedData = crypto.AES.decryptGCM(key, encryptedData);

```

## More examples:

See: [AESTest.java](https://github.com/gerritjvv/crypto/blob/master/crypto-core/src/test/java/crypto/AESTest.java)


# License

https://www.apache.org/licenses/LICENSE-2.0

# Contributors

Contributions PRs and suggestions are always welcome.

Please ping me directly in the "issues" on "gerritjvv" or send me an email at gerritjvv@gmail.com, this way
the issues/pull-requests won't just linger if github notifications doens't work.

## Guide on publishing to maven central

https://dzone.com/articles/publish-your-artifacts-to-maven-central

### Release Process:

Follow:

https://www.rainerhahnekamp.com/en/publishing-a-java-library-to-maven-central/


Repository staging is deployed to https://oss.sonatype.org



