package sencrypt;

import clojure.java.api.Clojure;
import clojure.lang.IFn;
import org.openjdk.jmh.annotations.Benchmark;

import java.security.SecureRandom;
import java.util.Arrays;

public class AesBuddy extends AesBase{


    private static final IFn RANDOM_BYTES;
    private static final IFn SHA256, SHA512;
    private static final IFn ENCRYPT;
    private static final Object BUDDY_CONF_512, BUDDY_CONF_256, BUDDY_CONF_128_GCM;

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();


    static {
        IFn require = Clojure.var("clojure.core", "require");
        require.invoke(Clojure.read("buddy.core.nonce"));
        require.invoke(Clojure.read("buddy.core.hash"));
        require.invoke(Clojure.read("buddy.core.crypto"));
        require.invoke(Clojure.read("buddy.core.codecs"));

        /**
           call with SECURE_RANDOM to avoid overhead of creating the SecureRandom instance on each invocation.
           see: https://github.com/funcool/buddy-core/blob/master/src/buddy/core/nonce.clj#L34
           and https://github.com/gerritjvv/crypto/issues/1
         */
        RANDOM_BYTES = Clojure.var("buddy.core.nonce", "random-bytes");
        SHA256 = Clojure.var("buddy.core.hash", "sha256");
        SHA512 = Clojure.var("buddy.core.hash", "sha512");

        ENCRYPT = Clojure.var("buddy.core.crypto", "encrypt");

        BUDDY_CONF_512 = Clojure.read("{:algorithm :aes256-cbc-hmac-sha512}");
        BUDDY_CONF_256 = Clojure.read("{:algorithm :aes128-cbc-hmac-sha256}");
        BUDDY_CONF_128_GCM = Clojure.read("{:algorithm :aes128-gcm}");

    }


    private static final Object PRE_HASHED_KEY_256 = SHA256.invoke("mysecretkeyt");

    private static final Object PRE_HASHED_KEY_128 = takeFirst16((byte[])SHA256.invoke("mysecretkeyt"));


    private static final Object PRE_HASHED_KEY_512 = SHA512.invoke("mysecretkeyt");

//    @Benchmark
//    public void aes128CbcHmacSha256() throws Exception {
//        ENCRYPT.invoke(
//                AesUtil.plaintext,
//                PRE_HASHED_KEY_256,
//                RANDOM_BYTES.invoke(16L, SECURE_RANDOM),
//                BUDDY_CONF_256);
//    }
//
//    @Benchmark
//    public void aes256CbcHmacSha512() throws Exception {
//        ENCRYPT.invoke(
//                AesUtil.plaintext,
//                PRE_HASHED_KEY_512,
//                RANDOM_BYTES.invoke(16L, SECURE_RANDOM),
//                BUDDY_CONF_512);
//    }
//
//    @Benchmark
//    public void aes256GCM() throws Exception {
//        ENCRYPT.invoke(
//                AesUtil.plaintext,
//                PRE_HASHED_KEY_128,
//                RANDOM_BYTES.invoke(12L),
//                BUDDY_CONF_128_GCM);
//    }


    /*
      Take the first 16 bytes of a 32 byte hash.
     */
    private static Object takeFirst16(byte[] bts) {
        return Arrays.copyOf(bts, 16);
    }
}
