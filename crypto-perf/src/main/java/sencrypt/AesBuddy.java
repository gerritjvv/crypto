package sencrypt;

import at.favre.lib.crypto.HKDF;
import clojure.java.api.Clojure;
import clojure.lang.IFn;
import org.openjdk.jmh.annotations.Benchmark;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

public class AesBuddy extends AesBase{

    public static final String PRE_HASHED_KEY = "mysecretkeyt";

    static final IFn RANDOM_BYTES;
    static final IFn SHA256, SHA512;
    static final IFn ENCRYPT;
    static final Object BUDDY_CONF_512, BUDDY_CONF_256, BUDDY_CONF_128_GCM;

    static {
        IFn require = Clojure.var("clojure.core", "require");
        require.invoke(Clojure.read("buddy.core.nonce"));
        require.invoke(Clojure.read("buddy.core.hash"));
        require.invoke(Clojure.read("buddy.core.crypto"));
        require.invoke(Clojure.read("buddy.core.codecs"));


        RANDOM_BYTES = Clojure.var("buddy.core.nonce", "random-bytes");
        SHA256 = Clojure.var("buddy.core.hash", "sha256");
        SHA512 = Clojure.var("buddy.core.hash", "sha512");

        ENCRYPT = Clojure.var("buddy.core.crypto", "encrypt");

        BUDDY_CONF_512 = Clojure.read("{:algorithm :aes256-cbc-hmac-sha512}");
        BUDDY_CONF_256 = Clojure.read("{:algorithm :aes128-cbc-hmac-sha256}");
        BUDDY_CONF_128_GCM = Clojure.read("{:algorithm :aes128-gcm}");

    }

    @Benchmark
    public void aes128CbcHmacSha256() throws Exception {
        ENCRYPT.invoke(
                AesUtil.plaintext,
                SHA256.invoke(PRE_HASHED_KEY),
                RANDOM_BYTES.invoke(16L),
                BUDDY_CONF_256);
    }

    @Benchmark
    public void aes256CbcHmacSha512() throws Exception {
        ENCRYPT.invoke(
                AesUtil.plaintext,
                SHA512.invoke(PRE_HASHED_KEY),
                RANDOM_BYTES.invoke(16L),
                BUDDY_CONF_512);
    }

    @Benchmark
    public void aes128GCM() throws Exception {
        ENCRYPT.invoke(
                AesUtil.plaintext,
                SHA256.invoke(PRE_HASHED_KEY),
                RANDOM_BYTES.invoke(12L),
                BUDDY_CONF_128_GCM);
    }


}
