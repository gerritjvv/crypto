package sencrypt;

import crypto.AES;
import crypto.Key;
import crypto.Util;
import org.apache.commons.codec.digest.HmacAlgorithms;
import org.apache.commons.crypto.cipher.CryptoCipher;
import org.apache.commons.crypto.utils.Utils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.openjdk.jmh.annotations.Benchmark;

import java.util.Properties;

public class AesBouncyCastle {

    private static final byte VERSION = (byte)0;
    private static final String PROVIDER = BouncyCastleProvider.PROVIDER_NAME;

    private static byte[] GCM_128_ENCRYPTED;
    private static byte[] CBC_128_ENCRYPTED;
    private static byte[] CBC_256_ENCRYPTED;
    private static byte[] DEFAULT_KEY = Util.genData(16);

    static {
        try {
            GCM_128_ENCRYPTED = AES.encryptGCM(Key.KeySize.AES_128.genKeysHmacSha(DEFAULT_KEY), AesUtil.plaintext);
            CBC_128_ENCRYPTED = AES.encryptCBC(VERSION, PROVIDER, Key.KeySize.AES_128.genKeysHmacSha(DEFAULT_KEY), AesUtil.plaintext);
            CBC_256_ENCRYPTED = AES.encryptCBC(VERSION, PROVIDER, Key.KeySize.AES_256.genKeysHmacSha(DEFAULT_KEY), AesUtil.plaintext);
        } catch (Exception e){
            e.printStackTrace();
        }
    }


    @Benchmark
    public void enc_aes128CbcHmacSha256() throws Exception {
        Key.ExpandedKey key = Key.KeySize.AES_128.genKeysHmacSha();
        AES.encryptCBC(VERSION, PROVIDER, key, AesUtil.plaintext);
    }

    @Benchmark
    public void enc_aes256CbcHmacSha512() throws Exception {
        Key.ExpandedKey key = Key.KeySize.AES_256.genKeysHmacSha();
        AES.encryptCBC(VERSION, PROVIDER, key, AesUtil.plaintext);
    }

    @Benchmark
    public void enc_aes128GCM() throws Exception {
        Key.ExpandedKey key = Key.KeySize.AES_128.genKeysHmacSha();
        AES.encryptGCM(VERSION, PROVIDER, key, AesUtil.plaintext);
    }


    @Benchmark
    public void dec_aes128CbcHmacSha256() throws Exception {
        AES.decryptCBC(VERSION, PROVIDER, Key.KeySize.AES_128.genKeysHmacSha(DEFAULT_KEY), CBC_128_ENCRYPTED);
    }

    @Benchmark
    public void dec_aes256CbcHmacSha512() throws Exception {
        AES.decryptCBC(VERSION, PROVIDER, Key.KeySize.AES_256.genKeysHmacSha(DEFAULT_KEY), CBC_256_ENCRYPTED);
    }

    @Benchmark
    public void dec_aes128GCM() throws Exception {
        AES.decryptCBC(VERSION, PROVIDER, Key.KeySize.AES_128.genKeysHmacSha(DEFAULT_KEY), GCM_128_ENCRYPTED);
    }

}
