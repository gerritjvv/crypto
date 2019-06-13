package sencrypt;

import crypto.AES;
import crypto.Key;
import crypto.Util;
import org.openjdk.jmh.annotations.Benchmark;

public class AesJce {

    private static byte[] GCM_128_ENCRYPTED;
    private static byte[] CBC_128_ENCRYPTED;
    private static byte[] CBC_256_ENCRYPTED;
    private static byte[] DEFAULT_KEY = Util.genData(16);

    static {
        try {
            GCM_128_ENCRYPTED = AES.encryptGCM(Key.KeySize.AES_128.genKeysHmacSha(DEFAULT_KEY), AesUtil.plaintext);
            CBC_128_ENCRYPTED = AES.encryptCBC(Key.KeySize.AES_128.genKeysHmacSha(DEFAULT_KEY), AesUtil.plaintext);
            CBC_256_ENCRYPTED = AES.encryptCBC(Key.KeySize.AES_256.genKeysHmacSha(DEFAULT_KEY), AesUtil.plaintext);
        } catch (Exception e){
            e.printStackTrace();
        }
    }


//    @Benchmark
//    public void enc_aes128CbcHmacSha256() throws Exception {
//        Key.ExpandedKey key = Key.KeySize.AES_128.genKeysHmacSha();
//        AES.encryptCBC(key, AesUtil.plaintext);
//    }
//
//    @Benchmark
//    public void enc_aes256CbcHmacSha512() throws Exception {
//        Key.ExpandedKey key = Key.KeySize.AES_256.genKeysHmacSha();
//        AES.encryptCBC(key, AesUtil.plaintext);
//    }
//
//    @Benchmark
//    public void enc_aes128GCM() throws Exception {
//        Key.ExpandedKey key = Key.KeySize.AES_128.genKeysHmacSha();
//        AES.encryptGCM(key, AesUtil.plaintext);
//    }


//    @Benchmark
//    public void dec_aes128CbcHmacSha256() throws Exception {
//        AES.decryptCBC(Key.KeySize.AES_128.genKeysHmacSha(DEFAULT_KEY), CBC_128_ENCRYPTED);
//    }
//
//    @Benchmark
//    public void dec_aes256CbcHmacSha512() throws Exception {
//        AES.decryptCBC(Key.KeySize.AES_256.genKeysHmacSha(DEFAULT_KEY), CBC_256_ENCRYPTED);
//    }
//
//    @Benchmark
//    public void dec_aes128GCM() throws Exception {
//        AES.decryptCBC(Key.KeySize.AES_128.genKeysHmacSha(DEFAULT_KEY), GCM_128_ENCRYPTED);
//    }


}
