package sencrypt;

import crypto.AES;
import crypto.Key;
import crypto.Util;
import org.openjdk.jmh.annotations.Benchmark;

public class AesJce extends AesBase{

    private static byte[] GCM_128_ENCRYPTED;
    private static byte[] CBC_128_ENCRYPTED;
    private static byte[] CBC_256_ENCRYPTED;
    private static byte[] DEFAULT_KEY = Util.genData(16);

    private static final Key.ExpandedKey ENC_DEFAULT_KEY_128 = Key.KeySize.AES_128.genKeysHmacSha(DEFAULT_KEY);
    private static final Key.ExpandedKey ENC_DEFAULT_KEY_256 = Key.KeySize.AES_256.genKeysHmacSha(DEFAULT_KEY);

    static {
        try {
            GCM_128_ENCRYPTED = AES.encryptGCM(ENC_DEFAULT_KEY_128, AesUtil.plaintext);
            CBC_128_ENCRYPTED = AES.encryptCBC(ENC_DEFAULT_KEY_128, AesUtil.plaintext);
            CBC_256_ENCRYPTED = AES.encryptCBC(ENC_DEFAULT_KEY_256, AesUtil.plaintext);

        } catch (Exception e){
            e.printStackTrace();
        }
    }

    @Benchmark
    public void enc_aes128CbcHmacSha256() throws Exception {
        AES.encryptCBC(ENC_DEFAULT_KEY_128, AesUtil.plaintext);
    }

    @Benchmark
    public void enc_aes256CbcHmacSha512() throws Exception {
        AES.encryptCBC(ENC_DEFAULT_KEY_256, AesUtil.plaintext);
    }

    @Benchmark
    public void enc_aes128GCM() throws Exception {
        AES.encryptGCM(ENC_DEFAULT_KEY_128, AesUtil.plaintext);
    }


    @Benchmark
    public void dec_aes128CbcHmacSha256() throws Exception {
        AES.decryptCBC(ENC_DEFAULT_KEY_128, CBC_128_ENCRYPTED);
    }

    @Benchmark
    public void dec_aes256CbcHmacSha512() throws Exception {
        AES.decryptCBC(ENC_DEFAULT_KEY_256, CBC_256_ENCRYPTED);
    }

    @Benchmark
    public void dec_aes128GCM() throws Exception {
        AES.decryptGCM(ENC_DEFAULT_KEY_128, GCM_128_ENCRYPTED);
    }
}
