package sencrypt;

import crypto.AES;
import crypto.Key;
import crypto.Util;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.openjdk.jmh.annotations.Benchmark;

import java.security.Security;

/**
 * Uses the {@link BouncyCastleProvider} to encrypt and decrypt AES CBC and GCM data.
 */
public class AesBouncyCastle extends AesBase{

    private static final byte VERSION = (byte) 0;
    private static final String PROVIDER = BouncyCastleProvider.PROVIDER_NAME;

    private static byte[] GCM_128_ENCRYPTED;
    private static byte[] CBC_128_ENCRYPTED;

    private static byte[] DEFAULT_KEY = Util.genData(16);

    private static final Key.ExpandedKey ENC_DEFAULT_KEY_128 = Key.KeySize.AES_128.genKeysHmacSha(DEFAULT_KEY);

    static {
        try {
            Security.addProvider(new BouncyCastleProvider());

            GCM_128_ENCRYPTED = AES.encryptGCM(ENC_DEFAULT_KEY_128, AesUtil.plaintext);
            CBC_128_ENCRYPTED = AES.encryptCBC(ENC_DEFAULT_KEY_128, AesUtil.plaintext);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Benchmark
    public void enc_aes128CbcHmacSha256() throws Exception {
        AES.encryptCBC(VERSION, PROVIDER, ENC_DEFAULT_KEY_128, AesUtil.plaintext);
    }

    @Benchmark
    public void enc_aes128GCM() throws Exception {
        AES.encryptGCM(VERSION, PROVIDER, ENC_DEFAULT_KEY_128, AesUtil.plaintext);
    }


    @Benchmark
    public void dec_aes128CbcHmacSha256() throws Exception {
        AES.decryptCBC(VERSION, PROVIDER, ENC_DEFAULT_KEY_128, CBC_128_ENCRYPTED);
    }

    @Benchmark
    public void dec_aes128GCM() throws Exception {
        AES.decryptGCM(VERSION, PROVIDER, ENC_DEFAULT_KEY_128, GCM_128_ENCRYPTED);
    }
}
