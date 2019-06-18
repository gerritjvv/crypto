package sencrypt;

import org.apache.commons.codec.digest.HmacAlgorithms;
import org.apache.commons.codec.digest.HmacUtils;
import org.apache.commons.crypto.cipher.CryptoCipher;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;
import java.util.Random;

/**
 * AES encryption helper functions. Mostly for apache commons encryption.
 *
 */
public class AesUtil {


    public static final byte[] plaintext = genData(4096); // 4kb


    public static final String CBC_CYPHER_TRANSFORM = "AES/CBC/PKCS5Padding";
    public static final String GCM_CYPHER_TRANSFORM = "AES/GCM/NoPadding";
    public static final int GCM_IV_SIZE = 12;
    public static final int CBC_IV_SIZE = 16;

    public static final SecureRandom RANDOM = new SecureRandom();


    /**
     * Encrypt the val byte array with AES GCM and return [iv.length, iv, encrypted-text]
     */
    public static byte[] encryptGCM(CryptoCipher encipher, SecretKey encKey, int ivSize, byte[] val) throws Exception {

        byte[] iv = new byte[ivSize];
        RANDOM.nextBytes(iv);

        encipher.init(Cipher.ENCRYPT_MODE, encKey, new GCMParameterSpec(96, iv));

        int cipherLen = (val.length / 16 + 1) * 16;
        byte[] cipherText = new byte[cipherLen];

        int len = encipher.doFinal(val, 0, val.length, cipherText, 0);

        byte[] output = new byte[1 + ivSize + len];
        int i = 0;
        output[i++] = (byte)ivSize;
        System.arraycopy(iv, 0, output, i, ivSize);
        i += ivSize;

        System.arraycopy(cipherText, 0, output, i, len);

        return output;
    }


    /**
     * Decrypt a message encrypted with {@link #encryptCBC(CryptoCipher, HmacAlgorithms, SecretKey, SecretKey, int, byte[])}
     */
    public static byte[] decryptCBC(CryptoCipher encipher, HmacAlgorithms hmacAlgo, SecretKey authKey, SecretKey enckey, byte[] encryptedMessage) throws Exception {
        int i = 0;

        int ivLength = encryptedMessage[i++];

        int ivPos = i;
        i += ivLength;

        int macLength = encryptedMessage[i++];

        int macPos = i;
        i += macLength;

        byte[] macBytes = new byte[macLength];
        System.arraycopy(encryptedMessage, macPos, macBytes, 0, macLength);

        int cipherTextPos = i;
        int cipherTextLen = encryptedMessage.length - cipherTextPos;

        // Before we decrypt we must validate the HMAC
        Mac mac = HmacUtils.getInitializedMac(hmacAlgo, authKey.getEncoded());

        mac.update(encryptedMessage, ivPos, ivLength);
        mac.update(encryptedMessage, cipherTextPos, cipherTextLen);

        byte[] refMac = mac.doFinal();

        // Important, we must use a constant time equals method like MessageDigest
        // to avoid side channel attacks.
        if (!MessageDigest.isEqual(refMac, macBytes)) {
            throw new SecurityException("could not authenticate");
        }

        encipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(enckey.getEncoded(), "AES"), new IvParameterSpec(encryptedMessage, ivPos, ivLength));

        byte[] output = new byte[encryptedMessage.length];

        int len = encipher.doFinal(encryptedMessage, cipherTextPos, cipherTextLen, output, 0);


        return len == output.length ? output : Arrays.copyOf(output, len);
    }


    /**
     * Decrypt a message encrypted with {@link #encryptGCM(CryptoCipher, SecretKey, int, byte[])}
     */
    public static final byte[] decryptGCM(CryptoCipher encipher, SecretKey encKey, byte[] encryptedMessage) throws Exception {

        int i = 0;
        int ivLength = encryptedMessage[i++];

        int ivPos = i;

        byte[] iv = new byte[ivLength];
        System.arraycopy(encryptedMessage, ivPos, iv, 0, ivLength);
        i += ivLength;

        int cipherTextPos = i;
        int cipherTextLen = encryptedMessage.length - cipherTextPos;

        encipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(encKey.getEncoded(), "AES"), new GCMParameterSpec(96, iv));

        byte[] output = new byte[encryptedMessage.length];

        int len = encipher.doFinal(encryptedMessage, cipherTextPos, cipherTextLen, output, 0);

        return len == output.length ? output : Arrays.copyOf(output, len);
    }


    /**
     * Encrypt the val bytes with AES CBC using a separate auth and enc key.
     * The bytes returns are [iv.length, iv, hmac.length, hmac, encryted-text]
     */
    public static byte[] encryptCBC(CryptoCipher encipher, HmacAlgorithms hmacAlgo, SecretKey authKey, SecretKey encKey, int ivSize, byte[] val) throws Exception {


        byte[] iv = new byte[ivSize];
        RANDOM.nextBytes(iv);

        encipher.init(Cipher.ENCRYPT_MODE, encKey, new IvParameterSpec(iv));

        int cipherLen = (val.length / 16 + 1) * 16;
        byte[] output = new byte[cipherLen];

        encipher.doFinal(val, 0, val.length, output, 0);


        return hmacTag(hmacAlgo, authKey.getEncoded(), iv, output);
    }

    /**
     * Generate an AES key with secure random data
     */
    public static SecretKey getKey(int keySize) throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(keySize, RANDOM);
        SecretKey key = keyGen.generateKey();

        return key;
    }


    /**
     * Create the hmac tagged byte array with [iv.len, iv, hmac.len, hmac, cipher-text]
     */
    private static byte[] hmacTag(HmacAlgorithms hmacAlgo, byte[] key, byte[] iv, byte[] cipherText) {

        Mac mac = HmacUtils.getInitializedMac(hmacAlgo, key);

        mac.update(iv);
        mac.update(cipherText);

        byte[] macBytes = mac.doFinal();

        byte[] output = new byte[1 + iv.length + 1 + macBytes.length + cipherText.length];
        int i = 0;

        output[i++] = (byte) iv.length;
        System.arraycopy(iv, 0, output, i, iv.length);
        i += iv.length;

        if (macBytes.length > Byte.MAX_VALUE) {
            throw new RuntimeException("Mac length " + macBytes.length + " is bigger than allowed range: " + Byte.MAX_VALUE);
        }

        output[i++] = (byte) macBytes.length;

        System.arraycopy(macBytes, 0, output, i, macBytes.length);
        i += macBytes.length;

        System.arraycopy(cipherText, 0, output, i, cipherText.length);

        return output;
    }

    /**
     * Get some random data
     */
    private static final byte[] genData(int byteLen) {
        byte[] v = new byte[byteLen];

        Random r = new Random();

        for (int i = 0; i < (byteLen); i++) {
            v[i] = (byte) r.nextInt(127);
        }

        return v;
    }

}