package crypto;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;

/**
 * Class that encrypts using AES, supports CBC+HMAC and GCM modes
 * <p>
 * Taken shamelessly from:
 * https://proandroiddev.com/security-best-practices-symmetric-encryption-with-aes-in-java-7616beaaade9
 * https://proandroiddev.com/security-best-practices-symmetric-encryption-with-aes-in-java-and-android-part-2-b3b80e99ad36
 * <p>
 * <p>
 * References:
 * GCM: https://tools.ietf.org/html/rfc4543#page-12
 * https://csrc.nist.gov/publications/detail/sp/800-38d/final
 */
public class AES {

    static {
        try {
            Security.setProperty("crypto.policy", "unlimited");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static final int CBC_IV_LENGTH = 16;
    public static final int GCM_IV_LENGTH = 12;

    public static final String AES_CBC_CIPHER_LBL = "AES/CBC/PKCS5Padding";
    public static final String AES_GCM_CIPHER_LBL = "AES/GCM/NoPadding";

    public static final byte[] encryptCBC(Key.ExpandedKey key, byte[] txt) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchProviderException {
        return encryptCBC((byte) 0, key, txt);
    }


    /**
     * Performs a AES CBC encryption with HMAC
     * The result is a byte array with
     * [ version:byte, iv-len:byte, iv:byte-array[iv-len], mac-len:byte, mac:byte-array[mac-len], encrypted-text:byte-array ]
     *
     * @param version any custom version you want to add to the output array
     * @param key the key to use
     * @param txt the text to encrypt
     * @return the encrypted byte array
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     * @throws NoSuchProviderException
     */
    public static final byte[] encryptCBC(byte version, Key.ExpandedKey key, byte[] txt) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchProviderException {
        return encryptCBC(version, null, key, txt);
    }

    /**
     *
     * This method allows to pass in a custom cipher provider.
     * By default please use {@link #encryptCBC(byte, Key.ExpandedKey, byte[])} which will use the default JCE provider.
     * @param version any custom version you want to add to the output array
     * @param key the key to use
     * @param txt the text to encrypt
     * @return the encrypted byte array
     *
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     * @throws NoSuchPaddingException
     * @throws NoSuchProviderException
     */
    public static final byte[] encryptCBC(byte version, String cipherProviderName, Key.ExpandedKey key, byte[] txt) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException, NoSuchProviderException {

        byte[] iv = new byte[CBC_IV_LENGTH];
        Random.nextBytes(iv);

        Cipher cipher = cipherProviderName == null ? Cipher.getInstance(AES_CBC_CIPHER_LBL) : Cipher.getInstance(AES_CBC_CIPHER_LBL, cipherProviderName);

        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key.encKey, "AES"), new IvParameterSpec(iv));
        byte[] cipherText = cipher.doFinal(txt);


        // HMAC output length:
        // 128 bits => 16
        // 256 bits => 32
        // 512 bits => 64
        SecretKey macKey = new SecretKeySpec(key.authKey, key.keySize.hmacLbl());
        Mac hmac = Mac.getInstance(key.keySize.hmacLbl());
        hmac.init(macKey);
        hmac.update(iv);
        hmac.update(cipherText);

        byte[] mac = hmac.doFinal();

        byte[] output = new byte[1 + 1 + iv.length + 1 + mac.length + cipherText.length];
        int i = 0;

        output[i++] = version;
        output[i++] = (byte) iv.length;
        System.arraycopy(iv, 0, output, i, iv.length);
        i += iv.length;

        if (mac.length > Byte.MAX_VALUE) {
            throw new RuntimeException("Mac length " + mac.length + " is bigger than allowed range: " + Byte.MAX_VALUE);
        }

        output[i++] = (byte) mac.length;

        System.arraycopy(mac, 0, output, i, mac.length);
        i += mac.length;

        System.arraycopy(cipherText, 0, output, i, cipherText.length);

        return output;

    }

    public static final byte[] decryptCBC(Key.ExpandedKey key, byte[] encryptedMessage) throws NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException, NoSuchPaddingException, NoSuchProviderException {
        return decryptCBC((byte) 0, key, encryptedMessage);
    }

    /**
     * Decrypt a AES CBC message encrypted with {@link #encryptCBC}
     * The expected message is:
     * <p>
     * [ version:byte, iv-len:byte, iv:byte-array[iv-len],  mac-len:byte, mac:byte-array[mac-len],  encrypted-text:byte-array
     *
     * @param version any custom version you want to add to the output array
     * @param key the key used to encrypt the data
     * @param encryptedMessage the encrypted data
     * @return the decrypted data
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchPaddingException
     * @throws NoSuchProviderException
     */
    public static final byte[] decryptCBC(byte version, Key.ExpandedKey key, byte[] encryptedMessage) throws NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException, NoSuchPaddingException, NoSuchProviderException {
        return decryptCBC(version, null, key, encryptedMessage);
    }

    /**
     * This method allows to pass in a custom cipher.
     * By default please use {@link #decryptCBC(byte, Key.ExpandedKey, byte[])}} which will use the default JCE provider.
     *
     * @param version any custom version you want to add to the output array
     * @param cipherProvider a JCE encryption provider
     * @param key the key used to encrypt the data
     * @param encryptedMessage the encrypted data
     * @return the decrypted data
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchPaddingException
     * @throws NoSuchProviderException
     */
    public static final byte[] decryptCBC(byte version, String cipherProvider, Key.ExpandedKey key, byte[] encryptedMessage) throws NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException, NoSuchPaddingException, NoSuchProviderException {

        int i = 0;
        int cipherVersion = encryptedMessage[i++];
        if (cipherVersion != version) {
            throw new RuntimeException("Version " + version + " was expected but the cipher message has " + cipherVersion);
        }

        int ivLength = encryptedMessage[i++];

        if (ivLength != CBC_IV_LENGTH) { // check input parameter
            throw new IllegalArgumentException("invalid iv length");
        }

        int ivPos = i;
        i += ivLength;

        int macLength = encryptedMessage[i++];

        if (macLength != key.keySize.getHMacSizeBytes()) { // check input parameter
            throw new IllegalArgumentException("invalid mac length");
        }

        int macPos = i;
        i += macLength;

        byte[] mac = new byte[macLength];
        System.arraycopy(encryptedMessage, macPos, mac, 0, macLength);

        int cipherTextPos = i;
        int cipherTextLen = encryptedMessage.length - cipherTextPos;

        // Before we decrypt we must validate the HMAC
        SecretKey macKey = new SecretKeySpec(key.authKey, key.keySize.hmacLbl());
        Mac hmac = Mac.getInstance(key.keySize.hmacLbl());
        hmac.init(macKey);
        hmac.update(encryptedMessage, ivPos, ivLength);
        hmac.update(encryptedMessage, cipherTextPos, cipherTextLen);

        byte[] refMac = hmac.doFinal();

        // Important, we must use a constant time equals method like MessageDigest
        // to avoid side channel attacks.
        if (!MessageDigest.isEqual(refMac, mac)) {
            throw new SecurityException("could not authenticate");
        }

        Cipher cipher = cipherProvider == null ? Cipher.getInstance(AES_CBC_CIPHER_LBL) : Cipher.getInstance(AES_CBC_CIPHER_LBL, cipherProvider);
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key.encKey, "AES"), new IvParameterSpec(encryptedMessage, ivPos, ivLength));
        return cipher.doFinal(encryptedMessage, cipherTextPos, cipherTextLen);
    }

    public static final byte[] encryptGCM(Key.ExpandedKey key, byte[] txt) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchProviderException {
        return encryptGCM((byte) 0, key, txt);
    }

    /**
     * Encryp a AES GCM message encrypted with {@link #encryptGCM}
     * The output message is:
     * <p>
     * [ version:byte, iv-len:byte, iv:byte-array[iv-len], encrypted-text:byte-array ]
     *
     * @param version any custom version you want to add to the output array
     * @param key the key to use for encryption
     * @param txt the text to encrypt
     * @return the encrypted data
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     * @throws NoSuchProviderException
     */
    public static final byte[] encryptGCM(byte version, Key.ExpandedKey key, byte[] txt) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchProviderException {
        return encryptGCM(version, null, key, txt);
    }

    /**
     * This method allows to pass in a custom cipher.
     * By default please use {@link #decryptGCM(byte, Key.ExpandedKey, byte[])}  which will use the default JCE provider.
     *
     * @param version any custom version you want to add to the output array
     * @param cipherProvider JCE provider
     * @param key the key to use for encryption
     * @param txt the plain text
     * @return the encrypted data
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     * @throws NoSuchProviderException
     */
    public static final byte[] encryptGCM(byte version, String cipherProvider, Key.ExpandedKey key, byte[] txt) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchProviderException {

        byte[] iv = new byte[GCM_IV_LENGTH];
        Random.nextBytes(iv);

        final Cipher cipher = cipherProvider == null ? Cipher.getInstance(AES_GCM_CIPHER_LBL) : Cipher.getInstance(AES_GCM_CIPHER_LBL, cipherProvider);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(key.keySize.getKeySizeBits(), iv);

        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key.encKey, "AES"), parameterSpec);
        byte[] cipherText = cipher.doFinal(txt);


        byte[] output = new byte[1 + 1 + iv.length + cipherText.length];
        int i = 0;
        output[i++] = version;
        output[i++] = (byte) iv.length;
        System.arraycopy(iv, 0, output, i, iv.length);
        i += iv.length;

        System.arraycopy(cipherText, 0, output, i, cipherText.length);

        return output;
    }

    /**
     *
     * @param key the key used for encryption
     * @param encryptedMessage the encrypted data
     * @return the decrypted data
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchPaddingException
     * @throws NoSuchProviderException
     */
    public static final byte[] decryptGCM(Key.ExpandedKey key, byte[] encryptedMessage) throws NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException, NoSuchPaddingException, NoSuchProviderException {
        return decryptGCM((byte) 0, key, encryptedMessage);
    }

    /**
     * Decrypt a AES GCM message encrypted with {@link #encryptGCM}
     * The expected message is:
     * <p>
     * [ version:byte, iv-len:byte, iv:byte-array[iv-len], encrypted-text:byte-array ]
     *
     * @param version any custom version you want to add to the output array
     * @param key the key used for encrypt the data
     * @param encryptedMessage the encrypted data
     * @return the decrypted data
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchPaddingException
     * @throws NoSuchProviderException
     */
    public static final byte[] decryptGCM(byte version, Key.ExpandedKey key, byte[] encryptedMessage) throws NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException, NoSuchPaddingException, NoSuchProviderException {
        return decryptGCM(version, null, key, encryptedMessage);
    }


    /**
     * This method allows to pass in a custom cipher.
     * By default please use {@link #decryptGCM(byte, Key.ExpandedKey, byte[])}  which will use the default JCE provider.
     *
     * @param version any custom version you want to add to the output array
     * @param cipherProvider JCE provider
     * @param key the key used to encrypt the data
     * @param encryptedMessage the encrypted data
     * @return the decrypted data
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchPaddingException
     * @throws NoSuchProviderException
     */
    public static final byte[] decryptGCM(byte version, String cipherProvider, Key.ExpandedKey key, byte[] encryptedMessage) throws NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException, NoSuchPaddingException, NoSuchProviderException {

        int i = 0;
        int cipherVersion = encryptedMessage[i++];
        if (cipherVersion != version) {
            throw new RuntimeException("Version " + version + " was expected but the cipher message has " + cipherVersion);
        }

        int ivLength = encryptedMessage[i++];

        if (ivLength != GCM_IV_LENGTH) { // check input parameter
            throw new IllegalArgumentException("invalid iv length: " + ivLength);
        }

        int ivPos = i;

        byte[] iv = new byte[ivLength];
        System.arraycopy(encryptedMessage, ivPos, iv, 0, ivLength);
        i += ivLength;

        int cipherTextPos = i;
        int cipherTextLen = encryptedMessage.length - cipherTextPos;


        final Cipher cipher = cipherProvider == null ? Cipher.getInstance(AES_GCM_CIPHER_LBL) : Cipher.getInstance(AES_GCM_CIPHER_LBL, cipherProvider);
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key.encKey, "AES"), new GCMParameterSpec(key.keySize.getKeySizeBits(), iv));

        return cipher.doFinal(encryptedMessage, cipherTextPos, cipherTextLen);
    }

}
