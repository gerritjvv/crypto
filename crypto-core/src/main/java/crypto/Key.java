package crypto;

import at.favre.lib.crypto.HKDF;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 *
 * Helper class to crete the appropriate sized keys for AES 128 and AES 256 bit encryption.
 *
 * For AES 128 HMAC SHA-256 is used.
 * For AES 256 HMAC SHA-512 is used.
 *
 * If you already have random keys generated you can use the ExpandedKey constructor directly.
 *
 */
public class Key {
    private static final byte[] ENC_KEY_META = "encKey".getBytes(StandardCharsets.UTF_8);
    private static final byte[] AUTH_KEY_META = "authKey".getBytes(StandardCharsets.UTF_8);


    public enum KeySize {
        AES_128(16, 32, "HmacSHA256"),
        AES_256(32, 64, "HmacSHA512");

        private final int sizeBts;
        private final int macSizeBts;
        private final String hmacLbl;

        KeySize(int sizeBts, int macSizeBts, String hmacLbl) {
            this.sizeBts = sizeBts;
            this.macSizeBts = macSizeBts;
            this.hmacLbl = hmacLbl;
        }

        public int getHMacSizeBytes() {
            return macSizeBts;
        }

        public int getKeySizeBytes() {
            return sizeBts;
        }

        public int getKeySizeBits() {
            return sizeBts * 8;
        }

        public String hmacLbl() {
            return hmacLbl;
        }

        /**
         * Return a new byte array of correct length, and initialised with random values.
         *
         */
        public byte[] newKey() {
            byte[] bts = new byte[sizeBts];
            Random.nextBytes(bts);

            return bts;
        }

        public ExpandedKey genKeysHmacSha() {
            return genKeysHmacSha(newKey());
        }

        /**
         * Generates a SHA-512 encryption key, and a SHA-256 authentication key.
         */
        /**
         *
         * @param key they key must already be a relatively random key.
         * @return
         */
        public ExpandedKey genKeysHmacSha(byte[] key) {
            byte[] encKey = HKDF.fromHmacSha512().expand(key, ENC_KEY_META, sizeBts);
            byte[] authKey = HKDF.fromHmacSha256().expand(key, AUTH_KEY_META, macSizeBts); //HMAC-SHA256 key is 32, HMAC-SHA512 key is 64 byte
            return new ExpandedKey(this, key, encKey, authKey);
        }

    }

    /**
     * Important: Do not use with a weak key like a user password, use {@link #deriveHmac256FromPass(byte[], byte[])}
     * @param randomKey must be an already good pseudo random key
     * @return 64 byte expanded key
     */
    public static final byte[] genHmacSha256(byte[] randomKey) {
        return HKDF.fromHmacSha256().expand(randomKey, ENC_KEY_META, 64);
    }

    /**
     * Extracts, and expands from a low entropy password using an optional sal.
     *
     * @param salt can be null
     * @param pass any non secure random key
     * @return a derived 64 byte key
     */
    public static final byte[] deriveHmac256FromPass (byte[] salt, byte[] pass) {
        byte[] pseudoRandomKey = HKDF.fromHmacSha256().extract(salt, pass);
        return  HKDF.fromHmacSha256().expand(pseudoRandomKey, null, 64);
    }
    /**
     * Extracts, and expands from a low entropy password using an optional sal.
     *
     * @param salt can be null
     * @param pass any non secure random key
     * @return a derived 64 byte key
     */
    public static final byte[] deriveHmac512FromPass (byte[] salt, byte[] pass) {
        byte[] pseudoRandomKey = HKDF.fromHmacSha512().extract(salt, pass);
        return  HKDF.fromHmacSha512().expand(pseudoRandomKey, null, 64);
    }

    /**
     * Hold the key and its expanded keys for encryption and authentication
     */
    public static class ExpandedKey {
        public KeySize keySize;

        public final byte[] orgKey;
        public final byte[] encKey;
        public final byte[] authKey;

        public ExpandedKey(KeySize keySize, byte[] orgKey, byte[] encKey, byte[] authKey) {
            this.keySize = keySize;
            this.orgKey = orgKey;
            this.encKey = encKey;
            this.authKey = authKey;
        }

        /**
         * Set all byte arrays passed into the construct to byte zero
         */
        public void destroy() {
            Arrays.fill(orgKey, (byte) 0);
            Arrays.fill(encKey, (byte) 0);
            Arrays.fill(authKey, (byte) 0);
        }
    }

}
