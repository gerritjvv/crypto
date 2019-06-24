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
        public ExpandedKey genKeysHmacSha(byte[] key) {
            byte[] encKey = HKDF.fromHmacSha512().expand(key, ENC_KEY_META, sizeBts);
            byte[] authKey = HKDF.fromHmacSha256().expand(key, AUTH_KEY_META, macSizeBts); //HMAC-SHA256 key is 32, HMAC-SHA512 key is 64 byte
            return new ExpandedKey(this, key, encKey, authKey);
        }

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
