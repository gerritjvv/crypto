package crypto;

import java.security.SecureRandom;

public class Random {

    public static final SecureRandom secureRandom = new SecureRandom();


    public static final void nextBytes(byte[] bts) {
        secureRandom.nextBytes(bts);
    }
}
