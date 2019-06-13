package crypto;

import java.util.Random;

public class Util {

    public static final byte[] genData(int byteLen) {
        byte[] v = new byte[byteLen];

        Random r = new Random();

        for (int i = 0; i < (byteLen); i++) {
            v[i] = (byte) r.nextInt(127);
        }

        return v;
    }
}
