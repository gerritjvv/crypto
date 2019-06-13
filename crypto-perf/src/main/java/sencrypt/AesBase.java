package sencrypt;

import java.security.Security;

public class AesBase {
    static {
        try {
            Security.setProperty("crypto.policy", "unlimited");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
