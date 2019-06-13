package crypto;

import org.junit.Assert;
import org.junit.Test;

public class AESTest {


    @Test
    public void testAesCBC128HMAC256_EncryptDecrypt() throws Exception{

        byte[] rawData = Util.genData(4096);

        Key.ExpandedKey key = Key.KeySize.AES_128.genKeysHmacSha();
        byte[] encryptedData = AES.encryptCBC(key, rawData);

        byte[] decryptedData = AES.decryptCBC(key, encryptedData);


        Assert.assertArrayEquals(rawData, decryptedData);
    }

    @Test
    public void testAesCBC256Hmac512_EncryptDecrypt() throws Exception{

        byte[] rawData = Util.genData(4096);

        Key.ExpandedKey key = Key.KeySize.AES_256.genKeysHmacSha();
        byte[] encryptedData = AES.encryptCBC(key, rawData);

        byte[] decryptedData = AES.decryptCBC(key, encryptedData);


        Assert.assertArrayEquals(rawData, decryptedData);
    }


    @Test
    public void testAesGcm128EncryptDecrypt() throws Exception{

        byte[] rawData = Util.genData(4096);

        Key.ExpandedKey key = Key.KeySize.AES_128.genKeysHmacSha();
        byte[] encryptedData = AES.encryptGCM(key, rawData);

        byte[] decryptedData = AES.decryptGCM(key, encryptedData);


        Assert.assertArrayEquals(rawData, decryptedData);
    }

}
