import kotlin.AESCipher;
import kotlin.RSACipher;

import java.security.KeyPair;

public class Main {
    public static void main(String[] args) {

        String text = "Hello Sam Mndebele.";



        System.out.println("AESCipher");
        String secreteKey = AESCipher.generateSecretKey();
        String aesEncrypted = AESCipher.encrypt(text, secreteKey);
        String aesDecrypted = AESCipher.decrypt(aesEncrypted, secreteKey);
        System.out.println("encrypted : " + aesEncrypted);
        System.out.println("decrypted : " + aesDecrypted);


        System.out.println();
        System.out.println("RSACipher");
        KeyPair keyPair = RSACipher.generateKeyPair();
        String rsaEncrypted = RSACipher.encrypt(text, keyPair.getPublic());
        String rsaDecrypted = RSACipher.decrypt(rsaEncrypted, keyPair.getPrivate());
        System.out.println("encrypted : " + rsaEncrypted);
        System.out.println("decrypted : " + rsaDecrypted);
    }
}