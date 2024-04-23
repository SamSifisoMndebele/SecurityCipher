package javacode;

import java.security.KeyPair;

public class JMain {
    public static void main(String[] args) {

        String text = "Hello Sam Mndebele.";



        System.out.println("javacode.AESCipher");
        String secreteKey = AESCipher.generateSecretKey();
        String aesEncrypted = AESCipher.encrypt(text, secreteKey);
        String aesDecrypted = AESCipher.decrypt(aesEncrypted, secreteKey);
        System.out.println("encrypted : " + aesEncrypted);
        System.out.println("decrypted : " + aesDecrypted);


        System.out.println();
        System.out.println("javacode.RSACipher");
        KeyPair keyPair = RSACipher.generateKeyPair();
        String rsaEncrypted = RSACipher.encrypt(text, keyPair.getPublic());
        String rsaDecrypted = RSACipher.decrypt(rsaEncrypted, keyPair.getPrivate());
        System.out.println("encrypted : " + rsaEncrypted);
        System.out.println("decrypted : " + rsaDecrypted);
    }
}