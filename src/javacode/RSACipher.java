package javacode;

import org.jetbrains.annotations.NotNull;

import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class RSACipher {
    private final byte[] publicKeyBytes;
    private byte[] privateKeyBytes = null;

    public RSACipher() {
        KeyPair keyPair = generateKeyPair();
        publicKeyBytes = keyPair.getPublic().getEncoded();
        privateKeyBytes = keyPair.getPrivate().getEncoded();
    }
    public RSACipher(@NotNull KeyPair keyPair) {
        publicKeyBytes = keyPair.getPublic().getEncoded();
        privateKeyBytes = keyPair.getPrivate().getEncoded();
    }
    public RSACipher(@NotNull PublicKey publicKey, @NotNull PrivateKey privateKey) {
        publicKeyBytes = publicKey.getEncoded();
        privateKeyBytes = privateKey.getEncoded();
    }
    public RSACipher(@NotNull String publicKey, @NotNull String privateKey) {
        publicKeyBytes = Base64.getDecoder().decode(publicKey.getBytes(StandardCharsets.UTF_16LE));
        privateKeyBytes = Base64.getDecoder().decode(privateKey.getBytes(StandardCharsets.UTF_16LE));
    }
    public RSACipher(@NotNull String publicKey) {
        publicKeyBytes = Base64.getDecoder().decode(publicKey.getBytes(StandardCharsets.UTF_16LE));
    }
    public RSACipher(byte[] publicKey, byte[] privateKey) {
        publicKeyBytes = publicKey;
        privateKeyBytes = privateKey;
    }
    public RSACipher(byte[] publicKey) {
        publicKeyBytes = publicKey;
    }

    @NotNull
    public static String getKeyString(@NotNull Key key) {
        byte[] bytes = Base64.getEncoder().encodeToString(key.getEncoded()).getBytes();
        return new String(bytes, StandardCharsets.UTF_16LE);
    }
    @NotNull
    public static String getKeyString(byte[] keyBytes) {
        byte[] bytes = Base64.getEncoder().encodeToString(keyBytes).getBytes();
        return new String(bytes, StandardCharsets.UTF_16LE);
    }

    @NotNull
    public static KeyPair generateKeyPair() {
        KeyPair keyPair = null;
        try {
            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
            keyPairGen.initialize(2048);
            keyPair = keyPairGen.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        assert keyPair != null;
        return keyPair;
    }

    @NotNull
    public String getPublicKey() {
        return getKeyString(publicKeyBytes);
    }
    @NotNull
    public String getPrivateKey() {
        return getKeyString(privateKeyBytes);
    }

    public String encrypt(String string) {
        if (string == null || string.isEmpty()) {
            return null;
        }

        try {
            PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(publicKeyBytes));

            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);

            byte[] encryptedBytes = cipher.doFinal(string.getBytes(StandardCharsets.UTF_8));
            String encryptedString = Base64.getEncoder().encodeToString(encryptedBytes);
            return new String(encryptedString.getBytes(), StandardCharsets.UTF_16LE);
        } catch (Exception e){
            e.printStackTrace();
            return null;
        }
    }
    public static String encrypt(String string, @NotNull PublicKey publicKey) {
        if (string == null || string.isEmpty()) {
            return null;
        }

        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);

            byte[] encryptedBytes = cipher.doFinal(string.getBytes(StandardCharsets.UTF_8));
            String encryptedString = Base64.getEncoder().encodeToString(encryptedBytes);
            return new String(encryptedString.getBytes(), StandardCharsets.UTF_16LE);
        } catch (Exception e){
            e.printStackTrace();
            return null;
        }
    }
    public static String encrypt(String string, @NotNull String publicKeyString) {
        if (string == null || string.isEmpty()) {
            return null;
        }

        try {
            byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyString.getBytes(StandardCharsets.UTF_16LE));
            PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(publicKeyBytes));

            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);

            byte[] encryptedBytes = cipher.doFinal(string.getBytes(StandardCharsets.UTF_8));
            String encryptedString = Base64.getEncoder().encodeToString(encryptedBytes);
            return new String(encryptedString.getBytes(), StandardCharsets.UTF_16LE);
        } catch (Exception e){
            e.printStackTrace();
            return null;
        }
    }

    public String decrypt(String string) {
        if (string == null || string.isEmpty()) {
            return null;
        }

        try {
            PrivateKey privateKey = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));

            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);


            byte[] encryptedBytes = Base64.getDecoder().decode(string.getBytes(StandardCharsets.UTF_16LE));
            byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

            return new String(decryptedBytes, StandardCharsets.UTF_8);
        } catch (Exception e){
            e.printStackTrace();
            return null;
        }
    }
    public static String decrypt(String string, @NotNull PrivateKey privateKey) {
        if (string == null || string.isEmpty()) {
            return null;
        }

        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);

            byte[] encryptedBytes = Base64.getDecoder().decode(string.getBytes(StandardCharsets.UTF_16LE));
            byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

            return new String(decryptedBytes, StandardCharsets.UTF_8);
        } catch (Exception e){
            e.printStackTrace();
            return null;
        }
    }
    public static String decrypt(String string, @NotNull String privateKeyString) {
        if (string == null || string.isEmpty()) {
            return null;
        }

        try {
            byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyString.getBytes(StandardCharsets.UTF_16LE));
            PrivateKey privateKey = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));

            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);

            byte[] encryptedBytes = Base64.getDecoder().decode(string.getBytes(StandardCharsets.UTF_16LE));
            byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

            return new String(decryptedBytes, StandardCharsets.UTF_8);
        } catch (Exception e){
            e.printStackTrace();
            return null;
        }
    }
}
