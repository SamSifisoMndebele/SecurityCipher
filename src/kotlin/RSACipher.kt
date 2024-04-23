package kotlin

import java.nio.charset.StandardCharsets.UTF_16LE
import java.security.NoSuchAlgorithmException
import java.security.Key
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import javax.crypto.Cipher

object RSACipher {
    val Key.string: String
        get() {
            val bytes = Base64.getEncoder().encodeToString(this.encoded).toByteArray()
            return String(bytes, UTF_16LE)
        }

    val generateKeyPair: KeyPair
        get() {
            var keyPair: KeyPair? = null
            try {
                val keyPairGen = KeyPairGenerator.getInstance("RSA")
                keyPairGen.initialize(2048)
                keyPair = keyPairGen.generateKeyPair()
            } catch (e: NoSuchAlgorithmException) {
                e.printStackTrace()
            }
            assert(keyPair != null)
            return keyPair!!
        }

    fun encrypt(string: String?, publicKeyString: String): String? {
        if (string.isNullOrEmpty()) {
            return null
        }

        try {
            val publicKeyBytes = Base64.getDecoder().decode(publicKeyString.toByteArray(UTF_16LE))
            val publicKey = KeyFactory.getInstance("RSA").generatePublic(X509EncodedKeySpec(publicKeyBytes))

            val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
            cipher.init(Cipher.ENCRYPT_MODE, publicKey)

            val encryptedBytes = cipher.doFinal(string.toByteArray(UTF_16LE))
            val encryptedString = Base64.getEncoder().encodeToString(encryptedBytes)
            return String(encryptedString.toByteArray(), UTF_16LE)
        } catch (e: Exception) {
            e.printStackTrace()
            return null
        }
    }

    fun decrypt(string: String?, privateKeyString: String): String? {
        if (string.isNullOrEmpty()) {
            return null
        }

        try {
            val privateKeyBytes =
                Base64.getDecoder().decode(privateKeyString.toByteArray(UTF_16LE))
            val privateKey = KeyFactory.getInstance("RSA").generatePrivate(PKCS8EncodedKeySpec(privateKeyBytes))

            val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
            cipher.init(Cipher.DECRYPT_MODE, privateKey)

            val encryptedBytes = Base64.getDecoder().decode(string.toByteArray(UTF_16LE))
            val decryptedBytes = cipher.doFinal(encryptedBytes)

            return String(decryptedBytes, UTF_16LE)
        } catch (e: Exception) {
            e.printStackTrace()
            return null
        }
    }
}
