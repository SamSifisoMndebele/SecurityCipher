package kotlincode

import java.nio.charset.StandardCharsets.UTF_16LE
import java.security.NoSuchAlgorithmException
import java.util.*
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

object AESCipher {
    val generateSecretKey: String
        get() {
            var secretKey = ByteArray(16)
            try {
                val keyGenerator = KeyGenerator.getInstance("AES")
                keyGenerator.init(256) //32 bytes
                secretKey = keyGenerator.generateKey().encoded
            } catch (e: NoSuchAlgorithmException) {
                e.printStackTrace()
            }
            return String(secretKey, UTF_16LE)
        }

    fun encrypt(string: String?, secretKey: String): String? {
        if (string.isNullOrEmpty()) {
            return null
        }
        val secretKeyBytes = secretKey.toByteArray(UTF_16LE)
        try {
            val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
            cipher.init(Cipher.ENCRYPT_MODE,
                SecretKeySpec(secretKeyBytes, "AES"),
                IvParameterSpec(secretKeyBytes.copyOf(16)))

            val encryptedBytes = cipher.doFinal(string.toByteArray(UTF_16LE))
            val encryptedString = Base64.getEncoder().encodeToString(encryptedBytes)
            return String(encryptedString.toByteArray(), UTF_16LE)
        } catch (e: Exception) {
            e.printStackTrace()
            return null
        }
    }

    fun decrypt(string: String?, secretKey: String): String? {
        if (string.isNullOrEmpty()) return null
        try {
            val secretKeyBytes = secretKey.toByteArray(UTF_16LE)
            val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
            cipher.init(Cipher.DECRYPT_MODE,
                SecretKeySpec(secretKeyBytes, "AES"),
                IvParameterSpec(secretKeyBytes.copyOf(16)))

            val encryptedBytes = Base64.getDecoder().decode(string.toByteArray(UTF_16LE))
            val decryptedBytes = cipher.doFinal(encryptedBytes)

            return String(decryptedBytes, UTF_16LE)
        } catch (e: Exception) {
            e.printStackTrace()
            return null
        }
    }
}
