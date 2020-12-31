package security

import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

// https://tools.ietf.org/id/draft-irtf-cfrg-gcmsiv-06.html
object Aes256Utils {
    private const val Algorithm = "AES"
    private const val HashAlgorithm = "SHA-256" // for key spec.
    private const val Digits = "0123456789abcdef"
    private val HexChars = Digits.toByteArray()


    /**
     * AES-256 CBC Encryption and Decryption
     */
    object CBC {
        private const val Transformation = "AES/CBC/PKCS5PADDING"
        private const val IvLength = 16

        /**
         * Encrypt
         */
        fun encrypt(data: ByteArray, secretKey: ByteArray): ByteArray {
            val cipher = Cipher.getInstance(Transformation)
            val ivSpec = IvParameterSpec(randomNonce(IvLength))
            val keySpec = SecretKeySpec(generateHashKey(secretKey), Algorithm)
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec)
            val encrypted = cipher.doFinal(data)
            return ivSpec.iv!! + encrypted
        }

        fun encrypt(plainText: String, secretKey: String): String {
            val encrypted = this.encrypt(plainText.toByteArray(), secretKey.toByteArray())
            return byteArrayToHexString(encrypted)
        }


        /**
         * Decrypt
         */
        @Throws(Exception::class)
        fun decrypt(cipherText: ByteArray, secretKey: ByteArray): ByteArray {
            val cipher = Cipher.getInstance(Transformation)
            val ivSpec = IvParameterSpec(cipherText, 0, IvLength)
            val keySpec = SecretKeySpec(generateHashKey(secretKey), Algorithm)
            cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec)
            return cipher.doFinal(cipherText.sliceArray(IvLength until cipherText.size))
        }

        fun decrypt(cipherText: String, secretKey: String): String {
            val decrypted = this.decrypt(hexStringToByteArray(cipherText), secretKey.toByteArray())
            return String(decrypted)
        }

    }

    object GCM {
        private const val Transformation = "AES/GCM/NoPadding"
        private const val NonceSize = 96 / 8 // 96 bit
        private const val AuthTagLength = 128

        /**
         * Encrypt
         */
        fun encrypt(data: ByteArray, secretKey: ByteArray): ByteArray {
            val cipher = Cipher.getInstance(Transformation)
            val keySpec = SecretKeySpec(generateHashKey(secretKey), Algorithm)
            val nonce = randomNonce(NonceSize)
            val gcmSpec = GCMParameterSpec(AuthTagLength, nonce) // 128 bit authentication tag
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec)
            val encrypted = cipher.doFinal(data)
            return nonce + encrypted
        }


        fun encrypt(plainText: String, secretKey: String): String {
            val encrypted = this.encrypt(plainText.toByteArray(), secretKey.toByteArray())
            return byteArrayToHexString(encrypted)
        }


        /**
         * Decrypt
         */
        @Throws(Exception::class)
        fun decrypt(cipherText: ByteArray, secretKey: ByteArray): ByteArray {
            val cipher = Cipher.getInstance(Transformation)
            val keySpec = SecretKeySpec(generateHashKey(secretKey), Algorithm)
            val gcmSpec = GCMParameterSpec(128, cipherText, 0, 12)
            cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec)
            return cipher.doFinal(cipherText.sliceArray(12 until cipherText.size))
        }

        fun decrypt(cipherText: String, secretKey: String): String {
            val decrypted = this.decrypt(hexStringToByteArray(cipherText), secretKey.toByteArray())
            return String(decrypted)
        }
    }


    private fun randomNonce(len: Int): ByteArray {
        val iv = ByteArray(len)
        SecureRandom.getInstanceStrong().nextBytes(iv)
        return iv
        // return Random.nextBytes(IvLength)
    }

    private fun generateHashKey(key: ByteArray) = MessageDigest.getInstance(HashAlgorithm).digest(key)

    private fun byteArrayToHexString(byteArray: ByteArray): String {
        val hexChars = CharArray(byteArray.size * 2)
        for (i in byteArray.indices) {
            val v = byteArray[i].toInt() and 0xff
            hexChars[i * 2] = Digits[v shr 4]
            hexChars[i * 2 + 1] = Digits[v and 0xf]
        }
        return String(hexChars)
    }

    private fun hexStringToByteArray(src: String): ByteArray {
        val result = ByteArray(src.length / 2)

        for (i in src.indices step 2) {
            val firstIndex = HexChars.indexOf(src[i].toByte());
            val secondIndex = HexChars.indexOf(src[i + 1].toByte());
            val octet = firstIndex.shl(4).or(secondIndex)
            result[i.shr(1)] = octet.toByte()
        }

        return result
    }
}