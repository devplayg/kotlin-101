package security

import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

object Aes256Cbc {
    private const val Transformation = "AES/CBC/PKCS5PADDING"
    private const val Algorithm = "AES"
    private const val HashAlgorithm = "SHA-256"
    private const val KeyLength = 16
    private const val Digits = "0123456789abcdef"
    private val HexChars = Digits.toByteArray()

    fun encrypt(data: ByteArray, secretKey: ByteArray): ByteArray {
        val cipher = Cipher.getInstance(Transformation)
        val ivParamSpec = IvParameterSpec(randomIv())
        val secretKeySpec = SecretKeySpec(generateHashKey(secretKey), Algorithm)
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParamSpec)
        val encrypted = cipher.doFinal(data)
        return ivParamSpec.iv!!.plus(encrypted)
    }

    fun encrypt(plainText: String, secretKey: String): String {
        val encrypted = this.encrypt(plainText.toByteArray(), secretKey.toByteArray())
        return this.byteArrayToHexString(encrypted)
    }


    @Throws(Exception::class)
    fun decrypt(cipherText: ByteArray, secretKey: ByteArray): ByteArray {
        val cipher = Cipher.getInstance(Transformation)
        val ivParamSpec = IvParameterSpec(cipherText, 0, 16)
        val key = SecretKeySpec(generateHashKey(secretKey), Algorithm)
        cipher.init(Cipher.DECRYPT_MODE, key, ivParamSpec)
        return cipher.doFinal(cipherText.sliceArray(16 until cipherText.size))
    }

    fun decrypt(cipherText: String, secretKey: String): String {
        val decrypted =  this.decrypt(hexStringToByteArray(cipherText), secretKey.toByteArray())
        return String(decrypted)
    }


    private fun randomIv(): ByteArray {
        val iv = ByteArray(KeyLength)
        SecureRandom.getInstanceStrong().nextBytes(iv)
        return iv
        //return Random.nextBytes(KeyLength)
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