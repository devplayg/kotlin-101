//
//object CharArrayShift {
//    private const val Digits = "0123456789abcdef"
//    private val HexChars = Digits.toByteArray()
//
//    fun toHexString(byteArray: ByteArray): String {
//        val hexChars = CharArray(byteArray.size * 2)
//        for (i in byteArray.indices) {
//            val v = byteArray[i].toInt() and 0xff
//            hexChars[i * 2] = Digits[v shr 4]
//            hexChars[i * 2 + 1] = Digits[v and 0xf]
//        }
//        return String(hexChars)
//    }
//
//    fun toByteArray(src: String): ByteArray {
//        val result = ByteArray(src.length / 2)
//
//        for (i in src.indices step 2) {
//            val firstIndex = HexChars.indexOf(src[i].toByte());
//            val secondIndex = HexChars.indexOf(src[i + 1].toByte());
//            val octet = firstIndex.shl(4).or(secondIndex)
//            result[i.shr(1)] = octet.toByte()
//        }
//
//        return result
//    }
//
//    fun toByteArray2(src: String) = ByteArray(src.length / 2) { src.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
//}
