import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import security.Aes256Utils
import java.security.MessageDigest
import java.util.*

fun encTest(prefix: String): String {
    val secret = Aes256Utils.generateHashKey("${prefix}secret".toByteArray())
    val plainText = "${prefix}-Test"
    val iv = MessageDigest.getInstance("SHA-256").digest("hello".toByteArray()).sliceArray(0 until 16)
    val cbcEncrypted = Aes256Utils.CBC.encrypt(plainText, secret)
    val cbcEncrypted2 = Aes256Utils.CBC.encrypt(plainText, secret, iv)
    val gcmEncrypted = Aes256Utils.GCM.encrypt(plainText, secret)

    var i = 0
    try {
        while (i < 10000) {
            // CBC
            val cbcDecrypted = Aes256Utils.CBC.decrypt(cbcEncrypted, secret)
            if (plainText != cbcDecrypted) {
                throw Exception("error; not matched")
            }


            val cbcDecrypted2 = Aes256Utils.CBC.decrypt(cbcEncrypted2, secret, iv)
            if (plainText != cbcDecrypted2) {
                throw Exception("error; not matched")
            }

            // GCM
            val gcmDecrypted = Aes256Utils.GCM.decrypt(gcmEncrypted, secret)
            if (plainText != gcmDecrypted) {
                throw Exception("error; not matched")
            }
            i++
        }
    } catch (e: Exception) {
        e.printStackTrace()
        println("[error] ${e.message}")
    }
    return "${prefix} done / "
}

fun run() {
    val one = GlobalScope.async {
        encTest("a")
    }
    val two = GlobalScope.async {
        encTest("b")
    }
    val three1 = GlobalScope.async {
        encTest("c")
    }
    val three2 = GlobalScope.async {
        encTest("d")
    }
    val three3 = GlobalScope.async {
        encTest("e")
    }
    runBlocking {
        val combined = one.await() + two.await() + three1.await() + three2.await() + three3.await()
        println(combined)
    }

}

fun main(args: Array<String>) {
    run()
}
