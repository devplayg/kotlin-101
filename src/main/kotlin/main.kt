import security.Aes256Cbc
import java.security.MessageDigest
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.async
import kotlinx.coroutines.launch

fun encTest(prefix: String): String {
    val secret = "${prefix}secret"
    val encryptedStr = Aes256Cbc.encrypt("${prefix}테스트아아아", secret)

    var i = 0
    try {
        while (i < 1000000) {

            val decrypted = Aes256Cbc.decrypt(encryptedStr, secret)
//                    println(decrypted)
            i++
        }
    } catch (e: Exception) {
        println(e.message)
    }
    return "${prefix} done"
}

fun workParellel() {
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
    GlobalScope.launch {
//        val combined = one.await() + "/" + two.await() + "/" + three.await()
        val combined = one.await()+        two.await()+        three1.await()+        three2.await()+        three3.await()
        println(combined)
    }

}

fun main(args: Array<String>) {

    workParellel()
    readLine()
//    encTest("a")
//    val secret = "secret2"
//    val encryptedStr = Aes256Cbc.encrypt("비밀글", secret)
//    try {
//        val decrypted = Aes256Cbc.decrypt(encryptedStr, secret)
//        println(decrypted)
//    } catch (e: Exception) {
//        println(e.message)
//    }


//
//    val encryptedBytes = Aes256Cbc.encrypt("비밀글".toByteArray(), secret.toByteArray())
//    try {
//        val decrypted = Aes256Cbc.decrypt(encryptedBytes, secret.toByteArray())
//        println(String(decrypted))
//    } catch(e: Exception) {
//        println(e.message)
//    }

//    println(encrypted.fold("", { str, it -> str + "%02x".format(it) }))
//    val decrypted = Aes256Cbc.decrypt(encrypted, "secret")
//    println(decrypted)


//    println("hello")
//    val a1 = Random.nextBytes(16)
//    val a2 = Random.nextBytes(16)
//    val a3 = Random.nextBytes(16)

//    println(hash("test".toByteArray()))
//    println(hash("test".toByteArray()))
//    println(hash("test".toByteArray()))
//    println( a1.toString())
//    println( a2.toString())
//    println( a3.toString())
//    println(hash(a1))
//    println(hash(a2))
//    println(hash(a3))
//    println( Random.nextInt(16))
//    println( Random.nextInt(16))
//    println( Random.nextInt(16))
//
//    val r1 = List(10) { Random.nextInt(0, 16) }
//    println(r1)
//    val r2 = List(10) { Random.nextInt(0, 16) }
//    println(r2)
//    val r3 = List(10) { Random.nextInt(0, 16) }
//    println(r3)


/*
[B@2ef9b8bc
[B@5d624da6
[B@1e67b872

[B@2ef9b8bc
[B@5d624da6
[B@1e67b872

[8, 0, 2, 13, 13, 2, 13, 6, 15, 0]
[13, 1, 11, 2, 7, 9, 11, 3, 13, 0]
[12, 3, 4, 14, 1, 6, 8, 9, 7, 3]

[12, 12, 14, 6, 6, 6, 8, 9, 1, 7]
[5, 0, 14, 4, 8, 8, 15, 10, 10, 11]
[3, 15, 5, 9, 8, 2, 9, 1, 1, 1]
 */
}

fun hash(b: ByteArray): String {
    val md = MessageDigest.getInstance("SHA-256")
    val digest = md.digest(b)
    return digest.fold("", { str, it -> str + "%02x".format(it) })
}

