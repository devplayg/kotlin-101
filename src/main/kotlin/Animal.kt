import kotlin.reflect.KClass

sealed class Animal(open val age: Int) {
    data class Dog(override val age: Int) : Animal(age)
    data class Cat(override val age: Int) : Animal(age)
    data class Bird(override val age: Int) : Animal(age)
}

enum class AnimalType(
    val clazz: KClass<out Animal>,
    val selectText: String,
    val hungryText: String
) {
    DogType(Animal.Dog::class, "개를 선택했어요", "멍멍이는 배고파요"),
    CatType(Animal.Cat::class, "고양이를 선택했어요", "야옹이는 배고파요"),
    BirdType(Animal.Bird::class, "새를 선택했어요", "구구는 배고파요")
}

inline fun <reified T : Any> createObject(clazz: KClass<out T>): T {
    return clazz.constructors.first().call()
}

inline fun <reified T : Any> createObject(clazz: KClass<out T>, vararg args: Any?): T {
    return clazz.constructors.first().call(*args)
}

data class Person(
    val name: String,
    val age: Int
)