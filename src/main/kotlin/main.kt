fun main(args: Array<String>) {
    run(AnimalType.DogType)

    val kClass = Class.forName("Person").kotlin
    val args = arrayOf("won", 43)
    val person = kClass.constructors.first().call(*args)
    val person2 = createObject(Person::class, *args)
    println(person)
    println(person2)

}

fun run(animalType: AnimalType) {
    val age = 3334
    val animal = createObject(animalType.clazz, age)
    println("${animal.age}살의 ${animalType.selectText}")
    println("${animal.age}살의 ${animalType.hungryText}")
}