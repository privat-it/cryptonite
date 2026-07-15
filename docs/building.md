# Збірка Cryptonite

Основна система збірки — **CMake** (≥ 3.16). Історична Gradle-збірка
залишена в репозиторії, але вважається застарілою (див. нижче).

## CMake

Потрібні CMake ≥ 3.16 та C-компілятор (GCC/Clang/MinGW).

```sh
cmake -B build
cmake --build build -j
```

### Опції

| Опція | Типово | Призначення |
|-------|--------|-------------|
| `BUILD_SHARED_LIBS` | `OFF` | збирати бібліотеки як shared замість static |
| `CRYPTONITE_WERROR` | `OFF` | `-Werror`; код чистий під `-Wall` (GCC 13/15), CI вмикає цю опцію |
| `CRYPTONITE_BUILD_XTEST` | `OFF` | крос-тести проти системних OpenSSL/libgcrypt/bee2/cppcrypto |
| `CRYPTONITE_BUILD_FUZZERS` | `OFF` | libFuzzer-харнеси декодерів (`fuzz/`, потрібен Clang) |

### Основні цілі

| Ціль | Тип | Залежить від |
|------|-----|--------------|
| `pthread_impl` | бібліотека | — |
| `cryptonite` | бібліотека | `pthread_impl` (+ `bcrypt` на Windows) |
| `asn1` | бібліотека | `cryptonite` |
| `pkix` | бібліотека | `asn1`, `cryptonite` |
| `storage` | бібліотека | `pkix` |
| `cryptoniteUtest`, `pkixUtest`, `storageUtest`, `asn1Utest` | виконувані тести | відповідні бібліотеки |
| `cryptoniteAtest`, `cryptonitePtest` | приймальні/перф. тести | `cryptonite` |
| `cryptoniteXtest` | крос-тести | системні OpenSSL, libgcrypt, bee2, cppcrypto (опція `CRYPTONITE_BUILD_XTEST`) |
| `cryptoniteExample`, `pkiExample` | демонстраційні програми | — |
| `example_*` (папка `examples/`) | короткі самодостатні приклади | `storage` |

Важливо: макрос `CRYPTONITE_EXPORT=extern` задається на рівні кореневого
`CMakeLists.txt` — якщо підключаєте заголовки до свого проєкту в обхід
CMake, визначте його самостійно.

### Тести (CTest)

```sh
ctest --test-dir build --output-on-failure
```

Зареєстровані тести: `cryptoniteUtest`, `asn1Utest`, `storageUtest`,
`pkixUtest`. Тести читають ресурси відносно кореня репозиторію — CTest
задає правильну робочу директорію сам; при ручному запуску виконуйте
бінарники з кореня репозиторію.

Примітка: `pkixUtest` містить дата-залежний тест — він перевіряє чинність
тестового сертифіката `src/pkixUtest/resources/acsk_cert.cer` на поточну
дату, а сертифікат уже протермінований. Тест зареєстрований у CTest як
очікувано-падаючий (`WILL_FAIL`), тож загальний прогін це враховує.

### Встановлення

```sh
cmake --install build --prefix /бажаний/шлях
```

Встановлюються бібліотеки та публічні заголовки:
`include/cryptonite` (ядро), `include/cryptonite/asn1`,
`include/cryptonite/pkix`, `include/cryptonite/storage`.

## Gradle (видалена)

Історична збірка на Gradle 2.14.1 з нативними плагінами software model
(`c`/`cpp`) та `gradle-experimental` для Android видалена з репозиторію:
ці плагіни не існують у сучасних версіях Gradle, а прекомпільовані
сторонні бібліотеки для крос-тестів (`libs/`, 278 МБ) застаріли на
десятиліття. Скрипти доступні в історії git.

Для Android актуальний шлях — стандартний Android Gradle Plugin з
`externalNativeBuild`, який використовує той самий CMake.

## Документація API

```sh
doxygen Doxyfile     # результат: docs/api/html/index.html
```
