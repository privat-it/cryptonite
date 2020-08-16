# Сryptonite
Сryptonite - is a crypto library with support of Ukrainian cryptographic standards and cryptocontainers.

Implemented algorithms:

* GOST 34.310-95 (same as GOST R 34.10-94) - digital signature
* GOST 34.311-95 (same as GOST R 34.11-94) - hash function
* DSTU 4145-2002 - elliptic curve digital signature
* DSTU GOST 28147:2009 (same as GOST 28147-89) - block cipher "Magma" (Russian: "Магма")
* DSTU 7624:2014 - symmetric block cipher "Kalyna" (Ukrainian: "Калина")
* DSTU 7564:2014 - hash function "Kupyna" (Ukrainian: "Купина")
* AES - block cipher "Rijndael"
* DES - block cipher
* 3DES - block cipher
* DSA - digital signature
* ECDSA - elliptic curve digital signature
* RSA - digital signature
* RIPEMD - hash function
* SHA1 - hash funtion
* SHA2 - hash funtion
* MD5 - hash function

Expert opinion on the results of the Ukrainian state expertise in the field of cryptographic protection of information [No 04/03/02-4834 from 30.11.2016](http://www.dsszzi.gov.ua/dsszzi/control/uk/publish/article?art_id=316570&cat_id=72110) (Due date 25.11.2021) "Програмний виріб криптографічного захисту інформації “CRYPTONITE” UA.14360570.00001-01 90 01-1".

# CMake Build
```
cd cryptonite
mkdir build
cd build
cmake ..
cmake --build . --target all
cmake --build . --target install
```

# License
See [LICENSE](LICENSE) file.
