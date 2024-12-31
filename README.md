# constexpr SHA-2

Implementation of SHA-2 cryptographic hash functions which enables compile time evaluation of message digests. This can be useful e.g. when strings are used in lookup tables but you don't want those strings to be visible in executable code.

Please note that implementation is far from optimal. The primary goal was to enable compile time generation of digest.

## Usage

Entire implementation is in a single header file `include/sha2.hpp`. It contains:

- `sha224_t` class that implements SHA-224 algorithm
- `sha256_t` class that implements SHA-256 algorithm
- `sha384_t` class that implements SHA-384 algorithm
- `sha512_t` class that implements SHA-512 algorithm
- `sha512_224_t` class that implements SHA-512/224 algorithm
- `sha512_256_t` class that implements SHA-512/256 algorithm.

Constructor accepts UTF8 encoded string and digest is obtained by `digest` member function as an array of binary values:

```C++
#include <sha2.hpp>
#include <string_view>

using namespace jsribar::cryptography::sha2;

constexpr std::array<uint8_t, 32> digest256 = sha256_t{"abc"}.digest();

constexpr std::string_view str{ "xyz" };
constexpr sha512_t sha512{ str };
constexpr auto digest512 = sha512.digest(); 
```

## Unit tests

`tests` directory contains unit tests. Unit tests use [Catch2 v2.x framework](https://github.com/catchorg/Catch2/tree/v2.x). To compile and run unit tests in Visual Studio solution provided, adjust the include path or simply set the environment variable `ThirParty` to point to the parent directory inside which Catch2 framework is cloned.

## References

- ‘SHA-2’ (2024). *Wikipedia*. Available at: https://en.wikipedia.org/wiki/SHA-2 (Accessed: 24 December 2024)
- ‘SHA256 Algorithm Explained’ (2024). Available at: https://sha256algorithm.com/ (Accessed: 24 December 2024)
- ‘Online Tools’ (2024). Available at: https://emn178.github.io/online-tools/ (Accessed: 24 December 2024)
- ‘Catch2’ (2024). Available at: https://github.com/catchorg/Catch2 (Accessed: 24 December 2024)
