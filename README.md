# constexpr SHA-2

Implementation of SHA-2 cryptographic hash functions which enables compile time evaluation of message digests. This can be useful when strings are used in lookup tables, but you don't want those strings to be visible in executable code.

## Usage

Entire implementation is in a single header file `include/sha2.hpp`. It contains:

- `sha224_t` class that implements SHA-224 algorithm
- `sha256_t` class that implements SHA-256 algorithm
- `sha384_t` class that implements SHA-384 algorithm
- `sha512_t` class that implements SHA-512 algorithm
- `sha512_224_t` class that implements SHA-512/224 algorithm
- `sha512_256_t` class that implements SHA-512/256 algorithm.

Constructor accepts UTF8 encoded strings and digest is obtained by `digest` member function as an array of binary values:

```C++
#include <sha2.hpp>

using namespace jsribar::cryptography::sha2;

constexpr std::array<uint8_t, 32> digest = sha256_t{"abc"}.digest();
```

