#include <catch2/catch.hpp>

#include <sha2.hpp>

#include "hex_to_binary.hpp"

constexpr auto hex_to_binary = hex_to_binary_fun<28>;

using namespace jsribar::cryptography::sha2;

TEST_CASE("SHA-224 of empty string", "[SHA-224]")
{
    sha224_t sh{ };
    REQUIRE(sh.digest() == hex_to_binary("d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"));
}

TEST_CASE("SHA-224 of a string 3 bytes long", "[SHA-224]")
{
    sha224_t sh1{ {'a', 'b', 'c' } };
    REQUIRE(sh1.digest() == hex_to_binary("23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"));

    sha224_t sh2{ {uint8_t('a'), uint8_t('b'), uint8_t('c') } };
    REQUIRE(sh2.digest() == hex_to_binary("23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"));
}

TEST_CASE("SHA-224 of a string 55 bytes long - padding fits entirely into first message block", "[SHA-224]")
{
    sha224_t sh{ "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRS" };
    REQUIRE(sh.digest() == hex_to_binary("ae6e560dc4e93c44815c2905157f79dacdde742dd41b650d0eb58f73"));
}

TEST_CASE("SHA-224 of a string 62 bytes long - padding fits partially into first message block", "[SHA-224]")
{
    sha224_t sh{ "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ" };
    REQUIRE(sh.digest() == hex_to_binary("cdcff09b353d59ec815072d18c64cd56fcbc981e1e8c93983e391657"));
}

TEST_CASE("SHA-224 of a string 64 bytes long - no padding in the first message block", "[SHA-224]")
{
    sha224_t sh{ "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ!@" };
    REQUIRE(sh.digest() == hex_to_binary("3ab9bbbb2fdcca7f8412ba066fb9e10a72817468e155ba06d0ee189b"));
}

TEST_CASE("SHA-224 of a string 65 bytes long - message longer than one message block", "[SHA-224]")
{
    std::string input{ "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ!@#" };
    sha224_t sh{ input.data(), input.size() };
    REQUIRE(sh.digest() == hex_to_binary("334352603727a9b4c8684b736a3c973e1e9ab9ac267ef9aa9c08b5c9"));
}

TEST_CASE("SHA-224 of a string 186 bytes long - message longer than two message blocks", "[SHA-224]")
{
    std::string input{ "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ" };
    sha224_t sh{ input.data(), input.size() };
    REQUIRE(sh.digest() == hex_to_binary("80773eb57e61aedbfa1c5494d59bd6215d005b80567e6d8f7767eef0"));
}

TEST_CASE("SHA-224 of a string 372 bytes long - message longer than five message blocks", "[SHA-224]")
{
    std::string input{ "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ" };
    sha224_t sh{ input.data(), input.size() };
    REQUIRE(sh.digest() == hex_to_binary("e5602434b87ae082174097de68747199017b95b6e7d236350eb7a77f"));
}

TEST_CASE("SHA-224 of a string with multibyte UTF8 characters", "[SHA-224]")
{
    sha224_t sh{ "ABC\xC3\x80\xD2\x9A\xE0\xA6\xAA\xE1\xB9\x96" };
    REQUIRE(sh.digest() == hex_to_binary("af644e794ebe2b0ef5d9250025002834b7ed11399835a2b6a0bd4935"));
}

TEST_CASE("Compile time SHA-224 evaluation", "[SHA-224]")
{
    SECTION("Empty string")
    {
        STATIC_REQUIRE(sha224_t{ }.digest() == hex_to_binary("d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"));
    }

    SECTION("String 3 bytes long")
    {
        STATIC_REQUIRE(sha224_t{ {'a', 'b', 'c' } }.digest() == hex_to_binary("23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"));
    }

    SECTION("String 55 bytes long")
    {
        STATIC_REQUIRE(sha224_t{ "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRS" }.digest() == hex_to_binary("ae6e560dc4e93c44815c2905157f79dacdde742dd41b650d0eb58f73"));
    }

    SECTION("String 63 bytes long")
    {
        static constexpr char input[] = { "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ" };
        STATIC_REQUIRE(sha224_t{ input, sizeof(input) - 1 }.digest() == hex_to_binary("cdcff09b353d59ec815072d18c64cd56fcbc981e1e8c93983e391657"));
    }
}
