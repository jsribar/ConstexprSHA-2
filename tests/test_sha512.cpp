#include <catch2/catch.hpp>

#include <sha2.hpp>

#include "hex_to_binary.hpp"

constexpr auto hex_to_binary = hex_to_binary_fun<64>;

using namespace jsribar::cryptography::sha2;

TEST_CASE("SHA-512 of empty string", "[SHA-512]")
{
    sha512_t sh{ };
    REQUIRE(sh.digest() == hex_to_binary("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"));
}

TEST_CASE("SHA-512 of a string 3 bytes long", "[SHA-512]")
{
    sha512_t sh1{ {'a', 'b', 'c' } };
    REQUIRE(sh1.digest() == hex_to_binary("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"));

    sha512_t sh2{ {uint8_t('a'), uint8_t('b'), uint8_t('c') } };
    REQUIRE(sh2.digest() == hex_to_binary("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"));
}

TEST_CASE("SHA-512 of a string 112 bytes long - padding fits entirely into first message block", "[SHA-512]")
{
    sha512_t sh{ "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLM" };
    REQUIRE(sh.digest() == hex_to_binary("65369b0fabe317f013bd5d2726417b4a84cf64cc2f3d6a07bc31f3ad29be12c77f0d1ca9036000bab7a141ef244371ace2c0ffe43bf286f06729004e2e8df785"));
}

TEST_CASE("SHA-512 of a string 114 bytes long - padding fits partially into first message block", "[SHA-512]")
{
    sha512_t sh{ "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNO" };
    REQUIRE(sh.digest() == hex_to_binary("d55815929d81f06078f04267d28fe732a41b21d5ed0ca54c45ceaeea25016af8ccc6d489c5ce1bec4550a6234620011a0655ddcccf2b8f3950d29ef32578d5de"));
}

TEST_CASE("SHA-512 of a string 128 bytes long - no padding in the first message block", "[SHA-512]")
{
    sha512_t sh{ "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcd" };
    REQUIRE(sh.digest() == hex_to_binary("2afd0138e2d25402033bfbe9716eabbcc59b7ecfde2b2b7370a921595879ec3be3d397a240a204a7975f875bbc5d397b2e185e9ee430cd3a471091c883190d72"));
}

TEST_CASE("SHA-512 of a string 129 bytes long - message longer than one message block", "[SHA-512]")
{
    std::string input{ "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcde" };
    sha512_t sh{ input.data(), input.size() };
    REQUIRE(sh.digest() == hex_to_binary("91adba6efb00cce51e959adaa535adc04fc0e6232690bc415d2d93277c982ee2f20bcba34e5e6158f9727a8f2f119b7d3ed5247405da68384386bbec173c32f6"));
}

TEST_CASE("SHA-512 of a string 256 bytes long - message two message blocks long", "[SHA-512]")
{
    std::string input{ "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh" };
    sha512_t sh{ input.data(), input.size() };
    REQUIRE(sh.digest() == hex_to_binary("0a1a879730b6f8d8c5f64d8511ab111d907d9e532ecb1b64178b2ffec89d08f0398bbd1b89f5c8a7626fe802e4eb64cdeed9aa6a96af57db1235358248d4384d"));
}

TEST_CASE("SHA-512 of a string 372 bytes long - message longer than two message blocks", "[SHA-512]")
{
    std::string input{ "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ" };
    sha512_t sh{ input.data(), input.size() };
    REQUIRE(sh.digest() == hex_to_binary("66d32b2ea5a81c9d8bbedfb3feb83ab8ae136e80f30e7b911df9328f1033c1e6969983a4a483a0f97321311570da5bfdeaba896d82135141bfe3f2f48fb2d271"));
}

TEST_CASE("SHA-512 of a string with multibyte UTF8 characters", "[SHA-512]")
{
    sha512_t sh{ "ABC\xC3\x80\xD2\x9A\xE0\xA6\xAA\xE1\xB9\x96" };
    REQUIRE(sh.digest() == hex_to_binary("c373d3a679115f9f6f765cce2ae3951f7dfcad44fca90860ef8904c2d46a201506734012a0094869fac08fb231ab417a2f2a3e4573cdb789f12ade6a22a83daf"));
}

TEST_CASE("Compile time SHA-512 evaluation", "[SHA-512]")
{
    SECTION("Empty string")
    {
        STATIC_REQUIRE(sha512_t{ }.digest() == hex_to_binary("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"));
    }

    SECTION("String 3 bytes long")
    {
        STATIC_REQUIRE(sha512_t{ {'a', 'b', 'c' } }.digest() == hex_to_binary("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"));
    }

    SECTION("String 112 bytes long")
    {
        STATIC_REQUIRE(sha512_t{ "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLM" }.digest() == hex_to_binary("65369b0fabe317f013bd5d2726417b4a84cf64cc2f3d6a07bc31f3ad29be12c77f0d1ca9036000bab7a141ef244371ace2c0ffe43bf286f06729004e2e8df785"));
    }

    SECTION("String 128 bytes long")
    {
        static constexpr char input[] = { "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcd" };
        STATIC_REQUIRE(sha512_t{ input, sizeof(input) - 1 }.digest() == hex_to_binary("2afd0138e2d25402033bfbe9716eabbcc59b7ecfde2b2b7370a921595879ec3be3d397a240a204a7975f875bbc5d397b2e185e9ee430cd3a471091c883190d72"));
    }

    SECTION("String 372 bytes long")
    {
        static constexpr char input[] = { "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ" };
        STATIC_REQUIRE(sha512_t{ input, sizeof(input) - 1 }.digest() == hex_to_binary("66d32b2ea5a81c9d8bbedfb3feb83ab8ae136e80f30e7b911df9328f1033c1e6969983a4a483a0f97321311570da5bfdeaba896d82135141bfe3f2f48fb2d271"));
    }
}
