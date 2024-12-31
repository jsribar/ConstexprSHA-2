#include <catch2/catch.hpp>

#include <sha2.hpp>

#include "hex_to_binary.hpp"

constexpr auto hex_to_binary = hex_to_binary_fun<28>;

using namespace jsribar::cryptography::sha2;

TEST_CASE("SHA-512/224 of empty string", "[SHA-512/224]")
{
    sha512_224_t sh{ };
    REQUIRE(sh.digest() == hex_to_binary("6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4"));
}

TEST_CASE("SHA-512/224 of a string 3 bytes long", "[SHA-512/224]")
{
    sha512_224_t sh1{ {'a', 'b', 'c' } };
    REQUIRE(sh1.digest() == hex_to_binary("4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa"));

    sha512_224_t sh2{ {uint8_t('a'), uint8_t('b'), uint8_t('c') } };
    REQUIRE(sh2.digest() == hex_to_binary("4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa"));
}

TEST_CASE("SHA-512/224 of a string 112 bytes long - padding fits entirely into first message block", "[SHA-512/224]")
{
    sha512_224_t sh{ "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLM" };
    REQUIRE(sh.digest() == hex_to_binary("a3ebf62a12649b7967ede32b6696a84fe87b098593c8eb9f03c68f4e"));
}

TEST_CASE("SHA-512/224 of a string 114 bytes long - padding fits partially into first message block", "[SHA-512/224]")
{
    sha512_224_t sh{ "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNO" };
    REQUIRE(sh.digest() == hex_to_binary("a6b6a45eb59ab8376d10a6561c64b295d3a4b0f3ba744bc63730b9e4"));
}

TEST_CASE("SHA-512/224 of a string 128 bytes long - no padding in the first message block", "[SHA-512/224]")
{
    sha512_224_t sh{ "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcd" };
    REQUIRE(sh.digest() == hex_to_binary("b56df1f84844f3c84bed6bdb69a28e290c2e747e5b7658ce14f91ca5"));
}

TEST_CASE("SHA-512/224 of a string 129 bytes long - message longer than one message block", "[SHA-512/224]")
{
    std::string input{ "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcde" };
    sha512_224_t sh{ input.data(), input.size() };
    REQUIRE(sh.digest() == hex_to_binary("cc0eb8eda85f8e8ffd3bd55d56baa81aab4fb3ba2781c34b14650be3"));
}

TEST_CASE("SHA-512/224 of a string 256 bytes long - message two message blocks long", "[SHA-512/224]")
{
    std::string input{ "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh" };
    sha512_224_t sh{ input.data(), input.size() };
    REQUIRE(sh.digest() == hex_to_binary("924f85a0c58cb220c1baade000b3ec917570b47c104559febdb96461"));
}

TEST_CASE("SHA-512/224 of a string 372 bytes long - message longer than two message blocks", "[SHA-512/224]")
{
    std::string input{ "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ" };
    sha512_224_t sh{ input.data(), input.size() };
    REQUIRE(sh.digest() == hex_to_binary("e7ab75d2674bce8e1a5db9c60374231853a0ba1219aa8b39623ca4c2"));
}

TEST_CASE("SHA-512/224 of a string with multibyte UTF8 characters", "[SHA-512/224]")
{
    sha512_224_t sh{ "ABC\xC3\x80\xD2\x9A\xE0\xA6\xAA\xE1\xB9\x96" };
    REQUIRE(sh.digest() == hex_to_binary("57135d0931c0df245361a31c361cdcc0b987cf0ca80ef3be2e23d698"));
}

//TEST_CASE("Compile time SHA-512/224 evaluation", "[SHA-512/224]")
//{
//    SECTION("Empty string")
//    {
//        STATIC_REQUIRE(sha512_224_t{ }.digest() == hex_to_binary("6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4"));
//    }
//
//    SECTION("String 3 bytes long")
//    {
//        STATIC_REQUIRE(sha512_224_t{ {'a', 'b', 'c' } }.digest() == hex_to_binary("4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa"));
//    }
//
//    SECTION("String 112 bytes long")
//    {
//        STATIC_REQUIRE(sha512_224_t{ "a3ebf62a12649b7967ede32b6696a84fe87b098593c8eb9f03c68f4e" }.digest() == hex_to_binary("b25924089f64bccfd86494f892361503ea488470be98dfbc6efab75a8f0c8c1d"));
//    }
//
//    SECTION("String 128 bytes long")
//    {
//        static constexpr char input[] = { "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcd" };
//        STATIC_REQUIRE(sha512_224_t{ input, sizeof(input) - 1 }.digest() == hex_to_binary("b56df1f84844f3c84bed6bdb69a28e290c2e747e5b7658ce14f91ca5"));
//    }
//
//    SECTION("String 372 bytes long")
//    {
//        static constexpr char input[] = { "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ" };
//        STATIC_REQUIRE(sha512_224_t{ input, sizeof(input) - 1 }.digest() == hex_to_binary("e7ab75d2674bce8e1a5db9c60374231853a0ba1219aa8b39623ca4c2"));
//    }
//}
