#define CATCH_CONFIG_MAIN

#include <catch2/catch.hpp>

#include <sha2.hpp>

#include "hex_to_binary.hpp"

constexpr auto hex_to_binary = hex_to_binary_fun<32>;

using namespace jsribar::cryptography::sha2;

TEST_CASE("SHA-256 of empty string", "[SHA-256]")
{
    sha256_t sh{ };
    REQUIRE(sh.digest() == hex_to_binary("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
}

TEST_CASE("SHA-256 of a string 3 bytes long", "[SHA-256]")
{
    sha256_t sh1{ {'a', 'b', 'c' } };
    REQUIRE(sh1.digest() == hex_to_binary("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));

    sha256_t sh2{ {uint8_t('a'), uint8_t('b'), uint8_t('c') } };
    REQUIRE(sh2.digest() == hex_to_binary("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
}

TEST_CASE("SHA-256 of a string 55 bytes long - padding fits entirely into first message block", "[SHA-256]")
{
    sha256_t sh{ "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRS" };
    REQUIRE(sh.digest() == hex_to_binary("dd00794e0454db49259b6c426331d5e0cdf642fc0d7353fb85ee89519aafd995"));
}

TEST_CASE("SHA-256 of a string 62 bytes long - padding fits partially into first message block", "[SHA-256]")
{
    sha256_t sh{ "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ" };
    REQUIRE(sh.digest() == hex_to_binary("cf0071a083ad3e47349d2e3fbc896d07a0d50580b335c37e397d4091bf8e713b"));
}

TEST_CASE("SHA-256 of a string 64 bytes long - no padding in the first message block", "[SHA-256]")
{
    sha256_t sh{ "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ!@" };
    REQUIRE(sh.digest() == hex_to_binary("8bd8b71acf927db5f94100ae137bfb5769ee57d60b95dbbab294173ef073c01a"));
}

TEST_CASE("SHA-256 of a string 65 bytes long - message longer than one message block", "[SHA-256]")
{
    std::string input{ "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ!@#" };
    sha256_t sh{ input.data(), input.size() };
    REQUIRE(sh.digest() == hex_to_binary("b780d798616b8ef8fe461f3440a80e3f7990166b097df34a4701bb3246fd3827"));
}

TEST_CASE("SHA-256 of a string 186 bytes long - message longer than two message blocks", "[SHA-256]")
{
    std::string input{ "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ" };
    sha256_t sh{ input.data(), input.size() };
    REQUIRE(sh.digest() == hex_to_binary("75636aa5c963ecd75ae937f983685cd987afbab30a96b40469d1859c98f7795e"));
}

TEST_CASE("SHA-256 of a string 372 bytes long - message longer than five message blocks", "[SHA-256]")
{
    std::string input{ "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ" };
    sha256_t sh{ input.data(), input.size() };
    REQUIRE(sh.digest() == hex_to_binary("38152aa07185f3a9b730ca5f1985797d17e52fdbb1917cd5481428864c610b0a"));
}

TEST_CASE("SHA-256 of a string with multibyte UTF8 characters", "[SHA-256]")
{
    sha256_t sh{ "ABC\xC3\x80\xD2\x9A\xE0\xA6\xAA\xE1\xB9\x96" };
    REQUIRE(sh.digest() == hex_to_binary("80c598a8a3872ab20eed7e2c25c11f2c4e78800c2a69dd048ab097bd662dcb89"));
}

TEST_CASE("Compile time SHA-256 evaluation", "[SHA-256]")
{
    SECTION("Empty string")
    {
        STATIC_REQUIRE(sha256_t{ }.digest() == hex_to_binary("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
    }

    SECTION("String 3 bytes long")
    {
        STATIC_REQUIRE(sha256_t{ {'a', 'b', 'c' } }.digest() == hex_to_binary("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    }

    SECTION("String 55 bytes long")
    {
        STATIC_REQUIRE(sha256_t{ "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRS" }.digest() == hex_to_binary("dd00794e0454db49259b6c426331d5e0cdf642fc0d7353fb85ee89519aafd995"));
    }

    SECTION("String 63 bytes long")
    {
        static constexpr char input[] = { "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ" };
        STATIC_REQUIRE(sha256_t{ input, sizeof(input) - 1 }.digest() == hex_to_binary("cf0071a083ad3e47349d2e3fbc896d07a0d50580b335c37e397d4091bf8e713b"));
    }
}
