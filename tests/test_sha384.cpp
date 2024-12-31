#include <catch2/catch.hpp>

#include <sha2.hpp>

#include "hex_to_binary.hpp"

constexpr auto hex_to_binary = hex_to_binary_fun<48>;

using namespace jsribar::cryptography::sha2;

TEST_CASE("SHA-384 of empty string", "[SHA-384]")
{
    sha384_t sh{ };
    REQUIRE(sh.digest() == hex_to_binary("38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"));
}

TEST_CASE("SHA-384 of a string 3 bytes long", "[SHA-384]")
{
    sha384_t sh1{ {'a', 'b', 'c' } };
    REQUIRE(sh1.digest() == hex_to_binary("cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"));

    sha384_t sh2{ {uint8_t('a'), uint8_t('b'), uint8_t('c') } };
    REQUIRE(sh2.digest() == hex_to_binary("cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"));
}

TEST_CASE("SHA-384 of a string 112 bytes long - padding fits entirely into first message block", "[SHA-384]")
{
    sha384_t sh{ "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLM" };
    REQUIRE(sh.digest() == hex_to_binary("b9ab0b0a6a45c15731e4f0d9e7816f45f924bae6c097135a6e34b26f0c898605127eed9248d893bdf6d226e6914469ee"));
}

TEST_CASE("SHA-384 of a string 114 bytes long - padding fits partially into first message block", "[SHA-384]")
{
    sha384_t sh{ "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNO" };
    REQUIRE(sh.digest() == hex_to_binary("001266429e59763b29bf0eda2751da628bfefa3cfed3c669429cbf17ad3ab6537716e9260f677e4ecef8a001d9690425"));
}

TEST_CASE("SHA-384 of a string 128 bytes long - no padding in the first message block", "[SHA-384]")
{
    sha384_t sh{ "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcd" };
    REQUIRE(sh.digest() == hex_to_binary("1ad0a330e25d75b61a484b520498e95fb6d0e36130b803e2286b3042786b010b0edc7f6b56f5b572014396418e4dff18"));
}

TEST_CASE("SHA-384 of a string 129 bytes long - message longer than one message block", "[SHA-384]")
{
    std::string input{ "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcde" };
    sha384_t sh{ input.data(), input.size() };
    REQUIRE(sh.digest() == hex_to_binary("91a6c80fffde68088c62b8a03c9b493530f2c1cb62b4df632b25e4ca36cb73922d55506ecbe565387e23db55f1bed892"));
}

TEST_CASE("SHA-384 of a string 256 bytes long - message two message blocks long", "[SHA-384]")
{
    std::string input{ "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh" };
    sha384_t sh{ input.data(), input.size() };
    REQUIRE(sh.digest() == hex_to_binary("62ee41183f57fb4cb3547b734f461adb96896f86379ab637054c3b0de4f15309bbd8af9139b4f3e8bcb851758a51a795"));
}

TEST_CASE("SHA-384 of a string 372 bytes long - message longer than two message blocks", "[SHA-384]")
{
    std::string input{ "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ" };
    sha384_t sh{ input.data(), input.size() };
    REQUIRE(sh.digest() == hex_to_binary("83a02e35bbe121941d57840c918fa9873a0fa2aa31c15ebd282f815f5e6c2592f456b41dbfe514f3519451cf9062b6ca"));
}

TEST_CASE("SHA-384 of a string with multibyte UTF8 characters", "[SHA-384]")
{
    sha384_t sh{ "ABC\xC3\x80\xD2\x9A\xE0\xA6\xAA\xE1\xB9\x96" };
    REQUIRE(sh.digest() == hex_to_binary("f4d3e13c942fb11dc71273e9ff4f432558a76544e3867f20afcd2d58a31f143471fb50ddc86b20a7078d06bd8f917c97"));
}

TEST_CASE("Compile time SHA-384 evaluation", "[SHA-384]")
{
    SECTION("Empty string")
    {
        STATIC_REQUIRE(sha384_t{ }.digest() == hex_to_binary("38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"));
    }

    SECTION("String 3 bytes long")
    {
        STATIC_REQUIRE(sha384_t{ {'a', 'b', 'c' } }.digest() == hex_to_binary("cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"));
    }

    SECTION("String 112 bytes long")
    {
        STATIC_REQUIRE(sha384_t{ "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLM" }.digest() == hex_to_binary("b9ab0b0a6a45c15731e4f0d9e7816f45f924bae6c097135a6e34b26f0c898605127eed9248d893bdf6d226e6914469ee"));
    }

    SECTION("String 128 bytes long")
    {
        static constexpr char input[] = { "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcd" };
        STATIC_REQUIRE(sha384_t{ input, sizeof(input) - 1 }.digest() == hex_to_binary("1ad0a330e25d75b61a484b520498e95fb6d0e36130b803e2286b3042786b010b0edc7f6b56f5b572014396418e4dff18"));
    }

    SECTION("String 372 bytes long")
    {
        static constexpr char input[] = { "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ" };
        STATIC_REQUIRE(sha384_t{ input, sizeof(input) - 1 }.digest() == hex_to_binary("83a02e35bbe121941d57840c918fa9873a0fa2aa31c15ebd282f815f5e6c2592f456b41dbfe514f3519451cf9062b6ca"));
    }
}
