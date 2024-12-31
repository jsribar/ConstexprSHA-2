#include <catch2/catch.hpp>

#include <sha256.hpp>

#include "hex_to_binary.hpp"

using hex_to_binary = hex_to_binary_t<32>;

using namespace jsribar::cryptography::sha2;

TEST_CASE("SHA-512/256 of empty string", "[SHA-512/256]")
{
    sha512_256_t sh{ };
    REQUIRE(sh.digest() == hex_to_binary{ "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a" }());
}

TEST_CASE("SHA-512/256 of a string 3 bytes long", "[SHA-512/256]")
{
    sha512_256_t sh1{ {'a', 'b', 'c' } };
    REQUIRE(sh1.digest() == hex_to_binary{ "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23" }());

    sha512_256_t sh2{ {uint8_t('a'), uint8_t('b'), uint8_t('c') } };
    REQUIRE(sh2.digest() == hex_to_binary{ "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23" }());
}

TEST_CASE("SHA-512/256 of a string 112 bytes long - padding fits entirely into first message block", "[SHA-512/256]")
{
    sha512_256_t sh{ "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLM" };
    REQUIRE(sh.digest() == hex_to_binary{ "b25924089f64bccfd86494f892361503ea488470be98dfbc6efab75a8f0c8c1d" }());
}

TEST_CASE("SHA-512/256 of a string 114 bytes long - padding fits partially into first message block", "[SHA-512/256]")
{
    sha512_256_t sh{ "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNO" };
    REQUIRE(sh.digest() == hex_to_binary{ "071189a8df68c2588b9d1381f8e3e9260950c512e1ba7c6a44d5fbd1a88d9600" }());
}

TEST_CASE("SHA-512/256 of a string 128 bytes long - no padding in the first message block", "[SHA-512/256]")
{
    sha512_256_t sh{ "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcd" };
    REQUIRE(sh.digest() == hex_to_binary{ "0a7ae4a1ddf5529ab97d7570a56af7db75bef96a457bb46f5ef21d7957b81f59" }());
}

TEST_CASE("SHA-512/256 of a string 129 bytes long - message longer than one message block", "[SHA-512/256]")
{
    std::string input{ "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcde" };
    sha512_256_t sh{ input.data(), input.size() };
    REQUIRE(sh.digest() == hex_to_binary{ "b208953c82b61c9772b67f09f942858f694de80a9bf4163aa3c8888109684576" }());
}

TEST_CASE("SHA-512/256 of a string 256 bytes long - message two message blocks long", "[SHA-512/256]")
{
    std::string input{ "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh" };
    sha512_256_t sh{ input.data(), input.size() };
    REQUIRE(sh.digest() == hex_to_binary{ "9ae2ded63b4287e902ffb8775c0a998b491cde4cf62ea61078f40977964adcac" }());
}

TEST_CASE("SHA-512/256 of a string 372 bytes long - message longer than two message blocks", "[SHA-512/256]")
{
    std::string input{ "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ" };
    sha512_256_t sh{ input.data(), input.size() };
    REQUIRE(sh.digest() == hex_to_binary{ "caaa78c8ab763a1f3743b67b7b0b997115277c9d442ab79fcc82847c952478a3" }());
}

TEST_CASE("SHA-512/256 of a string with multibyte UTF8 characters", "[SHA-512/256]")
{
    sha512_256_t sh{ "ABC\xC3\x80\xD2\x9A\xE0\xA6\xAA\xE1\xB9\x96" };
    REQUIRE(sh.digest() == hex_to_binary{ "d011ba33f6c676d578a89e6c2d6cd827998793b15819558444ee74741806ef20" }());
}

TEST_CASE("Compile time SHA-512/256 evaluation", "[SHA-512/256]")
{
    SECTION("Empty string")
    {
        STATIC_REQUIRE(sha512_256_t{ }.digest() == hex_to_binary{ "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a" }());
    }

    SECTION("String 3 bytes long")
    {
        STATIC_REQUIRE(sha512_256_t{ {'a', 'b', 'c' } }.digest() == hex_to_binary{ "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23" }());
    }

    SECTION("String 112 bytes long")
    {
        STATIC_REQUIRE(sha512_256_t{ "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLM" }.digest() == hex_to_binary{ "b25924089f64bccfd86494f892361503ea488470be98dfbc6efab75a8f0c8c1d" }());
    }

    SECTION("String 128 bytes long")
    {
        static constexpr char input[] = { "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcd" };
        STATIC_REQUIRE(sha512_256_t{ input, sizeof(input) - 1 }.digest() == hex_to_binary{ "0a7ae4a1ddf5529ab97d7570a56af7db75bef96a457bb46f5ef21d7957b81f59" }());
    }

    SECTION("String 372 bytes long")
    {
        static constexpr char input[] = { "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ" };
        STATIC_REQUIRE(sha512_256_t{ input, sizeof(input) - 1 }.digest() == hex_to_binary{ "caaa78c8ab763a1f3743b67b7b0b997115277c9d442ab79fcc82847c952478a3" }());
    }
}
