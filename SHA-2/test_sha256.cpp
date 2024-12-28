#define CATCH_CONFIG_MAIN

#include <catch2/catch.hpp>

#include "sha256.hpp"

using namespace jsribar::cryptography::sha2;

template <size_t N = 32>
class hex_to_binary
{
public:
    constexpr explicit hex_to_binary(std::string_view str)
    {
        assert(str.size() == 2 * N);

        const auto hex_to_nibble = [](const auto c) -> uint8_t
            {
                if (c >= '0' && c <= '9')
                {
                    return c - '0';
                }
                if (c >= 'a' && c <= 'f')
                {
                    return c - 'a' + 10;
                }
                if (c >= 'A' && c <= 'F')
                {
                    return c - 'A' + 10;
                }
                assert(false);
                return 0;
            };

        for (int i = 0; i < 2 * N; i += 2)
        {
            const uint8_t hi = hex_to_nibble(str[i]);
            const uint8_t lo = hex_to_nibble(str[i + 1]);
            data_m[i / 2] = uint8_t(16) * hi + lo;
        }
    }

    constexpr std::array<uint8_t, N> operator()()
    {
        return data_m;
    }

private:
    std::array<uint8_t, N> data_m;
};


TEST_CASE("SHA-256 of empty string", "[SHA-256]")
{
    sha256_t sh{ };
    REQUIRE(sh.digest() == hex_to_binary{ "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" }());
}

TEST_CASE("SHA-256 of a string 3 bytes long", "[SHA-256]")
{
    sha256_t sh{ {uint8_t('a'), uint8_t('b'), uint8_t('c') } };
    REQUIRE(sh.digest() == hex_to_binary{ "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" }());
}

TEST_CASE("SHA-256 of a string 55 bytes long - padding fits entirely into first message block", "[SHA-256]")
{
    std::string input{ "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRS" };
    sha256_t sh{ std::bit_cast<const uint8_t*>(input.data()), input.size() };
    REQUIRE(sh.digest() == hex_to_binary{ "dd00794e0454db49259b6c426331d5e0cdf642fc0d7353fb85ee89519aafd995" }());
}

TEST_CASE("SHA-256 of a string 62 bytes long - padding fits partially into first message block", "[SHA-256]")
{
    std::string input{ "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ" };
    sha256_t sh{ std::bit_cast<const uint8_t*>(input.data()), input.size() };
    REQUIRE(sh.digest() == hex_to_binary{ "cf0071a083ad3e47349d2e3fbc896d07a0d50580b335c37e397d4091bf8e713b" }());
}

TEST_CASE("SHA-256 of a string 64 bytes long - no padding in the first message block", "[SHA-256]")
{
    std::string input{ "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ!@" };
    sha256_t sh{ std::bit_cast<const uint8_t*>(input.data()), input.size() };
    REQUIRE(sh.digest() == hex_to_binary{ "8bd8b71acf927db5f94100ae137bfb5769ee57d60b95dbbab294173ef073c01a" }());
}

TEST_CASE("SHA-256 of a string 65 bytes long - message longer than one message block", "[SHA-256]")
{
    std::string input{ "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ!@#" };
    sha256_t sh{ std::bit_cast<const uint8_t*>(input.data()), input.size() };
    REQUIRE(sh.digest() == hex_to_binary{ "b780d798616b8ef8fe461f3440a80e3f7990166b097df34a4701bb3246fd3827" }());
}

TEST_CASE("SHA-256 of a string 186 bytes long - message longer than two message blocks", "[SHA-256]")
{
    std::string input{ "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ" };
    sha256_t sh{ std::bit_cast<const uint8_t*>(input.data()), input.size() };
    REQUIRE(sh.digest() == hex_to_binary{ "75636aa5c963ecd75ae937f983685cd987afbab30a96b40469d1859c98f7795e" }());
}

TEST_CASE("SHA-256 of a string 372 bytes long - message longer than five message blocks", "[SHA-256]")
{
    std::string input{ "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ" };
    sha256_t sh{ std::bit_cast<const uint8_t*>(input.data()), input.size() };
    REQUIRE(sh.digest() == hex_to_binary{ "38152aa07185f3a9b730ca5f1985797d17e52fdbb1917cd5481428864c610b0a" }());
}

TEST_CASE("Compile time SHA-256 evaluation", "[SHA-256]")
{
    SECTION("Empty string")
    {
        STATIC_REQUIRE(sha256_t{ }.digest() == hex_to_binary{ "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" }());
    }

    SECTION("String 3 bytes long")
    {
        STATIC_REQUIRE(sha256_t{ {uint8_t('a'), uint8_t('b'), uint8_t('c') } }.digest() == hex_to_binary<32>{ "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" }());

        static constexpr std::array<uint8_t, 3> input{ 'a', 'b', 'c' };
        STATIC_REQUIRE(sha256_t{ input.data(), input.size() }.digest() == hex_to_binary{ "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" }());
    }

    SECTION("String 55 bytes long")
    {
        static constexpr uint8_t input[] = { "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRS" };
        STATIC_REQUIRE(sha256_t{ input, sizeof(input) - 1 }.digest() == hex_to_binary{ "dd00794e0454db49259b6c426331d5e0cdf642fc0d7353fb85ee89519aafd995" }());
    }

    SECTION("String 63 bytes long")
    {
        static constexpr uint8_t input[] = { "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ" };
        STATIC_REQUIRE(sha256_t{ input, sizeof(input) - 1 }.digest() == hex_to_binary{ "cf0071a083ad3e47349d2e3fbc896d07a0d50580b335c37e397d4091bf8e713b" }());
    }
}

