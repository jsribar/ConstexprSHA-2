#include "sha256.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <cassert>
#include <string>

using namespace jsribar::cryptography::sha2;


constexpr std::array<uint8_t, 8> data{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };

static_assert(to_uint<uint8_t>(data.data()) == uint8_t(0x01));
static_assert(to_uint<uint16_t>(data.data()) == uint16_t(0x0102));
static_assert(to_uint<uint32_t>(data.data()) == uint32_t(0x01020304));
static_assert(to_uint<uint64_t>(data.data()) == uint64_t(0x0102030405060708));



static_assert(right_rotate(uint32_t(0x01020304), 8) == 0x04010203);
static_assert(right_rotate(uint32_t(0x01020304), 16) == 0x03040102);
static_assert(right_rotate(uint32_t(0x01020304), 3) == 0x80204060);
static_assert(right_rotate(uint32_t(0x01020304), 7) == 0x08020406);



static_assert(sha256_t{ }.digest() == hex_to_binary<32>{ "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" }());


static_assert(sha256_t{ {uint8_t('a'), uint8_t('b'), uint8_t('c') } }.digest() == hex_to_binary<32>{ "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" }());


static constexpr std::array<uint8_t, 3> input1{ 'a', 'b', 'c' };
static constexpr sha256_t sh3{ input1.data(), input1.size() };
static_assert(sh3.digest() == hex_to_binary<32>{ "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" }());


static constexpr uint8_t input2[] = { "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRS" };
static constexpr sha256_t sh4{ input2, sizeof(input2) - 1 };
static_assert(sh4.digest() == hex_to_binary<32>{ "dd00794e0454db49259b6c426331d5e0cdf642fc0d7353fb85ee89519aafd995" }());


int main()
{
    {
        std::array<uint8_t, 8> buffer{ 0 };

        to_uint8_array(uint8_t(0x01), buffer.data());
        assert(buffer.at(0) == 0x01);

        to_uint8_array(uint16_t(0x0102), buffer.data());
        assert(buffer.at(0) == 0x01);
        assert(buffer.at(1) == 0x02);

        to_uint8_array(uint32_t(0x01020304), buffer.data());
        assert(buffer.at(0) == 0x01);
        assert(buffer.at(1) == 0x02);
        assert(buffer.at(2) == 0x03);
        assert(buffer.at(3) == 0x04);

        to_uint8_array(uint64_t(0x0102030405060708), buffer.data());
        assert(buffer.at(0) == 0x01);
        assert(buffer.at(1) == 0x02);
        assert(buffer.at(2) == 0x03);
        assert(buffer.at(3) == 0x04);
        assert(buffer.at(4) == 0x05);
        assert(buffer.at(5) == 0x06);
        assert(buffer.at(6) == 0x07);
        assert(buffer.at(7) == 0x08);
    }


    {
#pragma warning( suppress : 4838)
        const std::array<uint8_t, 32> input{ '\xBA', '\x78', '\x16', '\xBF', '\x8F', '\x01', '\xCF', '\xEA', '\x41', '\x41', '\x40', '\xDE', '\x5D', '\xAE', '\x22', '\x23', '\xB0', '\x03', '\x61', '\xA3', '\x96', '\x17', '\x7A', '\x9C', '\xB4', '\x10', '\xFF', '\x61', '\xF2', '\x00', '\x15', '\xAD' };
        assert(hex_to_binary<32>{ "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" }() == input);
    }


    {
        sha256_t sh{ };

        assert(sh.digest() == hex_to_binary<32>{ "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" }());
    }

    {
        sha256_t sh{ {uint8_t('a'), uint8_t('b'), uint8_t('c') } };

        assert(sh.digest() == hex_to_binary<32>{ "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" }());
    }

    {
        std::string input{ "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRS" };

        sha256_t sh{ std::bit_cast<const uint8_t*>(input.data()), input.size() };

        assert(sh.digest() == hex_to_binary<32>{ "dd00794e0454db49259b6c426331d5e0cdf642fc0d7353fb85ee89519aafd995" }());
    }

    {
        std::string input{ "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ" };

        sha256_t sh{ std::bit_cast<const uint8_t*>(input.data()), input.size() };

        assert(sh.digest() == hex_to_binary<32>{ "cf0071a083ad3e47349d2e3fbc896d07a0d50580b335c37e397d4091bf8e713b" }());
    }

    {
        std::string input{ "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ!@" };

        sha256_t sh{ std::bit_cast<const uint8_t*>(input.data()), input.size() };

        assert(sh.digest() == hex_to_binary<32>{ "8bd8b71acf927db5f94100ae137bfb5769ee57d60b95dbbab294173ef073c01a" }());
    }

    {
        std::string input{ "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ!@#" };

        sha256_t sh{ std::bit_cast<const uint8_t*>(input.data()), input.size() };

        assert(sh.digest() == hex_to_binary<32>{ "b780d798616b8ef8fe461f3440a80e3f7990166b097df34a4701bb3246fd3827" }());
    }

    {
        std::string input{ "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ" };

        sha256_t sh{ std::bit_cast<const uint8_t*>(input.data()), input.size() };

        assert(sh.digest() == hex_to_binary<32>{ "75636aa5c963ecd75ae937f983685cd987afbab30a96b40469d1859c98f7795e" }());
    }

    {
        std::string input{ "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ" };

        sha256_t sh{ std::bit_cast<const uint8_t*>(input.data()), input.size() };

        assert(sh.digest() == hex_to_binary<32>{ "38152aa07185f3a9b730ca5f1985797d17e52fdbb1917cd5481428864c610b0a" }());
    }
}
