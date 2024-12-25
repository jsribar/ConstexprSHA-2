#include "sha256.h"

#include <algorithm>
#include <array>
#include <bit>
#include <cassert>
#include <iostream>

static constexpr bool operator==(const std::array<uint8_t, 32>& digest, std::array<uint8_t, 32> str)
{
    return std::ranges::equal(digest, str);
}

constexpr std::array<uint8_t, 8> data{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };

static_assert(to_uint<uint8_t>(data.data()) == uint8_t(0x01));
static_assert(to_uint<uint16_t>(data.data()) == uint16_t(0x0102));
static_assert(to_uint<uint32_t>(data.data()) == uint32_t(0x01020304));
static_assert(to_uint<uint64_t>(data.data()) == uint64_t(0x0102030405060708));


static_assert(right_rotate(uint32_t(0x01020304), 8) == 0x04010203);
static_assert(right_rotate(uint32_t(0x01020304), 16) == 0x03040102);
static_assert(right_rotate(uint32_t(0x01020304), 3) == 0x80204060);
static_assert(right_rotate(uint32_t(0x01020304), 7) == 0x08020406);


static constexpr sha256_t sh1{ sha256_t{{uint8_t(8)}} };

static_assert(sh1.data().front() == uint8_t(8));


static constexpr sha256_t sh2{ sha256_t{{uint8_t('a'), uint8_t('b'), uint8_t('b') }} };

static_assert(sh2.data().front() == uint8_t('a'));
static_assert(sh2.data().at(16 * 4 - 1) == uint8_t(24));


static constexpr std::array<uint8_t, 3> input1{ 'a', 'b', 'c' };

static constexpr sha256_t sh3{ input1.data(), input1.size() };

static_assert(*(sh3.data().begin()) == uint8_t('a'));
static_assert(*(sh3.data().begin() + 1) == uint8_t('b'));
static_assert(*(sh3.data().begin() + 2) == uint8_t('c'));
static_assert(*(sh3.data().begin() + 3) == uint8_t(0x80));
static_assert(to_uint<uint32_t>(&sh3.data().at(15 * 4)) == uint32_t(24));
static_assert(to_uint<uint32_t>(&sh3.data().at(16 * 4)) == uint32_t(0x61626380));
static_assert(to_uint<uint32_t>(&sh3.data().at(17 * 4)) == uint32_t(0x000F0000));
static_assert(to_uint<uint32_t>(&sh3.data().at(25 * 4)) == uint32_t(0xB73679A2));
static_assert(to_uint<uint32_t>(&sh3.data().at(30 * 4)) == uint32_t(0x702138A4));
static_assert(to_uint<uint32_t>(&sh3.data().at(31 * 4)) == uint32_t(0xD3B7973B));
static_assert(to_uint<uint32_t>(&sh3.data().at(32 * 4)) == uint32_t(0x93F5997F));
static_assert(to_uint<uint32_t>(&sh3.data().at(35 * 4)) == uint32_t(0xF10A5C62));
static_assert(to_uint<uint32_t>(&sh3.data().at(46 * 4)) == uint32_t(0x7A290D5D));
static_assert(to_uint<uint32_t>(&sh3.data().at(62 * 4)) == uint32_t(0xEEABA2CC));
static_assert(to_uint<uint32_t>(&sh3.data().at(63 * 4)) == uint32_t(0x12B1EDEB));

//static_assert(sh3.digest() == std::array<uint8_t, 32>{ '\xBA', '\x78', '\x16', '\xBF', '\x8F', '\x01', '\xCF', '\xEA', '\x41', '\x41', '\x40', '\xDE', '\x5D', '\xAE', '\x22', '\x23', '\xB0', '\x03', '\x61', '\xA3', '\x96', '\x17', '\x7A', '\x9C', '\xB4', '\x10', '\xFF', '\x61', '\xF2', '\x00', '\x15', '\xAD' });


static constexpr uint8_t input2[] = { "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRS" };

static constexpr sha256_t sh4{ input2, sizeof(input2) - 1 };

static_assert(*(sh4.data().begin()) == uint8_t('a'));
static_assert(*(sh4.data().begin() + 1) == uint8_t('b'));
static_assert(*(sh4.data().begin() + 2) == uint8_t('c'));
static_assert(to_uint<uint64_t>(&sh4.data().at(14 * 4)) == 440);

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
        sha256_t sh{ sha256_t{{uint8_t('a'), uint8_t('b'), uint8_t('c') }} };
        assert(to_uint<uint64_t>(&sh.data().at(14 * 4)) == 24);

#pragma warning( suppress : 4838)
        const std::array<uint8_t, 32> str{ '\xBA', '\x78', '\x16', '\xBF', '\x8F', '\x01', '\xCF', '\xEA', '\x41', '\x41', '\x40', '\xDE', '\x5D', '\xAE', '\x22', '\x23', '\xB0', '\x03', '\x61', '\xA3', '\x96', '\x17', '\x7A', '\x9C', '\xB4', '\x10', '\xFF', '\x61', '\xF2', '\x00', '\x15', '\xAD' };
        assert(std::ranges::equal(sh3.digest(), str));

    }

    {
        std::string input{ "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRS" };

        sha256_t sh{ std::bit_cast<const uint8_t*>(input.data()), input.size() };

        assert(*(sh.data().begin()) == uint8_t('a'));
        assert(*(sh.data().begin() + 1) == uint8_t('b'));
        assert(*(sh.data().begin() + 2) == uint8_t('c'));
        assert(to_uint<uint64_t>(&sh.data().at(14 * 4)) == 440);
    }

    {
        std::string input{ "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ" };

        sha256_t sh{ std::bit_cast<const uint8_t*>(input.data()), input.size() };

        assert(sh.data().at(62) == uint8_t(0x80));
        assert(sh.data().at(63) == uint8_t(0));
    }

    {
        std::string input{ "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ!@" };

        sha256_t sh{ std::bit_cast<const uint8_t*>(input.data()), input.size() };

        assert(sh.data().at(63) == uint8_t('@'));
    }


    {
        std::string input{ "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ!@#" };

        sha256_t sh{ std::bit_cast<const uint8_t*>(input.data()), input.size() };
    }
}
