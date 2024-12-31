#include <catch2/catch.hpp>

#include <util.hpp>

#include <array>

using namespace jsribar::cryptography::sha2;

TEST_CASE("to_uint function converts sequence of big-endian bytes to unsigned integer", "[to_uint]")
{
    constexpr std::array<uint8_t, 8> data{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };

    SECTION("uint8_t")
    {
        STATIC_REQUIRE(to_uint<uint8_t>(data.data()) == uint8_t(0x01));
    }

    SECTION("uint16_t")
    {
        STATIC_REQUIRE(to_uint<uint16_t>(data.data()) == uint16_t(0x0102));
    }

    SECTION("uint32_t")
    {
        STATIC_REQUIRE(to_uint<uint32_t>(data.data()) == uint32_t(0x01020304));
    }

    SECTION("uint64_t")
    {
        STATIC_REQUIRE(to_uint<uint64_t>(data.data()) == uint64_t(0x0102030405060708));
    }
}

TEST_CASE("to_uint8_array converts unsigned integer to a sequence of big-endian bytes", "[to_uint]")
{
    std::array<uint8_t, 8> buffer{ 0 };

    SECTION("uint8_t")
    {
        to_uint8_array(uint8_t(0x01), buffer.data());
        REQUIRE(memcmp(buffer.data(), "\x01\x00\x00\x00\x00\x00\x00\x00", 8) == 0);
    }

    SECTION("uint16_t")
    {
        to_uint8_array(uint16_t(0x0102), buffer.data());
        REQUIRE(memcmp(buffer.data(), "\x01\x02\x00\x00\x00\x00\x00\x00", 8) == 0);
    }

    SECTION("uint32_t")
    {
        to_uint8_array(uint32_t(0x01020304), buffer.data());
        REQUIRE(memcmp(buffer.data(), "\x01\x02\x03\x04\x00\x00\x00\x00", 8) == 0);
    }

    SECTION("uint64_t")
    {
        to_uint8_array(uint64_t(0x0102030405060708), buffer.data());
        REQUIRE(memcmp(buffer.data(), "\x01\x02\x03\x04\x05\x06\x07\x08", 8) == 0);
    }
}

TEST_CASE("to_uint8_array converts unsigned integer to a sequence of big-endian bytes of given length", "[to_uint]")
{
    std::array<uint8_t, 16> buffer{ 0 };

    SECTION("One byte")
    {
        to_uint8_array<1>(uint8_t(0x01), buffer.data());
        REQUIRE(memcmp(buffer.data(), "\x01\x00\x00\x00\x00\x00\x00\x00", 8) == 0);
    }

    SECTION("Two bytes")
    {
        to_uint8_array<2>(uint16_t(0x0102), buffer.data());
        REQUIRE(memcmp(buffer.data(), "\x01\x02\x00\x00\x00\x00\x00\x00", 8) == 0);
    }

    SECTION("Four bytes")
    {
        to_uint8_array<4>(0x01020304, buffer.data());
        REQUIRE(memcmp(buffer.data(), "\x01\x02\x03\x04\x00\x00\x00\x00", 8) == 0);
    }

    SECTION("Eight bytes")
    {
        to_uint8_array<8>(0x0102030405060708, buffer.data());
        REQUIRE(memcmp(buffer.data(), "\x01\x02\x03\x04\x05\x06\x07\x08\x00\x00", 10) == 0);
    }

    SECTION("Ten bytes")
    {
        to_uint8_array<10>(0x0102030405060708, buffer.data());
        REQUIRE(memcmp(buffer.data(), "\x00\x00\x01\x02\x03\x04\x05\x06\x07\x08\x00\x00", 12) == 0);
    }

    SECTION("Sixteen bytes")
    {
        to_uint8_array<16>(0x0102030405060708, buffer.data());
        REQUIRE(memcmp(buffer.data(), "\x00\x00\x00\x00\x00\x00\x00\x00\x01\x02\x03\x04\x05\x06\x07\x08", 16) == 0);
    }
}

TEST_CASE("right_rotate rotates bits by offset provided", "[right_rotate]")
{
    SECTION("uint8_t")
    {
        STATIC_REQUIRE(right_rotate(uint8_t(0x01), 0) == uint8_t(0x01));
        STATIC_REQUIRE(right_rotate(uint8_t(0x01), 1) == uint8_t(0x80));
        STATIC_REQUIRE(right_rotate(uint8_t(0x01), 2) == uint8_t(0x40));
        STATIC_REQUIRE(right_rotate(uint8_t(0x01), 3) == uint8_t(0x20));
        STATIC_REQUIRE(right_rotate(uint8_t(0x01), 4) == uint8_t(0x10));
        STATIC_REQUIRE(right_rotate(uint8_t(0x01), 5) == uint8_t(0x08));
        STATIC_REQUIRE(right_rotate(uint8_t(0x01), 6) == uint8_t(0x04));
        STATIC_REQUIRE(right_rotate(uint8_t(0x01), 7) == uint8_t(0x02));
        STATIC_REQUIRE(right_rotate(uint8_t(0x01), 8) == uint8_t(0x01));
        STATIC_REQUIRE(right_rotate(uint8_t(0x01), 9) == uint8_t(0x80));
        STATIC_REQUIRE(right_rotate(uint8_t(0x01), 10) == uint8_t(0x40));
        STATIC_REQUIRE(right_rotate(uint8_t(0x01), 11) == uint8_t(0x20));
        STATIC_REQUIRE(right_rotate(uint8_t(0x01), 12) == uint8_t(0x10));
        STATIC_REQUIRE(right_rotate(uint8_t(0x01), 13) == uint8_t(0x08));
        STATIC_REQUIRE(right_rotate(uint8_t(0x01), 14) == uint8_t(0x04));
        STATIC_REQUIRE(right_rotate(uint8_t(0x01), 15) == uint8_t(0x02));

        STATIC_REQUIRE(right_rotate(uint8_t(0x11), 0) == uint8_t(0x11));
        STATIC_REQUIRE(right_rotate(uint8_t(0x11), 1) == uint8_t(0x88));
        STATIC_REQUIRE(right_rotate(uint8_t(0x11), 2) == uint8_t(0x44));
        STATIC_REQUIRE(right_rotate(uint8_t(0x11), 3) == uint8_t(0x22));
        STATIC_REQUIRE(right_rotate(uint8_t(0x11), 4) == uint8_t(0x11));
        STATIC_REQUIRE(right_rotate(uint8_t(0x11), 5) == uint8_t(0x88));
        STATIC_REQUIRE(right_rotate(uint8_t(0x11), 6) == uint8_t(0x44));
        STATIC_REQUIRE(right_rotate(uint8_t(0x11), 7) == uint8_t(0x22));
    }

    SECTION("uint16_t")
    {
        STATIC_REQUIRE(right_rotate(uint16_t(0x0101), 0) == uint16_t(0x0101));
        STATIC_REQUIRE(right_rotate(uint16_t(0x0101), 1) == uint16_t(0x8080));
        STATIC_REQUIRE(right_rotate(uint16_t(0x0101), 2) == uint16_t(0x4040));
        STATIC_REQUIRE(right_rotate(uint16_t(0x0101), 3) == uint16_t(0x2020));
        STATIC_REQUIRE(right_rotate(uint16_t(0x0101), 4) == uint16_t(0x1010));
        STATIC_REQUIRE(right_rotate(uint16_t(0x0101), 5) == uint16_t(0x0808));
        STATIC_REQUIRE(right_rotate(uint16_t(0x0101), 6) == uint16_t(0x0404));
        STATIC_REQUIRE(right_rotate(uint16_t(0x0101), 7) == uint16_t(0x0202));
        STATIC_REQUIRE(right_rotate(uint16_t(0x0101), 8) == uint16_t(0x0101));
        STATIC_REQUIRE(right_rotate(uint16_t(0x0101), 9) == uint16_t(0x8080));
        STATIC_REQUIRE(right_rotate(uint16_t(0x0101), 10) == uint16_t(0x4040));
        STATIC_REQUIRE(right_rotate(uint16_t(0x0101), 11) == uint16_t(0x2020));
        STATIC_REQUIRE(right_rotate(uint16_t(0x0101), 12) == uint16_t(0x1010));
        STATIC_REQUIRE(right_rotate(uint16_t(0x0101), 13) == uint16_t(0x0808));
        STATIC_REQUIRE(right_rotate(uint16_t(0x0101), 14) == uint16_t(0x0404));
        STATIC_REQUIRE(right_rotate(uint16_t(0x0101), 15) == uint16_t(0x0202));
    }

    SECTION("uint32_t")
    {
        STATIC_REQUIRE(right_rotate(uint32_t(0x01010101), 0) == uint32_t(0x01010101));
        STATIC_REQUIRE(right_rotate(uint32_t(0x01010101), 1) == uint32_t(0x80808080));
        STATIC_REQUIRE(right_rotate(uint32_t(0x01010101), 2) == uint32_t(0x40404040));
        STATIC_REQUIRE(right_rotate(uint32_t(0x01010101), 3) == uint32_t(0x20202020));
        STATIC_REQUIRE(right_rotate(uint32_t(0x01010101), 4) == uint32_t(0x10101010));

        STATIC_REQUIRE(right_rotate(uint32_t(0xFF000000), 2) == uint32_t(0x3FC00000));
        STATIC_REQUIRE(right_rotate(uint32_t(0xFF000000), 4) == uint32_t(0x0FF00000));
        STATIC_REQUIRE(right_rotate(uint32_t(0xFF000000), 8) == uint32_t(0x00FF0000));
        STATIC_REQUIRE(right_rotate(uint32_t(0xFF000000), 12) == uint32_t(0x000FF000));
        STATIC_REQUIRE(right_rotate(uint32_t(0xFF000000), 16) == uint32_t(0x0000FF00));
        STATIC_REQUIRE(right_rotate(uint32_t(0xFF000000), 20) == uint32_t(0x00000FF0));
        STATIC_REQUIRE(right_rotate(uint32_t(0xFF000000), 24) == uint32_t(0x000000FF));
        STATIC_REQUIRE(right_rotate(uint32_t(0xFF000000), 28) == uint32_t(0xF000000F));
        STATIC_REQUIRE(right_rotate(uint32_t(0xFF000000), 32) == uint32_t(0xFF000000));
        STATIC_REQUIRE(right_rotate(uint32_t(0xFF000000), 34) == uint32_t(0x3FC00000));
    }

    SECTION("uint64_t")
    {
        STATIC_REQUIRE(right_rotate(uint64_t(0x0123456789ABCDEF), 2) == uint64_t(0xC048D159E26AF37B));
        STATIC_REQUIRE(right_rotate(uint64_t(0x0123456789ABCDEF), 4) == uint64_t(0xF0123456789ABCDE));
        STATIC_REQUIRE(right_rotate(uint64_t(0x0123456789ABCDEF), 6) == uint64_t(0xBC048D159E26AF37));
        STATIC_REQUIRE(right_rotate(uint64_t(0x0123456789ABCDEF), 7) == uint64_t(0xDE02468ACF13579B));
        STATIC_REQUIRE(right_rotate(uint64_t(0x0123456789ABCDEF), 12) == uint64_t(0xDEF0123456789ABC));
    }
}
