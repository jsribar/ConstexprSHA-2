#pragma once

#include <cassert>
#include <cstdint>
#include <string_view>

namespace jsribar::cryptography::sha2
{

template <typename T>
constexpr T to_uint(const uint8_t* input)
{
    T result = 0;
    for (size_t i = 0; i < sizeof(T); ++i)
    {
        result <<= 8;
        result += *input;
        ++input;
    }
    return result;
}

template <>
constexpr uint8_t to_uint<uint8_t>(const uint8_t* input)
{
    return *input;
}


template <typename T>
constexpr void to_uint8_array(T value, uint8_t* dest)
{
    for (int i = sizeof(T) - 1; i >= 0; --i)
    {
        const auto n = value % 256;
        *(dest + i) = uint8_t(n);
        value /= T(256);
    }
}

template <>
constexpr void to_uint8_array<uint8_t>(uint8_t value, uint8_t* dest)
{
    *dest = value;
}

template <size_t length, typename T>
constexpr void to_uint8_array(T value, uint8_t* dest)
{
    for (int i = length - 1; i >= 0; --i)
    {
        const auto n = value % 256;
        *(dest + i) = uint8_t(n);
        value /= T(256);
    }
}

template <typename T>
constexpr T right_rotate(const T input, size_t n)
{
    assert(n < sizeof(T) * 8);
    return (input >> n) | (input << (sizeof(T) * 8 - n));
}

}
