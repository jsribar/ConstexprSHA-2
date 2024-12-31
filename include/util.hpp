// SPDX-License-Identifier: MIT

/*
 * MIT License
 *
 * Copyright (c) 2024 by Julijan Šribar
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */

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


template <typename T>
constexpr void to_uint8_array(T value, uint8_t* dest, int length)
{
    // If the length is smaller than value size, remove surplus rightmost bytes.
    if (int extra = sizeof(T) - length; extra > 0)
    {
        value >>= 8 * extra;
    }

    for (int i = length - 1; i >= 0; --i)
    {
        const auto n = value % 256;
        *(dest + i) = uint8_t(n);
        value /= T(256);
    }
}

template <>
constexpr void to_uint8_array<uint8_t>(uint8_t value, uint8_t* dest, int length)
{
    assert(length >= 1);

    *dest = value;
}


template <typename T>
constexpr T right_rotate(const T input, size_t n)
{
    if (n %= sizeof(T) * 8)
    {
        return (input >> n) | (input << (sizeof(T) * 8 - n));
    }
    return input;
}

}
