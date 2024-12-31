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

#include <array>
#include <cassert>
#include <cstdint>
#include <string_view>

template <size_t N>
class hex_to_binary_t
{
public:
    constexpr explicit hex_to_binary_t(std::string_view str)
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
