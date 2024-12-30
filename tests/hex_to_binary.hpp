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
