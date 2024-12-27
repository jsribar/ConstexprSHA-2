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
    constexpr T right_rotate(const T input, size_t n)
    {
        assert(n < sizeof(T) * 8);
        return (input >> n) | (input << (sizeof(T) * 8 - n));
    }

    template <size_t N>
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

}
