#pragma once

#include <array>
#include <cassert>
#include <cstdint>

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


class sha256_t
{
    static constexpr size_t bits_per_byte_k{ 8 };

    static constexpr size_t digest_bits_k{ 256 };
    static constexpr size_t digest_bytes_k{ digest_bits_k / bits_per_byte_k };

    static constexpr size_t message_block_bits_k{ 512 };
    static constexpr size_t message_block_bytes_k{ message_block_bits_k / bits_per_byte_k };

    static constexpr size_t message_schedule_bytes_k{ 64 * 4 };

public:
    using message_digest_t = std::array<uint8_t, digest_bytes_k>;
    using message_schedule_t = std::array<uint8_t, message_schedule_bytes_k>;

    constexpr sha256_t(std::initializer_list<uint8_t> input)
        : sha256_t(input.begin(), input.size())
    {
    }

    constexpr explicit sha256_t(const uint8_t* input, size_t length)
        : message_length_m(length)
        , message_left_m(length)
    {
        update(input);
        pad_last_block(length);
        extend_message_schedule();
        compress();
    }

    constexpr message_schedule_t data() const
    {
        return message_schedule_m;
    }

    constexpr message_digest_t digest() const
    {
        return message_digest_m;
    }

private:
    size_t message_length_m{ 0 };
    size_t message_left_m{ 0 };

    message_schedule_t message_schedule_m{ 0 };
    message_digest_t message_digest_m{ 0 };

    static constexpr uint8_t padding_one_k{ 0x80 };
    static constexpr size_t last_block_size_k{ message_block_bytes_k - 8 };

    static constexpr std::array<uint32_t, 8> h_k{
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    };

    static constexpr std::array<uint32_t, 64> k_k{
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };


    constexpr void update(const uint8_t* input)
    {
        const auto to_copy = message_length_m > message_block_bytes_k ? message_length_m % message_block_bytes_k : message_length_m;
        std::copy(input, input + to_copy, message_schedule_m.data());
        message_left_m -= to_copy;
    }

    constexpr void pad_last_block(size_t length)
    {
        if (length < message_block_bytes_k)
        {
            message_schedule_m.at(length) = padding_one_k;
            ++length;
        }
        if (length <= last_block_size_k)
        {
            const auto beg = message_schedule_m.data() + length;
            const auto end = beg + last_block_size_k - length;
            std::fill(beg, end, 0);
            append_message_length(end, message_length_m * bits_per_byte_k);
        }
    }

    constexpr void append_message_length(uint8_t* destination, size_t length) const
    {
        to_uint8_array<uint64_t>(length, destination);
    }

    constexpr void extend_message_schedule()
    {
        for (size_t offset = 0; offset < (64 - 16) * 4; offset += 4)
        {
            auto off = message_schedule_m.data() + offset;
            const auto w0 = to_uint<uint32_t>(off);

            off += 4;
            const auto w1 = to_uint<uint32_t>(off);
            const auto s0 = right_rotate(w1, 7) ^ right_rotate(w1, 18) ^ (w1 >> 3);

            off += 32;
            const auto w2 = to_uint<uint32_t>(off);

            off += 20;
            const auto w3 = to_uint<uint32_t>(off);
            const auto s1 = right_rotate(w3, 17) ^ right_rotate(w3, 19) ^ (w3 >> 10);

            off += 8;
            const auto w4 = w0 + s0 + w2 + s1;
            to_uint8_array(w4, off);
        }
    }

    constexpr void compress()
    {
        auto a = h_k[0];
        auto b = h_k[1];
        auto c = h_k[2];
        auto d = h_k[3];
        auto e = h_k[4];
        auto f = h_k[5];
        auto g = h_k[6];
        auto h = h_k[7];

        for (int i = 0; i < 64; ++i)
        {
            const auto sigma1 = (right_rotate(e, 6)) ^ (right_rotate(e, 11)) ^ (right_rotate(e, 25));
            const auto choice = (e & f) ^ ((~e) & g);
            const auto temp1 = h + sigma1 + choice + k_k[i] + to_uint<uint32_t>(message_schedule_m.data() + i * 4);
            const auto sigma0 = (right_rotate(a, 2)) ^ (right_rotate(a, 13)) ^ (right_rotate(a, 22));
            const auto majority = (a & b) ^ (a & c) ^ (b & c);
            const auto temp2 = sigma0 + majority;

            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        const auto h0 = h_k[0] + a;
        const auto h1 = h_k[1] + b;
        const auto h2 = h_k[2] + c;
        const auto h3 = h_k[3] + d;
        const auto h4 = h_k[4] + e;
        const auto h5 = h_k[5] + f;
        const auto h6 = h_k[6] + g;
        const auto h7 = h_k[7] + h;

        to_uint8_array(h0, &message_digest_m[0]);
        to_uint8_array(h1, &message_digest_m[4]);
        to_uint8_array(h2, &message_digest_m[8]);
        to_uint8_array(h3, &message_digest_m[12]);
        to_uint8_array(h4, &message_digest_m[16]);
        to_uint8_array(h5, &message_digest_m[20]);
        to_uint8_array(h6, &message_digest_m[24]);
        to_uint8_array(h7, &message_digest_m[28]);
    }
};
