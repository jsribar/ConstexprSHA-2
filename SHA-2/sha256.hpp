#pragma once

#include "util.hpp"

#include <algorithm>
#include <array>
#include <cassert>
#include <cstdint>
#include <string_view>

namespace jsribar::cryptography::sha2
{

class sha256_t
{
    static constexpr size_t digest_size_k{ 32 };
    static constexpr size_t message_block_size_k{ 64 };
    static constexpr size_t message_schedule_bytes_k{ 64 * 4 };

public:
    using message_digest_t = std::array<uint8_t, digest_size_k>;
    using message_schedule_t = std::array<uint8_t, message_schedule_bytes_k>;

    constexpr sha256_t(std::initializer_list<char> input)
        : sha256_t(input.begin(), input.size())
    {
    }

    constexpr explicit sha256_t(std::string_view input)
        : sha256_t(input.data(), input.size())
    {
    }

    constexpr explicit sha256_t(const char* input, size_t length)
        : message_begin_m(input)
        , message_end_m(input + length)
        , message_length_m(length)
    {
        do
        {
            if (const auto copied = copy_message_block(); copied < message_block_size_k)
            {
                pad_last_block(copied);
            }
            extend_message_schedule();
            compress();
        } while (message_begin_m < message_end_m || padding_m != padding_t::size);

        final_hash();
    }

    constexpr message_digest_t digest() const
    {
        return message_digest_m;
    }

private:
    const char* message_begin_m{ nullptr };
    const char* message_end_m{ nullptr };

    const size_t message_length_m{ 0 };

    message_schedule_t message_schedule_m{ 0 };
    message_digest_t message_digest_m{ 0 };

    std::array<uint32_t, 8> h_m{ h_k };

    // Padding(s) done.
    enum class padding_t
    {
        none,
        bit_one,
        size,
    };

    padding_t padding_m{ padding_t::none };

    static constexpr uint8_t padding_one_k{ 0x80 };
    static constexpr size_t last_block_size_k{ message_block_size_k - 8 };

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


    constexpr size_t copy_message_block()
    {
        const auto to_copy = std::min(size_t(message_end_m - message_begin_m), message_block_size_k);
        std::copy(message_begin_m, message_begin_m + to_copy, message_schedule_m.data());
        message_begin_m += to_copy;
        return to_copy;
    }

    // Append single '1' bit to the message and add original message length to the end of the message block.
    constexpr void pad_last_block(size_t copied_input_block_length)
    {
        assert(copied_input_block_length < message_block_size_k);

        if (padding_m == padding_t::none)
        {
            message_schedule_m.at(copied_input_block_length) = padding_one_k;
            ++copied_input_block_length;
            padding_m = padding_t::bit_one;
        }

        const auto beg = message_schedule_m.data() + copied_input_block_length;
        if (copied_input_block_length <= last_block_size_k)
        {
            auto end = message_schedule_m.data() + last_block_size_k;
            std::fill(beg, end, 0);
            append_message_length(end, message_length_m * 8);
            padding_m = padding_t::size;
        }
        else
        {
            std::fill(beg, message_schedule_m.data() + message_block_size_k, 0);
        }
    }

    constexpr void append_message_length(uint8_t* destination, size_t length) const
    {
        to_uint8_array<uint64_t>(length, destination);
    }

    // Extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array.
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
        std::array<uint32_t, 8> h{ h_m };

        for (int i = 0; i < 64; ++i)
        {
            const auto sigma1 = (right_rotate(h[4], 6)) ^ (right_rotate(h[4], 11)) ^ (right_rotate(h[4], 25));
            const auto choice = (h[4] & h[5]) ^ ((~h[4]) & h[6]);
            const auto temp1 = h[7] + sigma1 + choice + k_k[i] + to_uint<uint32_t>(message_schedule_m.data() + i * 4);
            const auto sigma0 = (right_rotate(h[0], 2)) ^ (right_rotate(h[0], 13)) ^ (right_rotate(h[0], 22));
            const auto majority = (h[0] & h[1]) ^ (h[0] & h[2]) ^ (h[1] & h[2]);
            const auto temp2 = sigma0 + majority;

            std::ranges::rotate(h, h.end() - 1);
            h[0] = temp1 + temp2;
            h[4] += temp1;
        }

        for (size_t i = 0; i < 8; ++i)
        {
            h_m[i] += h[i];
        }
    }

    constexpr void final_hash()
    {
        for (size_t i = 0; i < 8; ++i)
        {
            to_uint8_array(h_m[i], &message_digest_m[i * 4]);
        }
    }
};

}
