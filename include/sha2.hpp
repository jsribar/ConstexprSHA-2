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

#include "util.hpp"

#include <algorithm>
#include <array>
#include <cassert>
#include <cstdint>
#include <string_view>

namespace jsribar::cryptography::sha2
{

// Sum implementations for SHA-224/SHA-256 and SHA-384/SHA-512, respectively.
constexpr uint32_t sum0(uint32_t w)
{
    return right_rotate(w, 7) ^ right_rotate(w, 18) ^ (w >> 3);
}

constexpr uint32_t sum1(uint32_t w)
{
    return right_rotate(w, 17) ^ right_rotate(w, 19) ^ (w >> 10);
}

constexpr uint64_t sum0(uint64_t w)
{
    return right_rotate(w, 1) ^ right_rotate(w, 8) ^ (w >> 7);
}

constexpr uint64_t sum1(uint64_t w)
{
    return right_rotate(w, 19) ^ right_rotate(w, 61) ^ (w >> 6);
}

// Sigma implementations for SHA-224/SHA-256 and SHA-384/SHA-512, respectively.
constexpr uint32_t sigma0(uint32_t h)
{
    return right_rotate(h, 2) ^ right_rotate(h, 13) ^ right_rotate(h, 22);
}

constexpr uint32_t sigma1(uint32_t h)
{
    return right_rotate(h, 6) ^ right_rotate(h, 11) ^ right_rotate(h, 25);
}

constexpr uint64_t sigma0(uint64_t h)
{
    return right_rotate(h, 28) ^ right_rotate(h, 34) ^ right_rotate(h, 39);
}

constexpr uint64_t sigma1(uint64_t h)
{
    return right_rotate(h, 14) ^ right_rotate(h, 18) ^ right_rotate(h, 41);
}

// Base class for all implementations.
template <typename T, typename InitialHashValues, typename RoundConstants, size_t message_schedule_length, size_t digest_size>
class sha_base_t
{
protected:
    constexpr explicit sha_base_t(const char* input, size_t length)
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

public:
    using message_digest_t = std::array<uint8_t, digest_size>;
    using message_schedule_t = std::array<uint8_t, message_schedule_length>;

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

    static constexpr InitialHashValues initial_hash_values_k;

    std::array<T, 8> h_m{ initial_hash_values_k.values };

    static constexpr RoundConstants k_k;

    // Padding(s) done.
    enum class padding_t
    {
        none,
        bit_one,
        size,
    };

    padding_t padding_m{ padding_t::none };

    static constexpr size_t message_block_size_k{ sizeof(T) * 16 };

    static constexpr uint8_t padding_bit_one_k{ 0x80 };
    static constexpr size_t last_block_size_k{ message_block_size_k - 2 * sizeof(T) };


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
            message_schedule_m.at(copied_input_block_length) = padding_bit_one_k;
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
        to_uint8_array(length, destination, sizeof(T) * 2);
    }

    // Extend the first 16 words into the remaining words w[16..63] (or w[16..79] for SHA-512) of the message schedule array.
    constexpr void extend_message_schedule()
    {
        for (size_t offset = 0; offset < message_schedule_length - 16 * sizeof(T); offset += sizeof(T))
        {
            auto off = message_schedule_m.data() + offset;
            const auto w0 = to_uint<T>(off);

            off += sizeof(T);
            const auto w1 = to_uint<T>(off);

            off += 8 * sizeof(T);
            const auto w2 = to_uint<T>(off);

            off += 5 * sizeof(T);
            const auto w3 = to_uint<T>(off);

            off += 2 * sizeof(T);
            const auto w4 = w0 + sum0(w1) + w2 + sum1(w3);
            to_uint8_array(w4, off);
        }
    }

    constexpr void compress()
    {
        std::array<T, 8> h{ h_m };

        for (int i = 0; i < k_k.size(); ++i)
        {
            const auto choice = (h[4] & h[5]) ^ ((~h[4]) & h[6]);
            const auto temp1 = h[7] + sigma1(h[4]) + choice + k_k[i] + to_uint<T>(message_schedule_m.data() + i * sizeof(T));
            const auto majority = (h[0] & h[1]) ^ (h[0] & h[2]) ^ (h[1] & h[2]);
            const auto temp2 = sigma0(h[0]) + majority;

            std::ranges::rotate(h, h.end() - 1);
            h[0] = temp1 + temp2;
            h[4] += temp1;
        }

        for (size_t i = 0; i < h_m.size(); ++i)
        {
            h_m[i] += h[i];
        }
    }

    constexpr void final_hash()
    {
        // If final digest is smaller than evaluated, trim the rightmost surplus bits.
        int digest_len = digest_size;
        for (size_t i = 0; i < h_m.size() && digest_len > 0; ++i)
        {
            const auto len = std::min<int>(sizeof(T), digest_len);
            to_uint8_array(h_m[i], &message_digest_m[i * sizeof(T)], len);
            digest_len -= len;
        }
    }
};

// Round constants for SHA-224/SHA-256.
class round_constants_2x_t
{
public:
    constexpr uint32_t operator[](int index) const
    {
        return values[index];
    }

    constexpr size_t size() const
    {
        return values.size();
    }

private:
    static constexpr std::array<uint32_t, 64> values{
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };
};

// Initial hash values for SHA-224.
struct initital_hash_values_224_t
{
    static constexpr std::array<uint32_t, 8> values{
        0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4
    };
};

// SHA-224 implementation.
class sha224_t : public sha_base_t<uint32_t, initital_hash_values_224_t, round_constants_2x_t, 256, 28>
{
public:
    constexpr sha224_t(std::initializer_list<char> input)
        : sha_base_t(input.begin(), input.size())
    {
    }

    constexpr explicit sha224_t(std::string_view input)
        : sha_base_t(input.data(), input.size())
    {
    }

    constexpr explicit sha224_t(const char* input, size_t length)
        : sha_base_t(input, length)
    {
    }
};

// Initial hash values for SHA-256.
struct initial_hash_values_256_t
{
    static constexpr std::array<uint32_t, 8> values{
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };
};

// SHA-256 implementation.
class sha256_t : public sha_base_t<uint32_t, initial_hash_values_256_t, round_constants_2x_t, 256, 32>
{
public:
    constexpr sha256_t(std::initializer_list<char> input)
        : sha_base_t(input.begin(), input.size())
    {
    }

    constexpr explicit sha256_t(std::string_view input)
        : sha_base_t(input.data(), input.size())
    {
    }

    constexpr explicit sha256_t(const char* input, size_t length)
        : sha_base_t(input, length)
    {
    }
};

// Round constants for SHA-384/SHA-256.
class round_constants_5x_t
{
public:
    constexpr uint64_t operator[](int index) const
    {
        return values[index];
    }

    constexpr size_t size() const
    {
        return values.size();
    }

private:
    static constexpr std::array<uint64_t, 80> values{
        0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538,
        0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe,
        0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235,
        0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
        0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab,
        0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
        0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed,
        0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
        0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218,
        0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53,
        0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373,
        0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
        0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c,
        0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6,
        0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc,
        0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
    };
};

// Initial hash values for SHA-384.
struct initial_hash_values_384_t
{
    static constexpr std::array<uint64_t, 8> values{
        0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939,
        0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4
    };
};

// SHA-384 implementation.
class sha384_t : public sha_base_t<uint64_t, initial_hash_values_384_t, round_constants_5x_t, 640, 48>
{
public:
    constexpr sha384_t(std::initializer_list<char> input)
        : sha_base_t(input.begin(), input.size())
    {
    }

    constexpr explicit sha384_t(std::string_view input)
        : sha_base_t(input.data(), input.size())
    {
    }

    constexpr explicit sha384_t(const char* input, size_t length)
        : sha_base_t(input, length)
    {
    }
};

// Initial hash values for SHA-512.
struct initial_hash_values_512_t
{
    static constexpr std::array<uint64_t, 8> values{
        0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
        0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
    };
};

// SHA-512 implementation.
class sha512_t : public sha_base_t<uint64_t, initial_hash_values_512_t, round_constants_5x_t, 640, 64>
{
public:
    constexpr sha512_t(std::initializer_list<char> input)
        : sha_base_t(input.begin(), input.size())
    {
    }

    constexpr explicit sha512_t(std::string_view input)
        : sha_base_t(input.data(), input.size())
    {
    }

    constexpr explicit sha512_t(const char* input, size_t length)
        : sha_base_t(input, length)
    {
    }
};

// Initial hash values for SHA-512/224.
struct initial_hash_values_512_224_t
{
    static constexpr std::array<uint64_t, 8> values{
        0x8c3d37c819544da2, 0x73e1996689dcd4d6, 0x1dfab7ae32ff9c82, 0x679dd514582f9fcf,
        0x0f6d2b697bd44da8, 0x77e36f7304C48942, 0x3f9d85a86a1d36C8, 0x1112e6ad91d692a1
    };
};

// SHA-512/224 implementation.
class sha512_224_t : public sha_base_t<uint64_t, initial_hash_values_512_224_t, round_constants_5x_t, 640, 28>
{
public:
    constexpr sha512_224_t(std::initializer_list<char> input)
        : sha_base_t(input.begin(), input.size())
    {
    }

    constexpr explicit sha512_224_t(std::string_view input)
        : sha_base_t(input.data(), input.size())
    {
    }

    constexpr explicit sha512_224_t(const char* input, size_t length)
        : sha_base_t(input, length)
    {
    }
};

// Initial hash values for SHA-512/256.
struct initial_hash_values_512_256_t
{
    static constexpr std::array<uint64_t, 8> values{
        0x22312194fc2bf72c, 0x9f555fa3c84c64c2, 0x2393b86b6f53b151, 0x963877195940eabd,
        0x96283ee2a88effe3, 0xbe5e1e2553863992, 0x2b0199fc2c85b8aa, 0x0eb72ddC81c52ca2
    };
};

// SHA-512/256 implementation.
class sha512_256_t : public sha_base_t<uint64_t, initial_hash_values_512_256_t, round_constants_5x_t, 640, 32>
{
public:
    constexpr sha512_256_t(std::initializer_list<char> input)
        : sha_base_t(input.begin(), input.size())
    {
    }

    constexpr explicit sha512_256_t(std::string_view input)
        : sha_base_t(input.data(), input.size())
    {
    }

    constexpr explicit sha512_256_t(const char* input, size_t length)
        : sha_base_t(input, length)
    {
    }
};

}
