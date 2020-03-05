#pragma once

#include <x86intrin.h>
#include <cstdint>
#include <ostream>

struct block {
  __m128i b = {};
  constexpr block() = default;
  constexpr block(__m128i data)
  : b(data)
  {}
  constexpr block(int64_t a, int64_t b)
  : b{a, b}
  {}
  constexpr block& operator=(__m128i data) noexcept { b = data; return *this; }
  constexpr operator __m128i() const noexcept { return b; }
  constexpr block operator<<(int count) { return b << count; }
  constexpr block operator>>(int count) { return b >> count; }
  constexpr block& operator^=(block a) { b ^= a.b; return *this; }
  constexpr block operator|(block a) noexcept { return b | a.b; }
  friend constexpr block operator^(block a, block b) noexcept {
    return block(a.b ^ b.b);
  }
  friend constexpr bool operator==(block a, block b) noexcept {
    auto [x,y] = a.b == b.b;
    return !x && !y;
  }
};

constexpr block reduction = { static_cast<int64_t>(0xC200'0000'0000'0000), 0 };

block galoisMultiply(block xy, block h) {
  // Use 4 64-bit clmul's to do a 128-bit clmul
  block resultLow = _mm_clmulepi64_si128(xy, h, 0x00);
  block resultMid = _mm_clmulepi64_si128(xy, h, 0x10) ^ _mm_clmulepi64_si128(xy, h, 0x01);
  block resultHigh = _mm_clmulepi64_si128(xy, h, 0x11);

  // Combine half results
  resultLow.b[1] ^= resultMid.b[0];
  resultHigh.b[0] ^= resultMid.b[1];

  block tmp7 = _mm_srli_epi32(resultLow, 31);
  block tmp8 = _mm_srli_epi32(resultHigh, 31);
  resultLow = _mm_slli_epi32(resultLow, 1);
  resultHigh = _mm_slli_epi32(resultHigh, 1);

  resultLow = resultLow | _mm_slli_si128(tmp7, 4);
  resultHigh = resultHigh | _mm_srli_si128(tmp7, 12) | _mm_slli_si128(tmp8, 4);

  block ovLow = _mm_clmulepi64_si128(resultLow, reduction, 0x00);
  resultLow.b[1] ^= ovLow.b[0];


  resultHigh.b[0] ^= ovLow.b[1];
  resultHigh ^= _mm_clmulepi64_si128(resultLow, reduction, 0x01) ^ resultLow;

  return resultHigh;
}

block ghash_block(block x, block h, block hash) {
  return galoisMultiply(hash ^ x, h);
}

