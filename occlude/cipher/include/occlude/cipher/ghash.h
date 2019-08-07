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
  friend constexpr block operator^(block a, block b) noexcept {
    return block(a.b ^ b.b);
  }
  friend constexpr bool operator==(block a, block b) noexcept {
    auto [x,y] = a.b == b.b;
    return !x && !y;
  }
};

constexpr block reduction = { 0, 0b1000'0111 };

constexpr uint64_t tops = 0xaaaaaaaaaaaaaaaa;
constexpr uint64_t bottoms = 0x5555555555555555;

constexpr block clmul(block a, block b, uint8_t selector) {
#ifdef __AES__
//  if constexpr(std::is_constant_evaluated()) {
  if constexpr(true) {
#endif
    __m128i a_ = { 0, (selector & 1) ? a.b[1] : a.b[0] };
    __m128i b_ = { 0, (selector & 0x10) ? b.b[1] : b.b[0] };
    __m128i t = ((a_ & tops) * (b_ & tops));
    __m128i b = ((a_ & bottoms) * (b_ & bottoms));
    t[0] &= tops;
    t[1] &= tops;
    b[0] &= bottoms;
    b[1] &= bottoms;
    return t | b;
#ifdef __AES__
  } else {
    return _mm_clmulepi64_si128(a, b, selector);
  }
#endif
}

constexpr block galoisMultiply(block xy, block h) {
  // Use 4 64-bit clmul's to do a 128-bit clmul
  block resultLow = clmul(xy, h, 0x00);
  block resultMid1 = clmul(xy, h, 0x10);
  block resultMid2 = clmul(xy, h, 0x01);
  block resultHigh = clmul(xy, h, 0x11);
  // Combine half results
  resultLow ^= (resultMid1 << 64) ^ (resultMid2 << 64);
  resultHigh ^= (resultMid1 >> 64) ^ (resultMid2 >> 64);
  // Take high result and reduce it with polynomial
  block overflowLow = clmul(resultHigh, reduction, 0x00);
  block overflowHigh = clmul(resultHigh, reduction, 0x01);
  // This gives us a 135 bit result. Take the bottom 128 and add it in
  resultLow ^= overflowLow ^ (overflowHigh << 64);
  // then take the top 7 bit result, reduce that again (to a 14-bit result), and add it in too.
  resultLow ^= clmul(overflowHigh, reduction, 0x01);
  // since add cannot overflow, this is now the 128-bit result
  return resultLow; 
}

constexpr block ghash_block(block x, block h, block hash) {
  return galoisMultiply(hash ^ x, h);
}

