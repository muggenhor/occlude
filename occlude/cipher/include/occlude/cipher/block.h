#pragma once

#include <x86intrin.h>
#include <cstdint>
#include <ostream>

struct block {
  __m128i b = {};
  block() = default;
  block(__m128i data)
  : b(data)
  {}
  block(int64_t a, int64_t b)
  : b{a, b}
  {}
  block& operator=(__m128i data) noexcept { b = data; return *this; }
  operator __m128i() const noexcept { return b; }
  block operator<<(int count) { return b << count; }
  block operator>>(int count) { return b >> count; }
  block& operator^=(block a) { b ^= a.b; return *this; }
  block operator|(block a) noexcept { return b | a.b; }
  friend block operator^(block a, block b) noexcept {
    return block(a.b ^ b.b);
  }
  friend bool operator==(block a, block b) noexcept {
    return a.b[0] == b.b[0] && a.b[1] == b.b[1];
  }
  friend std::ostream& operator<<(std::ostream& os, block a) {
    const uint8_t* p = (const uint8_t*)&a;
    for (size_t n = 0; n < 16; n++) {
      if (n && n % 4 == 0) os << " ";
      os << std::hex << (uint32_t)p[n];
    }
    return os;
  }
};

