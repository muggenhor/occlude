#pragma once

#include <cstdint>
#include <vector>
#include <x86intrin.h>

namespace Occlude::Cipher {

class AesKeySchedule {
public:
  explicit AesKeySchedule(const std::vector<uint8_t>& key);
//private:
  enum {
    Aes128,
    Aes192,
    Aes256
  } keysize = Aes128;
  __m128i eroundKeys[11];
  __m128i droundKeys[9];
  friend __m128i AesEncrypt(const AesKeySchedule& key, __m128i block);
  friend __m128i AesDecrypt(const AesKeySchedule& key, __m128i block);
};

inline __m128i AesEncrypt(const AesKeySchedule& key, __m128i block) {
  block ^= key.eroundKeys[0];
  for (size_t n = 0; n < 9; n++) {
    block = _mm_aesenc_si128(block, key.eroundKeys[n+1]);
  }
  block = _mm_aesenclast_si128(block, key.eroundKeys[10]);
  return block;
}

inline __m128i AesDecrypt(const AesKeySchedule& key, __m128i block) {
  block ^= key.eroundKeys[10];
  for (size_t n = 0; n < 9; n++) {
    block = _mm_aesdec_si128(block, key.droundKeys[n]);
  }
  block = _mm_aesdeclast_si128(block, key.eroundKeys[0]);
  return block;
}

}
