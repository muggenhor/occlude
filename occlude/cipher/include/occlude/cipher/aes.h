#pragma once

#include <x86intrin.h>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <cstring>
  #include <cstdio>

namespace Occlude::Cipher {

class AesKeySchedule {
public:
  explicit AesKeySchedule(const std::vector<uint8_t>& key) {
    const uint8_t roundConstants[] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36 };
    switch(key.size()) {
      case 16: keysize = Aes128; break;
      case 24: // keysize = Aes192; break;
      case 32: // keysize = Aes256; break;
      default: abort();
    }
    memcpy(eroundKeys, key.data(), key.size());
    for (size_t n = 0; n < 10; n++) {
        __m128i t = eroundKeys[n] ^ _mm_srli_si128(_mm_aeskeygenassist_si128 (eroundKeys[n] ,roundConstants[n]), 0x0c);
        eroundKeys[n+1] = t ^ _mm_slli_si128 (t, 0x4) ^ _mm_slli_si128 (t, 0x8) ^ _mm_slli_si128 (t, 0xC);
    }
    for (size_t n = 0; n < 9; n++) {
        droundKeys[8 - n] = _mm_aesimc_si128(eroundKeys[n+1]);
    } 
  }
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

__m128i AesEncrypt(const AesKeySchedule& key, __m128i block) {
  block ^= key.eroundKeys[0];
  for (size_t n = 0; n < 9; n++) {
    block = _mm_aesenc_si128(block, key.eroundKeys[n+1]);
  }
  block = _mm_aesenclast_si128(block, key.eroundKeys[10]);
  return block;
}

__m128i AesDecrypt(const AesKeySchedule& key, __m128i block) {
  block ^= key.eroundKeys[10];
  for (size_t n = 0; n < 9; n++) {
    block = _mm_aesdec_si128(block, key.droundKeys[n]);
  }
  block = _mm_aesdeclast_si128(block, key.eroundKeys[0]);
  return block;
}

}

