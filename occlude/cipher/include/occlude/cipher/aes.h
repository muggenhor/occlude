#pragma once

#include <cstdint>
#include <vector>
#include <x86intrin.h>

namespace Occlude::Cipher {

class AesKeySchedule {
public:
  explicit AesKeySchedule(const std::vector<uint8_t>& key);
//private:
  __m128i eroundKeys[15];
  enum keytype{
    Aes128,
    Aes192,
    Aes256
  } keysize = Aes128;
  friend constexpr unsigned rounds(keytype size)
  {
    switch (size)
    {
      case Aes128: return 10;
      case Aes192: return 12;
      case Aes256: return 14;
    }

    throw "unknown keysize";
  }
  friend __m128i AesEncrypt(const AesKeySchedule& key, __m128i block);
};

class AesDecryptKeySchedule {
public:
  explicit AesDecryptKeySchedule(const AesKeySchedule& key);
  __m128i droundKeys[15];
  AesKeySchedule::keytype keysize;

  friend __m128i AesDecrypt(const AesDecryptKeySchedule& key, __m128i block);
};

inline __m128i AesEncrypt(const AesKeySchedule& key, __m128i block) {
  // whitening
  block ^= key.eroundKeys[0];

  for (size_t n = 1; n < rounds(key.keysize); n++) {
    block = _mm_aesenc_si128(block, key.eroundKeys[n]);
  }
  block = _mm_aesenclast_si128(block, key.eroundKeys[rounds(key.keysize)]);
  return block;
}

inline __m128i AesDecrypt(const AesDecryptKeySchedule& key, __m128i block) {
  block ^= key.droundKeys[0];
  for (size_t n = 1; n < rounds(key.keysize); n++) {
    block = _mm_aesdec_si128(block, key.droundKeys[n]);
  }
  block = _mm_aesdeclast_si128(block, key.droundKeys[rounds(key.keysize)]);
  return block;
}

}
