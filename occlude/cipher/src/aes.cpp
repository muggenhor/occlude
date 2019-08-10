#include "occlude/cipher/aes.h"

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <x86intrin.h>

namespace Occlude::Cipher {

AesKeySchedule::AesKeySchedule(const std::vector<uint8_t>& key) {
  const uint8_t roundConstants[] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36 };
  switch(key.size()) {
    case 16: keysize = Aes128; break;
    case 24: // keysize = Aes192; break;
    case 32: // keysize = Aes256; break;
    default: std::abort();
  }
  std::memcpy(eroundKeys, key.data(), key.size());

  for (std::size_t n = 0; n < 10; ++n) {
      __m128i t = eroundKeys[n] ^ _mm_srli_si128(_mm_aeskeygenassist_si128 (eroundKeys[n] ,roundConstants[n]), 0x0c);
      eroundKeys[n+1] = t ^ _mm_slli_si128 (t, 0x4) ^ _mm_slli_si128 (t, 0x8) ^ _mm_slli_si128 (t, 0xC);
  }
  for (size_t n = 0; n < 9; n++) {
      droundKeys[8 - n] = _mm_aesimc_si128(eroundKeys[n+1]);
  }
}

}
