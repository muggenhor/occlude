#include "occlude/cipher/aes.h"

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <x86intrin.h>

namespace Occlude::Cipher {

AesKeySchedule::AesKeySchedule(const std::vector<uint8_t>& key) {
  static constexpr const uint8_t roundConstants[] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36 };
  switch(key.size()) {
    case 16: keysize = Aes128; break;
    case 24: // keysize = Aes192; break;
    case 32: // keysize = Aes256; break;
    default: std::abort();
  }
  std::memcpy(eroundKeys, key.data(), key.size());

  for (std::size_t n = 0; n < 10; ++n) {
    auto t = eroundKeys[n] ^ _mm_srli_si128(_mm_aeskeygenassist_si128(eroundKeys[n], roundConstants[n]), 0x0c);
    eroundKeys[n+1] = t ^ _mm_slli_si128 (t, 0x4) ^ _mm_slli_si128 (t, 0x8) ^ _mm_slli_si128 (t, 0xC);
  }
}

AesDecryptKeySchedule::AesDecryptKeySchedule(const AesKeySchedule& key)
  : keysize(key.keysize)
{
  using std::begin;
  using std::end;

  // compute decryption round keys in reverse order by performing a reverse MixColumn transform
  std::reverse_copy(begin(key.eroundKeys), begin(key.eroundKeys) + rounds(keysize) + 1, droundKeys);
  std::transform(begin(droundKeys) + 1, begin(droundKeys) + rounds(keysize), begin(droundKeys) + 1,
      [] (auto key) { return _mm_aesimc_si128(key); });
}

}
