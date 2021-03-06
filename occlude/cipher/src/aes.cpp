#include "occlude/cipher/aes.h"

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <x86intrin.h>

namespace Occlude::Cipher {

template <uint8_t round>
static __m128i nextRoundKey(__m128i in) {
  constexpr const uint8_t roundConstants[] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36 };
  auto t = in ^ _mm_srli_si128(_mm_aeskeygenassist_si128(in, roundConstants[round]), 0x0c);
  return t ^ _mm_slli_si128 (t, 0x4) ^ _mm_slli_si128 (t, 0x8) ^ _mm_slli_si128 (t, 0xC);
}

AesKeySchedule::AesKeySchedule(const std::vector<uint8_t>& key) {
  switch(key.size()) {
    case 16: keysize = Aes128; break;
    case 24: // keysize = Aes192; break;
    case 32: // keysize = Aes256; break;
    default: std::abort();
  }
  std::memcpy(eroundKeys, key.data(), key.size());

  eroundKeys[1] = nextRoundKey<0>(eroundKeys[0]);
  eroundKeys[2] = nextRoundKey<1>(eroundKeys[1]);
  eroundKeys[3] = nextRoundKey<2>(eroundKeys[2]);
  eroundKeys[4] = nextRoundKey<3>(eroundKeys[3]);
  eroundKeys[5] = nextRoundKey<4>(eroundKeys[4]);
  eroundKeys[6] = nextRoundKey<5>(eroundKeys[5]);
  eroundKeys[7] = nextRoundKey<6>(eroundKeys[6]);
  eroundKeys[8] = nextRoundKey<7>(eroundKeys[7]);
  eroundKeys[9] = nextRoundKey<8>(eroundKeys[8]);
  eroundKeys[10] = nextRoundKey<9>(eroundKeys[9]);
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
