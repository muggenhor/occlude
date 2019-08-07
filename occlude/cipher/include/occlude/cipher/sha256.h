#pragma once

#include <vector>
#include <span>
#include <cstddef>

namespace Occlude::Cipher {

struct Sha256 {
  operator std::vector<uint8_t>();
  size_t byteCount = 0;
  std::array<uint32_t, 8> state = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };
};

}


