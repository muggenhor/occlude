#pragma once

#include <array>
#include <cstddef>
#include <vector>

namespace Occlude::Cipher {

struct Sha256 {
  void addBytes(const uint8_t* data, size_t length);
  operator std::vector<uint8_t>() const;
  size_t byteCount = 0;
  std::array<uint32_t, 8> state = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };
  std::array<uint32_t, 16> data = {};
private:
  void transform();
};

inline std::vector<uint8_t> sha256(const uint8_t* data, size_t length) {
  Sha256 obj;
  obj.addBytes(data, length);
  return obj;
}

}


