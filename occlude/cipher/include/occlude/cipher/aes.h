#pragma once

#include <span>
#include <cstddef>

namespace Occlude::Cipher {

class AesKeySchedule {
public:
  explicit AesKeySchedule(std::span<const std::byte>);
private:
  enum {
    Aes128,
    Aes192,
    Aes256
  } keysize = Aes128;
  __m128i roundKeys[14];
};

void AesEncrypt(const AesKeySchedule& key, std::span<std::byte> data);
void AesDecrypt(const AesKeySchedule& key, std::span<std::byte> data);

}

