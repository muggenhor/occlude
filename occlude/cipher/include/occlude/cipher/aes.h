#pragma once

#include <span>
#include <cstddef>

namespace Ripley::Cipher {

class AesKeySchedule {
public:
  explicit AesKeySchedule(std::span<const std::byte>);
};

void AesEncrypt(const AesKeySchedule& key, std::span<std::byte> data);
void AesDecrypt(const AesKeySchedule& key, std::span<std::byte> data);

}

