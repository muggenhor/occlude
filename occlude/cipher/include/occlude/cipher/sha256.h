#pragma once

#include <vector>
#include <span>
#include <cstddef>

namespace Ripley::Cipher {

std::vector<std::byte> sha256(std::span<std::byte> data, std::vector<std::byte> currentHash = std::vector<std::byte>(32));

}


