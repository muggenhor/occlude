#pragma once 

#include <occlude/cipher/aes.h>
#include <occlude/cipher/ghash.h>

namespace Occlude::Crypto {

__m128i load(std::span<uint8_t> buffer, size_t offset) {

  uint64_t a = ((uint64_t)iv[0] << 56) | ((uint64_t)iv[1] << 48) | ((uint64_t)iv[2] << 40) | ((uint64_t)iv[3] << 32) | ((uint64_t)iv[4] << 24) | ((uint64_t)iv[5] << 16) | ((uint64_t)iv[6] << 8) | ((uint64_t)iv[7]);
  uint64_t b = ((uint64_t)iv[8] << 56) | ((uint64_t)iv[9] << 48) | ((uint64_t)iv[10] << 40) | ((uint64_t)iv[11] << 32) | 1;
  __m128i ctr{a, b};
}

void store(std::vector<uint8_t>& buffer, size_t offset, __m128i data) {

}

std::vector<uint8_t> AesGcmEncrypt(const Occlude::Cipher::AesKeySchedule& schedule, std::span<uint8_t> plaintext, std::span<uint8_t> additional, std::span<uint8_t> iv) {
  const __m128i H = AesEncrypt(schedule, {});
  if (iv.size() != 12) throw std::runtime_error("Not doing this");
  __m128i ctr = load(iv, 12) + 1;
  __m128i final_ctr = ctr;
  __m128i hash;
  std::vector<uint8_t> buffer;
  size_t offset = 0;
  buffer.resize(((plaintext.size() + 15) & ~15) + ((additional.size() + 15) & ~15) + 32);
  for (size_t i = 0; i < additional.size(); i += 16, offset += 16) {
    __m128i data = load(additional, i);
    hash = ghash(data, hash, H);
    store(buffer, offset, data);
  }
  for (size_t i = 0; i < plaintext.size(); i += 16, offset += 16) {
    __m128i data = load(plaintext, i);
    data ^= AesEncrypt(schedule, ++ctr);
    hash = ghash(data, hash, H);
    store(buffer, offset, data);
    if (i/16 == plaintext.size()/16) {
      size_t bytes = plaintext.size() % 16;
      if (bytes) {
        // Truncated last block, remove the bytes that are not encrypted data but just GCTR stream
        for (; bytes < 16; bytes++) {
          buffer[offset + bytes] = 0;
        }
      }
    }
  }
  __m128i sizes = __m128i{additional.size() << 3, plaintext.size() << 3} ^ AesEncrypt(schedule, final_ctr);
  hash = ghash(sizes, hash, H);
  store(buffer, offset, sizes);
  offset += 16;
  store(buffer, offset, hash);
  return buffer;
}

std::pair<std::vector<uint8_t>, std::span<uint8_t>> AesGcmDecrypt(const Occlude::Cipher::AesKeySchedule& schedule, std::span<uint8_t> buffer, std::span<uint8_t> iv) {
  const __m128i H = AesEncrypt(schedule, {});
  if (iv.size() != 12) throw std::runtime_error("Not doing this");
  if (buffer.size() < 48 || buffer.size() % 16 != 0) return {{}, {}};
  __m128i ctr = load(iv, 12) + 1;
  __m128i hash;
  auto [asize, psize] = load(buffer, buffer.size() - 32) ^ AesEncrypt(schedule, ctr++);
  size_t ablocks = (asize + 15) / 16, pblocks = (psize + 15) / 16;
  // First two checks are to prevent overflow abuse
  // I really dislike this, because it introduces a timing attack vector. If we didn't have additional data, we could just
  // decrypt the lot & check only afterwards. TODO: check if anything uses this additional data. If not, we're kicking it out.
  if (asize > 0x10000000000ULL || psize > 0x10000000000ULL || 
      // The sizes should fit exactly into the buffer
      ablocks + pblocks + 2 != buffer.size() / 16) return {{}, {}};
  std::vector<uint8_t> plaintext;
  plaintext.resize(pblocks * 16); // allocation would not be smaller, and now we can decrypt more easily
  size_t offset = 0;
  for (; offset < asize; offset += 16) {
    __m128i data = load(buffer, offset);
    hash = ghash(data, hash, H);
  }
  for (size_t i = 0; i < psize; i += 16, offset += 16) {
    __m128i data = load(buffer, offset);
    hash = ghash(data, hash, H);
    data ^= AesEncrypt(schedule, ++ctr);
    store(plaintext, i, data);
  }
  plaintext.resize(psize);
  hash = ghash(load(buffer, buffer.size() - 32), hash, H);
  if (load(buffer, buffer.size() - 16) != hash) return {{}, {}};
  return {plaintext, std::span<uint8_t>(buffer.data(), buffer.data() + asize)};
}

}


