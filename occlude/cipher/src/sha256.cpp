/* Based on code from Igor Pavlov in the Public domain */
#include "occlude/cipher/sha256.h"

void Occlude::Cipher::Sha256::addBytes(const uint8_t* newdata, size_t length) {
  for (size_t i = 0; i < length; i++) {
    size_t byteindex = (byteCount) % 64;
    data[byteindex / 4] |= ((uint32_t)newdata[i] << (8*(3-byteindex % 4)));
    if ((++byteCount % 64) == 0) {
      transform();
    }
  }
}

Occlude::Cipher::Sha256::operator std::vector<uint8_t>() const {
  Sha256 copy = *this;

  uint8_t blank[64] = {0x80};
  copy.addBytes(blank, (byteCount % 64) > 55 ? 120 - (byteCount % 64): 56 - (byteCount % 64));
 
  uint8_t lenInBits[8] = { 
    (uint8_t)((byteCount >> 53) & 0xFF), 
    (uint8_t)((byteCount >> 45) & 0xFF),
    (uint8_t)((byteCount >> 37) & 0xFF),
    (uint8_t)((byteCount >> 29) & 0xFF),
    (uint8_t)((byteCount >> 21) & 0xFF),
    (uint8_t)((byteCount >> 13) & 0xFF),
    (uint8_t)((byteCount >> 5) & 0xFF),
    (uint8_t)((byteCount << 3) & 0xFF)
  };
  copy.addBytes(lenInBits, 8);

  std::vector<uint8_t> hash;
  for (size_t i = 0; i < 8; i++)
  {
    hash.push_back((uint8_t)(copy.state[i] >> 24));
    hash.push_back((uint8_t)(copy.state[i] >> 16));
    hash.push_back((uint8_t)(copy.state[i] >> 8));
    hash.push_back((uint8_t)(copy.state[i]));
  }
  return hash;
}

static const uint32_t K[64] = {
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
  0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
  0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
  0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static inline uint32_t rotr(uint32_t value, uint8_t rotation) {
  return (value >> rotation) | (value << (32 - rotation));
}

inline uint32_t S0(uint32_t x) {
  return rotr(x, 2) ^ rotr(x,13) ^ rotr(x, 22);
}

inline uint32_t S1(uint32_t x) {
  return rotr(x, 6) ^ rotr(x,11) ^ rotr(x, 25);
}

inline uint32_t s0(uint32_t x) {
  return rotr(x, 7) ^ rotr(x,18) ^ (x >> 3);
}

inline uint32_t s1(uint32_t x) {
  return rotr(x,17) ^ rotr(x,19) ^ (x >> 10);
}

inline uint32_t Ch(uint32_t x,uint32_t y,uint32_t z) {
  return z^(x&(y^z));
}

inline uint32_t Maj(uint32_t x,uint32_t y,uint32_t z) {
  return (x&y)|(z&(x|y));
}

#define a(i) T[(0-(i))&7]
#define b(i) T[(1-(i))&7]
#define c(i) T[(2-(i))&7]
#define d(i) T[(3-(i))&7]
#define e(i) T[(4-(i))&7]
#define f(i) T[(5-(i))&7]
#define g(i) T[(6-(i))&7]
#define h(i) T[(7-(i))&7]

void Occlude::Cipher::Sha256::transform()
{
  uint32_t T[8];
  for (size_t j = 0; j < 8; j++)
    T[j] = state[j];

  for (size_t i = 0; i < 16; i++)
  {
    h(i) += S1(e(i)) + Ch(e(i),f(i),g(i)) + K[i] + data[i];
    d(i) += h(i); 
    h(i) += S0(a(i)) + Maj(a(i), b(i), c(i));
  }
  for (size_t j = 16; j < 64; j++)
  {
    size_t i = (j % 16);
    data[i] += s1(data[(i+14)&15]) + data[(i+9)&15] + s0(data[(i+1)&15]);
    h(i) += S1(e(i)) + Ch(e(i),f(i),g(i)) + K[j] + data[i];
    d(i) += h(i); 
    h(i) += S0(a(i)) + Maj(a(i), b(i), c(i));
  }

  for (size_t j = 0; j < 8; j++)
    state[j] += T[j];

  data = {};
}


