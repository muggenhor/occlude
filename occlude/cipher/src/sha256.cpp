/* Based on code from Igor Pavlov in the Public domain */
#include "Sha256.h"

static void Sha256_Transform(uint32_t *state, const uint32_t *data);

static void Sha256_WriteByteBlock(CSha256 *p)
{
  uint32_t data32[16];
  unsigned i;
  for (i = 0; i < 16; i++)
    data32[i] =
      ((uint32_t)(p->buffer[i * 4    ]) << 24) +
      ((uint32_t)(p->buffer[i * 4 + 1]) << 16) +
      ((uint32_t)(p->buffer[i * 4 + 2]) <<  8) +
      ((uint32_t)(p->buffer[i * 4 + 3]));
  Sha256_Transform(p->state, data32);
}

void Sha256_Update(CSha256 *p, const uint8_t *data, size_t size)
{
  uint32_t curBufferPos = (uint32_t)p->count & 0x3F;
  while (size > 0)
  {
    p->buffer[curBufferPos++] = *data++;
    p->count++;
    size--;
    if (curBufferPos == 64)
    {
      curBufferPos = 0;
      Sha256_WriteByteBlock(p);
    }
  }
}

void Sha256_Final(CSha256 *p, uint8_t *digest)
{
  uint64_t lenInBits = (p->count << 3);
  uint32_t curBufferPos = (uint32_t)p->count & 0x3F;
  unsigned i;
  p->buffer[curBufferPos++] = 0x80;
  while (curBufferPos != (64 - 8))
  {
    curBufferPos &= 0x3F;
    if (curBufferPos == 0)
      Sha256_WriteByteBlock(p);
    p->buffer[curBufferPos++] = 0;
  }
  for (i = 0; i < 8; i++)
  {
    p->buffer[curBufferPos++] = (uint8_t)(lenInBits >> 56);
    lenInBits <<= 8;
  }
  Sha256_WriteByteBlock(p);

  for (i = 0; i < 8; i++)
  {
    *digest++ = (uint8_t)(p->state[i] >> 24);
    *digest++ = (uint8_t)(p->state[i] >> 16);
    *digest++ = (uint8_t)(p->state[i] >> 8);
    *digest++ = (uint8_t)(p->state[i]);
  }
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

#define rotr(x, c) ((x >> c) | (x << 32-c))

#define S0(x) (rotr(x, 2) ^ rotr(x,13) ^ rotr(x, 22))
#define S1(x) (rotr(x, 6) ^ rotr(x,11) ^ rotr(x, 25))
#define s0(x) (rotr(x, 7) ^ rotr(x,18) ^ (x >> 3))
#define s1(x) (rotr(x,17) ^ rotr(x,19) ^ (x >> 10))

#define blk0(i) (W[i] = data[i])
#define blk2(i) (W[i&15] += s1(W[(i-2)&15]) + W[(i-7)&15] + s0(W[(i-15)&15]))

#define Ch(x,y,z) (z^(x&(y^z)))
#define Maj(x,y,z) ((x&y)|(z&(x|y)))

#define a(i) T[(0-(i))&7]
#define b(i) T[(1-(i))&7]
#define c(i) T[(2-(i))&7]
#define d(i) T[(3-(i))&7]
#define e(i) T[(4-(i))&7]
#define f(i) T[(5-(i))&7]
#define g(i) T[(6-(i))&7]
#define h(i) T[(7-(i))&7]

static void Sha256_Transform(uint32_t *state, const uint32_t *data)
{
  uint32_t W[16];
  uint32_t T[8];
  for (size_t j = 0; j < 8; j++)
    T[j] = state[j];

  for (size_t j = 0; j < 64; j++)
  {
    size_t i = (j % 16);
    h(i) += S1(e(i)) + Ch(e(i),f(i),g(i)) + K[j] + (j >= 15 ? blk2(i) : blk0(i));
    d(i) += h(i); 
    h(i) += S0(a(i)) + Maj(a(i), b(i), c(i));
  }

  for (size_t j = 0; j < 8; j++)
    state[j] += T[j];
}

