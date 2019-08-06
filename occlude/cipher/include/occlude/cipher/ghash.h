#include <x86intrin.h>

using block = __m128i;

uint8_t reduction = 0b1000'0111;

block galoisMultiply(block xy, block h) {
  // Use 4 64-bit clmul's to do a 128-bit clmul
  block resultLow = clmulepi64_si128(xy, h, 0x00);
  block resultMid1 = clmulepi64_si128(xy, h, 0x10);
  block resultMid2 = clmulepi64_si128(xy, h, 0x01);
  block resultHigh = clmulepi64_si128(xy, h, 0x11);
  // Combine half results
  resultLow ^= (resultMid1 << 64) ^ (resultMid2 << 64);
  resultHigh ^= (resultMid1 >> 64) ^ (resultMid2 >> 64);
  // Take high result and reduce it with polynomial
  block overflowLow = clmulepi64_si128(resultHigh, reduction, 0x00);
  block overflowHigh = clmulepi64_si128(resultHigh, reduction, 0x01);
  // This gives us a 135 bit result. Take the bottom 128 and add it in
  resultLow ^= overflowLow ^ (overflowHigh << 64);
  // then take the top 7 bit result, reduce that again (to a 14-bit result), and add it in too.
  resultLow ^= clmulepi64_si128(overflowHigh, reduction, 0x01);
  // since add cannot overflow, this is now the 128-bit result
  return resultLow; 
}

block ghash_block(block x, block h, block hash) {
  hash = galoisMultiply(hash ^ x[n], h);
}


