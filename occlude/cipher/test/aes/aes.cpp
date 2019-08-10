#include "occlude/cipher/aes.h"
#include <vector>
#include <catch.hpp>
#include <iostream>

bool EncDecWorks(
    const Occlude::Cipher::AesKeySchedule& enc_sch
  , const Occlude::Cipher::AesDecryptKeySchedule& dec_sch
  , __m128i plain
  , __m128i cipher
  ) {
  auto newenc = Occlude::Cipher::AesEncrypt(enc_sch, plain);
  auto newplain = Occlude::Cipher::AesDecrypt(dec_sch, cipher);
  auto [x,y] = newenc == cipher;
  auto [a,b] = newplain == plain;
  return (x && y && a && b);
}

TEST_CASE("key schedule") {
  std::vector<uint8_t> aeskey2 = 
  { 0x54, 0x68, 0x61, 0x74, 0x73, 0x20, 0x6D, 0x79, 0x20, 0x4B, 0x75, 0x6E, 0x67, 0x20, 0x46, 0x75 };
  __m128i roundKeys[11] = {
    __m128i{(int64_t)0x796D207374616854, (int64_t)0x754620676E754B20},
    __m128i{(int64_t)0x88911291F1FC32E2, (int64_t)0x93A279D6E6E459B1},
    __m128i{(int64_t)0x8FB11AC707200856, (int64_t)0xFAF73AA069554376},
    __m128i{(int64_t)0x68BC7A15E70D60D2, (int64_t)0xFB1E03C301E93963},
    __m128i{(int64_t)0xA1BE68B4C90212A1, (int64_t)0x5B495214A05751D7},
    __m128i{(int64_t)0x92854105333B29B1, (int64_t)0x699B42C632D210D2},
    __m128i{(int64_t)0x15477CB887C23DBD, (int64_t)0x4E0E2EAC27956C6A},
    __m128i{(int64_t)0x03AAEA7416ED96CC, (int64_t)0x6A31A8B2243F861E},
    __m128i{(int64_t)0x2245BBFA21EF518E, (int64_t)0x6C4B9556067A3DE4},
    __m128i{(int64_t)0xB2FA594590BFE2BF, (int64_t)0xD8CBF1F7B48064A1},
    __m128i{(int64_t)0x4A24A46DF8DEFD28, (int64_t)0x266F313BFEA4C0CC}
  };

  Occlude::Cipher::AesKeySchedule h(aeskey2);
  REQUIRE(h.eroundKeys[0][0] == roundKeys[0][0]);
  REQUIRE(h.eroundKeys[0][1] == roundKeys[0][1]);
  REQUIRE(h.eroundKeys[1][0] == roundKeys[1][0]);
  REQUIRE(h.eroundKeys[1][1] == roundKeys[1][1]);
  REQUIRE(h.eroundKeys[2][0] == roundKeys[2][0]);
  REQUIRE(h.eroundKeys[2][1] == roundKeys[2][1]);
  REQUIRE(h.eroundKeys[3][0] == roundKeys[3][0]);
  REQUIRE(h.eroundKeys[3][1] == roundKeys[3][1]);
  REQUIRE(h.eroundKeys[4][0] == roundKeys[4][0]);
  REQUIRE(h.eroundKeys[4][1] == roundKeys[4][1]);
  REQUIRE(h.eroundKeys[5][0] == roundKeys[5][0]);
  REQUIRE(h.eroundKeys[5][1] == roundKeys[5][1]);
  REQUIRE(h.eroundKeys[6][0] == roundKeys[6][0]);
  REQUIRE(h.eroundKeys[6][1] == roundKeys[6][1]);
  REQUIRE(h.eroundKeys[7][0] == roundKeys[7][0]);
  REQUIRE(h.eroundKeys[7][1] == roundKeys[7][1]);
  REQUIRE(h.eroundKeys[8][0] == roundKeys[8][0]);
  REQUIRE(h.eroundKeys[8][1] == roundKeys[8][1]);
  REQUIRE(h.eroundKeys[9][0] == roundKeys[9][0]);
  REQUIRE(h.eroundKeys[9][1] == roundKeys[9][1]);
  REQUIRE(h.eroundKeys[10][0] == roundKeys[10][0]);
  REQUIRE(h.eroundKeys[10][1] == roundKeys[10][1]);
}


TEST_CASE("aes test vectors") {
  std::vector<uint8_t> aeskey = 
  { 0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C };
  Occlude::Cipher::AesKeySchedule enc_sch(aeskey);
  Occlude::Cipher::AesDecryptKeySchedule dec_sch(enc_sch);
  REQUIRE(EncDecWorks(enc_sch, dec_sch, 
    __m128i{(int64_t)0x969f402ee2bec16b, (int64_t)0x2a179373117e3de9}, 
    __m128i{(int64_t)0x60367a0db47bd73a, (int64_t)0x97ef6624f3ca9ea8}));
  REQUIRE(EncDecWorks(enc_sch, dec_sch, 
    __m128i{(int64_t)0x9cac031e578a2dae, (int64_t)0x518eaf45ac6fb79e}, 
    __m128i{(int64_t)0x9d69b90385d5d3f5, (int64_t)0xafbafd965a8985e7}));
  REQUIRE(EncDecWorks(enc_sch, dec_sch, 
    __m128i{(int64_t)0x11e45ca3461cc830, (int64_t)0xef520a1a19c1fbe5}, 
    __m128i{(int64_t)0x23ce8e597fcdb143, (int64_t)0x880603ede3001b88}));
  REQUIRE(EncDecWorks(enc_sch, dec_sch, 
    __m128i{(int64_t)0x179b4fdf45249ff6, (int64_t)0x10376ce67b412bad}, 
    __m128i{(int64_t)0x3fade8275e780c7b, (int64_t)0xd45d720471202382}));
}

