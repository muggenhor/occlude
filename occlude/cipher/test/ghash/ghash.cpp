#include "occlude/cipher/ghash.h"
#include <vector>
#include <catch.hpp>

struct ghash_test_vector {
  block h;
  block x[4];
  block expectedGhash;
};

block ghash(const block* x, block h) {
  block hash = {};
  for (size_t n = 0; n < 4; n++) {
    hash = ghash_block(x[n], h, hash);
  }
  return hash;
}

TEST_CASE("ghash test vectors") {
  const ghash_test_vector vectors[] = {
    {
      { (long long int)0xb83b533708bf535d, (long long int)0x0aa6e52980d53b78 },
      { block{ (long long int)0x42831ec221777424, (long long int)0x4b7221b784d0d49c }, 
        block{ (long long int)0xe3aa212f2c02a4e0, (long long int)0x35c17e2329aca12e }, 
        block{ (long long int)0x21d514b25466931c, (long long int)0x7d8f6a5aac84aa05 }, 
        block{ (long long int)0x1ba30b396a0aac97, (long long int)0x3d58e091473f5985 },  
      },
      { (long long int)0x7f1b32b81b820d02, (long long int)0x614f8895ac1d4eac },
    },
  };
  for (auto& v : vectors) {
    REQUIRE(ghash(v.x, v.h) == v.expectedGhash);
  }
}

