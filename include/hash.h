#pragma once

#include <cstdint>
#include <array>
#include "openssl/evp.h"

using std::array;

namespace hash {
    struct Hasher {
        Hasher();
        Hasher(const Hasher&) = delete;
        Hasher(Hasher&&) = delete;
        Hasher& operator=(const Hasher&) = delete;
        Hasher& operator=(Hasher&&) = delete;
        ~Hasher();
        int update(const uint8_t *src, int len) noexcept;
        int finalize(uint8_t *dst, int *len) noexcept;

        private:
            EVP_MD_CTX *ctx = nullptr; 
            char buf[EVP_MAX_MD_SIZE];
    };

    array<uint8_t, 56> sha224(const uint8_t *src, int len) noexcept;
}
