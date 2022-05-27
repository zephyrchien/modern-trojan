#include "hash.h"

#include <cassert>
#include "fmt/core.h"
#include "fmt/ranges.h"
#include "range/v3/all.hpp"

using ranges::view::take;

namespace hash {
    // EVP_MD_CTX_new may return NULL if no enough memory.
    Hasher::Hasher(): ctx(EVP_MD_CTX_new()) {
        assert(EVP_DigestInit_ex(this->ctx, EVP_sha224(), nullptr));
    }

    Hasher::~Hasher() {
        EVP_MD_CTX_free(this->ctx);
        this->ctx = nullptr;
    }

    int Hasher::update(const uint8_t *src, int len) noexcept {
        return EVP_DigestUpdate(this->ctx, src, len);
    }

    int Hasher::finalize(uint8_t *dst, int *len) noexcept {
        // will not overflow
        return EVP_DigestFinal_ex(this->ctx, (unsigned char*)dst, (unsigned int*)len);
    }

    array<uint8_t, 56> sha224(const uint8_t *src, int len) noexcept {
        Hasher hasher{};
        array<uint8_t, 56> hex{0};
        array<uint8_t, EVP_MAX_MD_SIZE> buffer{0};
        int length = 0;
        int offset = 0;

        assert(hasher.update(src, len));
        assert(hasher.finalize(buffer.data(), &length));
        assert(length == 28);

        for (auto b: buffer | take(28)) {
            fmt::format_to(hex.data()+offset, "{:x}", b);
            offset +=2;
        }
        return hex;
    }
}
