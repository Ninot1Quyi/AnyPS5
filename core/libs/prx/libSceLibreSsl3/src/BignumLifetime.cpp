#include "prx/libSceLibreSsl3/libSceLibreSsl3.hpp"
#include "prx/libSceLibreSsl/include/Error.hpp"
#include "prx/libc/libc.hpp"
#include <cstddef>
#include <cstring>
#include <limits>
#include <stdexcept>

namespace {

constexpr int Malloced = 1;
constexpr int StaticData = 2;
constexpr int ConstantTime = 4;
constexpr int MaxWords = std::numeric_limits<std::int32_t>::max() / 256;

static_assert(sizeof(LibreSsl3Bignum) == 24);
static_assert(offsetof(LibreSsl3Bignum, top) == 8);
static_assert(offsetof(LibreSsl3Bignum, dmax) == 12);
static_assert(offsetof(LibreSsl3Bignum, neg) == 16);
static_assert(offsetof(LibreSsl3Bignum, flags) == 20);

void Clear(void* pointer, std::size_t size) {
    auto* bytes = static_cast<volatile unsigned char*>(pointer);
    for (std::size_t index = 0; index < size; ++index) bytes[index] = 0;
}

}

extern "C" void APS5_VABI BN_clear_free_nid_postfix(LibreSsl3Bignum* value) {
    if (!value) return;
    const bool release = (value->flags & Malloced) != 0;
    if (value->d && !(value->flags & StaticData)) {
        if (value->dmax < 0) throw std::invalid_argument("BN_clear_free: negative limb capacity");
        Clear(value->d, static_cast<std::size_t>(value->dmax) * sizeof(*value->d));
        free_nid_postfix(value->d);
    }
    Clear(value, sizeof(*value));
    if (release) free_nid_postfix(value);
}

extern "C" LibreSsl3Bignum* APS5_VABI BN_dup_nid_postfix(const LibreSsl3Bignum* source) {
    if (!source) return nullptr;
    if (source->top > 0 && source->top <= MaxWords && (!source->d || source->top > source->dmax))
        throw std::invalid_argument("BN_dup: invalid limb storage");
    auto* copy = static_cast<LibreSsl3Bignum*>(calloc_nid_postfix(1, sizeof(LibreSsl3Bignum)));
    if (!copy) {
        LibreSslPutError_nid_no_patch(3, 0xfff, 65);
        return nullptr;
    }
    copy->flags = Malloced;
    if (source->top < 0 || source->top > MaxWords) {
        if (source->top > MaxWords) LibreSslPutError_nid_no_patch(3, 0xfff, 114);
        BN_clear_free_nid_postfix(copy);
        return nullptr;
    }
    if (source->top > 0) {
        copy->d = static_cast<std::uint64_t*>(calloc_nid_postfix(static_cast<std::size_t>(source->top), sizeof(*copy->d)));
        if (!copy->d) {
            LibreSslPutError_nid_no_patch(3, 0xfff, 65);
            BN_clear_free_nid_postfix(copy);
            return nullptr;
        }
        copy->dmax = source->top;
        std::memcpy(copy->d, source->d, static_cast<std::size_t>(source->top) * sizeof(*copy->d));
    }
    copy->top = source->top;
    copy->neg = source->neg;
    copy->flags |= source->flags & ConstantTime;
    return copy;
}
