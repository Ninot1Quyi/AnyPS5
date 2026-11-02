#include "prx/libSceLibreSsl3/libSceLibreSsl3.hpp"
#include "prx/libSceLibreSsl/include/Error.hpp"
#include "prx/libc/libc.hpp"
#include <cstddef>
#include <cstring>
#include <limits>
#include <stdexcept>

namespace {

constexpr int Malloced = 1;
constexpr int ConstantTime = 4;
constexpr int MaxWords = std::numeric_limits<std::int32_t>::max() / 256;

static_assert(sizeof(LibreSsl3Bignum) == 24);
static_assert(offsetof(LibreSsl3Bignum, top) == 8);
static_assert(offsetof(LibreSsl3Bignum, capacity) == 12);
static_assert(offsetof(LibreSsl3Bignum, negative) == 16);
static_assert(offsetof(LibreSsl3Bignum, flags) == 20);

void Clear(void* pointer, std::size_t size) {
    auto* bytes = static_cast<volatile unsigned char*>(pointer);
    for (std::size_t index = 0; index < size; ++index) bytes[index] = 0;
}

}

extern "C" LibreSsl3Bignum* APS5_VABI BN_dup_nid_postfix(const LibreSsl3Bignum* source) {
    if (!source) return nullptr;
    if (source->top > 0 && source->top <= MaxWords && (!source->data || source->top > source->capacity))
        throw std::invalid_argument("BN_dup: invalid limb storage");
    auto* copy = static_cast<LibreSsl3Bignum*>(calloc_nid_postfix(1, sizeof(LibreSsl3Bignum)));
    if (!copy) {
        LibreSslPutError_nid_no_patch(3, 0xfff, 65);
        return nullptr;
    }
    copy->flags = Malloced;
    if (source->top < 0 || source->top > MaxWords) {
        if (source->top > MaxWords) LibreSslPutError_nid_no_patch(3, 0xfff, 114);
        Clear(copy, sizeof(*copy));
        free_nid_postfix(copy);
        return nullptr;
    }
    if (source->top > 0) {
        copy->data = static_cast<std::uint64_t*>(calloc_nid_postfix(static_cast<std::size_t>(source->top), sizeof(*copy->data)));
        if (!copy->data) {
            LibreSslPutError_nid_no_patch(3, 0xfff, 65);
            Clear(copy, sizeof(*copy));
            free_nid_postfix(copy);
            return nullptr;
        }
        copy->capacity = source->top;
        std::memcpy(copy->data, source->data, static_cast<std::size_t>(source->top) * sizeof(*copy->data));
    }
    copy->top = source->top;
    copy->negative = source->negative;
    copy->flags |= source->flags & ConstantTime;
    return copy;
}
