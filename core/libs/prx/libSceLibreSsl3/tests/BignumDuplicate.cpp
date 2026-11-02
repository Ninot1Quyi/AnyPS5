#include "prx/libSceLibreSsl3/libSceLibreSsl3.hpp"
#include "prx/libSceLibreSsl/include/Error.hpp"
#include "prx/libc/libc.hpp"
#include "prx/libc/include/ApplicationHeap.hpp"
#include <algorithm>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <source_location>
#include <stdexcept>
#include <unordered_map>

namespace {

void Require(bool condition, std::source_location location = std::source_location::current()) {
    if (condition) return;
    std::fprintf(stderr, "BIGNUM duplication check failed at line %u\n", location.line());
    std::abort();
}

std::unordered_map<void*, std::size_t> allocations;
int failAfter = -1;
int allocationsAttempted = 0;
int frees = 0;

void* APS5_VABI Allocate_nid_no_patch(std::size_t size) {
    ++allocationsAttempted;
    if (failAfter == 0) return nullptr;
    if (failAfter > 0) --failAfter;
    auto* result = std::malloc(size);
    Require(result != nullptr);
    allocations.emplace(result, size);
    std::memset(result, 0xa5, size);
    return result;
}

void* APS5_VABI Calloc_nid_no_patch(std::size_t count, std::size_t size) {
    void* result = Allocate_nid_no_patch(count * size);
    if (result) std::memset(result, 0, count * size);
    return result;
}

void APS5_VABI Free_nid_no_patch(void* pointer) {
    if (!pointer) return;
    const auto found = allocations.find(pointer);
    Require(found != allocations.end());
    const auto* bytes = static_cast<const unsigned char*>(pointer);
    Require(std::all_of(bytes, bytes + found->second, [](auto byte) { return byte == 0; }));
    allocations.erase(found);
    ++frees;
    std::free(pointer);
}

void* APS5_VABI UnexpectedReallocate_nid_no_patch(void*, std::size_t) { throw std::runtime_error("unexpected realloc"); }
void* APS5_VABI UnexpectedAlign_nid_no_patch(std::size_t, std::size_t) { throw std::runtime_error("unexpected aligned allocation"); }
void* APS5_VABI UnexpectedRealign_nid_no_patch(void*, std::size_t, std::size_t) { throw std::runtime_error("unexpected aligned reallocation"); }
int APS5_VABI UnexpectedPosixAlign_nid_no_patch(void**, std::size_t, std::size_t) { throw std::runtime_error("unexpected posix_memalign"); }

void ReleaseCopy(LibreSsl3Bignum* copy) {
    if (copy->data) {
        std::memset(copy->data, 0, static_cast<std::size_t>(copy->capacity) * sizeof(*copy->data));
        free_nid_postfix(copy->data);
    }
    std::memset(copy, 0, sizeof(*copy));
    free_nid_postfix(copy);
}

void Copies() {
    std::array<std::uint64_t, 65> words;
    for (std::size_t index = 0; index < words.size(); ++index)
        words[index] = 0xfedcba9876543210ULL ^ (std::uint64_t{1} << (index % 64));
    for (const auto top : {0, 1, 2, 31, 32, 64, 65}) {
        for (const auto neg : {0, 1, -1}) {
            for (int flags = 0; flags < 16; ++flags) {
                LibreSsl3Bignum source {words.data(), top, 65, neg, flags};
                const auto before = source;
                auto* copy = BN_dup_nid_postfix(&source);
                Require(copy && copy != &source && copy->top == top && copy->capacity == top);
                Require(copy->negative == neg && copy->flags == (1 | (flags & 4)));
                Require(std::memcmp(&source, &before, sizeof(source)) == 0);
                if (top == 0) Require(copy->data == nullptr);
                else {
                    Require(copy->data && copy->data != source.data);
                    Require(std::equal(copy->data, copy->data + top, words.begin()));
                    const auto original = words[0];
                    copy->data[0] ^= 1;
                    Require(words[0] == original);
                }
                const int previousFrees = frees;
                ReleaseCopy(copy);
                Require(frees == previousFrees + 1 + (top != 0));
                Require(allocations.empty());
            }
        }
    }
    LibreSsl3Bignum zero {};
    auto* copy = BN_dup_nid_postfix(&zero);
    Require(copy && copy->data == nullptr && copy->top == 0 && copy->capacity == 0 && copy->negative == 0 && copy->flags == 1);
    ReleaseCopy(copy);
}

void Failures() {
    std::uint64_t word = 0x123456789abcdef0ULL;
    LibreSsl3Bignum source {&word, 1, 1, 1, 6};
    const auto before = source;
    for (int stage = 0; stage < 2; ++stage) {
        failAfter = stage;
        ERR_clear_error_nid_postfix();
        Require(BN_dup_nid_postfix(&source) == nullptr);
        Require(ERR_get_error_nid_postfix() == 0x03fff041 && ERR_get_error_nid_postfix() == 0);
        Require(allocations.empty() && std::memcmp(&source, &before, sizeof(source)) == 0);
        Require(word == 0x123456789abcdef0ULL);
    }
    failAfter = -1;
    for (const int top : {-1, std::numeric_limits<std::int32_t>::max() / 256 + 1}) {
        source.top = top;
        ERR_clear_error_nid_postfix();
        Require(BN_dup_nid_postfix(&source) == nullptr);
        Require(ERR_get_error_nid_postfix() == (top < 0 ? 0 : 0x03fff072));
        Require(ERR_get_error_nid_postfix() == 0 && allocations.empty());
    }
    ERR_clear_error_nid_postfix();
    LibreSslPutError_nid_no_patch(13, 0xfff, 100);
    const auto error = ERR_peek_error_nid_postfix();
    const int attempted = allocationsAttempted;
    Require(BN_dup_nid_postfix(nullptr) == nullptr);
    Require(allocationsAttempted == attempted && ERR_get_error_nid_postfix() == error);
}

void InvalidStorage() {
    std::uint64_t word = 42;
    for (auto source : {LibreSsl3Bignum{nullptr, 1, 1, 0, 0}, LibreSsl3Bignum{nullptr, 1, 0, 0, 0},
                        LibreSsl3Bignum{&word, 1, 0, 0, 0}, LibreSsl3Bignum{&word, 1, -1, 0, 0}}) {
        const auto before = source;
        const int attempted = allocationsAttempted;
        bool thrown = false;
        try { BN_dup_nid_postfix(&source); }
        catch (const std::invalid_argument&) { thrown = true; }
        Require(thrown && std::memcmp(&source, &before, sizeof(source)) == 0);
        Require(allocationsAttempted == attempted && word == 42);
    }
}

}

int main() {
    std::array<void*, 10> api {
        reinterpret_cast<void*>(Allocate_nid_no_patch), reinterpret_cast<void*>(Free_nid_no_patch), reinterpret_cast<void*>(Calloc_nid_no_patch),
        reinterpret_cast<void*>(UnexpectedReallocate_nid_no_patch), reinterpret_cast<void*>(UnexpectedAlign_nid_no_patch), reinterpret_cast<void*>(UnexpectedRealign_nid_no_patch),
        reinterpret_cast<void*>(UnexpectedPosixAlign_nid_no_patch)};
    ApplicationHeapRegister_nid_no_patch(api.data());
    Copies();
    Failures();
    InvalidStorage();
    Require(allocations.empty());
    std::puts("libSceLibreSsl3 BIGNUM duplication tests passed");
}
