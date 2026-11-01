#include "prx/libSceLibreSsl3/libSceLibreSsl3.hpp"
#include "prx/libSceLibreSsl/libSceLibreSsl.hpp"
#include "prx/libc/libc.hpp"
#include "prx/libc/include/ApplicationHeap.hpp"
#include <algorithm>
#include <array>
#include <cstdint>
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
    std::fprintf(stderr, "ASN1_INTEGER_set check failed at line %u\n", location.line());
    std::abort();
}

std::unordered_map<void*, std::size_t> allocations;
void* pendingClear = nullptr;
std::size_t clearLength = 0;
bool failAllocation = false;
std::size_t freeCalls = 0;

void* APS5_VABI Allocate_nid_no_patch(std::size_t size) {
    Require(pendingClear == nullptr);
    if (failAllocation) {
        failAllocation = false;
        return nullptr;
    }
    auto* data = std::malloc(size);
    Require(data != nullptr);
    allocations.emplace(data, size);
    return data;
}

void APS5_VABI Free_nid_no_patch(void* data) {
    if (!data) return;
    const auto found = allocations.find(data);
    Require(found != allocations.end());
    if (data == pendingClear) {
        Require(clearLength <= found->second);
        const auto* bytes = static_cast<const unsigned char*>(data);
        Require(std::all_of(bytes, bytes + clearLength, [](unsigned char byte) { return byte == 0; }));
        pendingClear = nullptr;
    }
    allocations.erase(found);
    ++freeCalls;
    std::free(data);
}

void* APS5_VABI UnexpectedCalloc_nid_no_patch(std::size_t, std::size_t) { throw std::runtime_error("unexpected calloc"); }
void* APS5_VABI UnexpectedReallocate_nid_no_patch(void*, std::size_t) { throw std::runtime_error("unexpected realloc"); }
void* APS5_VABI UnexpectedAlign_nid_no_patch(std::size_t, std::size_t) { throw std::runtime_error("unexpected aligned allocation"); }
void* APS5_VABI UnexpectedRealign_nid_no_patch(void*, std::size_t, std::size_t) { throw std::runtime_error("unexpected aligned reallocation"); }
int APS5_VABI UnexpectedPosixAlign_nid_no_patch(void**, std::size_t, std::size_t) { throw std::runtime_error("unexpected posix_memalign"); }

void ExpectClear(const Asn1String& integer) {
    pendingClear = integer.data;
    clearLength = static_cast<std::size_t>(integer.length);
}

void Check(Asn1String& integer, std::int64_t value) {
    const auto previousFreeCalls = freeCalls;
    const bool hadData = integer.data != nullptr;
    ExpectClear(integer);
    Require(ASN1_INTEGER_set_nid_postfix(&integer, value) == 1);
    Require(pendingClear == nullptr && freeCalls == previousFreeCalls + hadData);
    Require(integer.data != nullptr && integer.length >= 1 && integer.length <= 8);
    Require(allocations.contains(integer.data));
    Require(integer.type == (value < 0 ? 0x102 : 2) && integer.flags == 0);
    Require(integer.length == 1 || integer.data[0] != 0);
    std::uint64_t decoded = 0;
    for (int index = 0; index < integer.length; ++index)
        decoded = decoded * 256 + integer.data[index];
    const auto expected = value < 0 ? std::uint64_t{0} - static_cast<std::uint64_t>(value) : static_cast<std::uint64_t>(value);
    Require(decoded == expected);
}

void Values() {
    Asn1String integer {};
    Check(integer, 0);
    Require(integer.length == 1 && integer.data[0] == 0);
    for (std::int64_t value = -1024; value <= 1024; ++value)
        Check(integer, value);
    for (unsigned bit = 1; bit < 63; ++bit) {
        const auto boundary = std::int64_t{1} << bit;
        for (const auto delta : {-1, 0, 1}) {
            Check(integer, boundary + delta);
            Check(integer, -(boundary + delta));
        }
    }
    Check(integer, std::numeric_limits<std::int64_t>::min());
    Require(integer.length == 8 && integer.data[0] == 0x80);
    Require(std::all_of(integer.data + 1, integer.data + 8, [](auto byte) { return byte == 0; }));
    Check(integer, std::numeric_limits<std::int64_t>::max());
    Require(integer.length == 8 && integer.data[0] == 0x7f);
    free_nid_postfix(integer.data);
}

void OwnershipAndFailure() {
    for (const auto flags : {std::int64_t{0}, std::int64_t{0x10}, std::int64_t{0x110}, std::int64_t{-1}}) {
        for (const auto value : {std::int64_t{0}, std::int64_t{123}, std::int64_t{-123}}) {
            auto* data = static_cast<unsigned char*>(malloc_nid_postfix(17));
            std::memset(data, 0xa5, 17);
            Asn1String integer {17, 4, data, flags};
            ExpectClear(integer);
            failAllocation = true;
            ERR_clear_error_nid_postfix();
            Require(ASN1_INTEGER_set_nid_postfix(&integer, value) == 0);
            Require(!failAllocation && pendingClear == nullptr && allocations.empty());
            Require(integer.data == nullptr && integer.length == 0 && integer.flags == 0);
            Require(integer.type == (value < 0 ? 0x102 : 2));
            Require(ERR_get_error_nid_postfix() == 0);
            Check(integer, value);
            free_nid_postfix(integer.data);
            integer = {-1, 4, nullptr, flags};
            Check(integer, value);
            free_nid_postfix(integer.data);
        }
    }
}

void InvalidStorage() {
    bool thrown = false;
    try { ASN1_INTEGER_set_nid_postfix(nullptr, 1); }
    catch (const std::invalid_argument&) { thrown = true; }
    Require(thrown);
    unsigned char byte = 0xa5;
    Asn1String integer {-1, 4, &byte, 0x10};
    thrown = false;
    try { ASN1_INTEGER_set_nid_postfix(&integer, 1); }
    catch (const std::invalid_argument&) { thrown = true; }
    Require(thrown && integer.length == -1 && integer.type == 4 && integer.flags == 0x10);
    Require(integer.data == &byte && byte == 0xa5);
}

}

int main() {
    std::array<void*, 10> api {
        reinterpret_cast<void*>(Allocate_nid_no_patch), reinterpret_cast<void*>(Free_nid_no_patch), reinterpret_cast<void*>(UnexpectedCalloc_nid_no_patch),
        reinterpret_cast<void*>(UnexpectedReallocate_nid_no_patch), reinterpret_cast<void*>(UnexpectedAlign_nid_no_patch), reinterpret_cast<void*>(UnexpectedRealign_nid_no_patch),
        reinterpret_cast<void*>(UnexpectedPosixAlign_nid_no_patch)};
    ApplicationHeapRegister_nid_no_patch(api.data());
    Values();
    OwnershipAndFailure();
    InvalidStorage();
    Require(allocations.empty());
    std::puts("libSceLibreSsl3 integer setter tests passed");
}
