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
    std::fprintf(stderr, "HMAC context check failed at line %u\n", location.line());
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

void FreshContexts() {
    const int before = allocationsAttempted;
    HMAC_CTX_free_nid_postfix(nullptr);
    Require(allocationsAttempted == before && allocations.empty());
    ERR_clear_error_nid_postfix();
    LibreSslPutError_nid_no_patch(13, 0xfff, 100);
    const auto error = ERR_peek_error_nid_postfix();
    failAfter = 0;
    Require(HMAC_CTX_new_nid_postfix() == nullptr);
    Require(ERR_get_error_nid_postfix() == error && ERR_get_error_nid_postfix() == 0);
    failAfter = -1;
    auto* first = HMAC_CTX_new_nid_postfix();
    auto* second = HMAC_CTX_new_nid_postfix();
    Require(first && second && first != second && allocations.size() == 2);
    for (const auto* context : {first, second}) {
        const auto* bytes = reinterpret_cast<const unsigned char*>(context);
        Require(std::all_of(bytes, bytes + sizeof(*context), [](auto byte) { return byte == 0; }));
    }
    std::array<unsigned char, 64> digest {};
    std::uint32_t length = 0;
    Require(HMAC_Update_nid_postfix(first, nullptr, 0) == 0);
    Require(HMAC_Final_nid_postfix(first, digest.data(), &length) == 0);
    HMAC_CTX_free_nid_postfix(first);
    Require(allocations.size() == 1 && allocations.contains(second));
    HMAC_CTX_free_nid_postfix(second);
    Require(allocations.empty());
}

void CheckDigest(HmacContext* context, const char* expected) {
    std::array<unsigned char, 64> digest {};
    std::uint32_t length = 0;
    Require(HMAC_Final_nid_postfix(context, digest.data(), &length) == 1);
    Require(length * 2 == std::strlen(expected));
    constexpr char hex[] = "0123456789abcdef";
    for (std::size_t i = 0; i < length; ++i) {
        Require(hex[digest[i] >> 4] == expected[i * 2]);
        Require(hex[digest[i] & 15] == expected[i * 2 + 1]);
    }
}

void Vectors() {
    struct Vector { const EvpMd* digest; const char* shortDigest; const char* longDigest; const char* emptyDigest; };
    const Vector vectors[] {
        {EVP_md5_nid_postfix(), "5ccec34ea9656392457fa1ac27f08fbc", "bfecaf4efff90a3a668f3922fec3762d", "74e6f7298a9c2d168935f58c001bad88"},
        {EVP_sha256_nid_postfix(), "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7", "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54", "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad"},
        {EVP_sha384_nid_postfix(), "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6", "4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c60c2ef6ab4030fe8296248df163f44952", "6c1f2ee938fad2e24bd91298474382ca218c75db3d83e114b3d4367776d14d3551289e75e8209cd4b792302840234adc"},
        {EVP_sha512_nid_postfix(), "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854", "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598", "b936cee86c9f87aa5d3c6f2e84cb5a4239a5fe50480a6ec66b70ab5b1f4ac6730c6c515421b327ec1d69402e53dfb49ad7381eb067b338fd7b0cb22247225d47"},
    };
    const auto* message = reinterpret_cast<const unsigned char*>("Hi There");
    const auto* longMessage = reinterpret_cast<const unsigned char*>("Test Using Larger Than Block-Size Key - Hash Key First");
    std::array<unsigned char, 20> shortKey;
    shortKey.fill(0x0b);
    std::array<unsigned char, 131> longKey;
    longKey.fill(0xaa);
    for (const auto& vector : vectors) {
        auto* context = HMAC_CTX_new_nid_postfix();
        Require(context != nullptr);
        Require(HMAC_Init_ex_nid_postfix(context, shortKey.data(), shortKey.size(), vector.digest, nullptr) == 1);
        Require(HMAC_Update_nid_postfix(context, message, 3) == 1);
        Require(HMAC_Update_nid_postfix(context, message + 3, 5) == 1);
        CheckDigest(context, vector.shortDigest);
        Require(HMAC_Init_ex_nid_postfix(context, nullptr, 0, nullptr, nullptr) == 1);
        Require(HMAC_Update_nid_postfix(context, message, 8) == 1);
        CheckDigest(context, vector.shortDigest);
        Require(HMAC_Init_ex_nid_postfix(context, longKey.data(), longKey.size(), vector.digest, nullptr) == 1);
        Require(HMAC_Update_nid_postfix(context, longMessage, std::strlen(reinterpret_cast<const char*>(longMessage))) == 1);
        CheckDigest(context, vector.longDigest);
        Require(HMAC_Init_ex_nid_postfix(context, shortKey.data(), 0, vector.digest, nullptr) == 1);
        Require(HMAC_Update_nid_postfix(context, nullptr, 0) == 1);
        CheckDigest(context, vector.emptyDigest);
        HMAC_CTX_cleanup_nid_postfix(context);
        Require(HMAC_Init_ex_nid_postfix(context, shortKey.data(), shortKey.size(), vector.digest, nullptr) == 1);
        HMAC_CTX_free_nid_postfix(context);
        Require(allocations.empty());
    }
}

void PartialFailures() {
    std::array<unsigned char, 131> key;
    key.fill(0xaa);
    for (const auto* md : {EVP_md5_nid_postfix(), EVP_sha256_nid_postfix(), EVP_sha384_nid_postfix(), EVP_sha512_nid_postfix()}) {
        for (const int keyLength : {20, 131}) {
            bool sawFailure = false;
            bool sawSuccess = false;
            for (int stage = 0; stage < 9; ++stage) {
                auto* context = HMAC_CTX_new_nid_postfix();
                Require(context != nullptr);
                failAfter = stage;
                const int initialized = HMAC_Init_ex_nid_postfix(context, key.data(), keyLength, md, nullptr);
                std::array<unsigned char, 64> digest {};
                std::uint32_t length = 0;
                int finalized = 0;
                if (initialized) {
                    Require(HMAC_Update_nid_postfix(context, key.data(), key.size()) == 1);
                    finalized = HMAC_Final_nid_postfix(context, digest.data(), &length);
                }
                sawFailure |= !initialized || !finalized;
                sawSuccess |= initialized && finalized;
                failAfter = -1;
                HMAC_CTX_free_nid_postfix(context);
                Require(allocations.empty());
            }
            Require(sawFailure && sawSuccess);
        }
    }
}

}

int main() {
    std::array<void*, 10> api {
        reinterpret_cast<void*>(Allocate_nid_no_patch), reinterpret_cast<void*>(Free_nid_no_patch), reinterpret_cast<void*>(Calloc_nid_no_patch),
        reinterpret_cast<void*>(UnexpectedReallocate_nid_no_patch), reinterpret_cast<void*>(UnexpectedAlign_nid_no_patch), reinterpret_cast<void*>(UnexpectedRealign_nid_no_patch),
        reinterpret_cast<void*>(UnexpectedPosixAlign_nid_no_patch)};
    ApplicationHeapRegister_nid_no_patch(api.data());
    FreshContexts();
    Vectors();
    PartialFailures();
    Require(allocations.empty());
    std::puts("libSceLibreSsl3 HMAC context lifetime tests passed");
}
