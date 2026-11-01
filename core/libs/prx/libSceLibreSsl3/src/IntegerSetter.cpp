#include "prx/libSceLibreSsl3/libSceLibreSsl3.hpp"
#include "prx/libc/libc.hpp"
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <stdexcept>

static_assert(sizeof(Asn1String) == 24);
static_assert(offsetof(Asn1String, data) == 8);
static_assert(offsetof(Asn1String, flags) == 16);

extern "C" int APS5_VABI ASN1_INTEGER_set_nid_postfix(Asn1String* integer, std::int64_t value) {
    if (!integer || (integer->data && integer->length < 0))
        throw std::invalid_argument("ASN1_INTEGER_set: invalid integer storage");
    if (integer->data) {
        auto* previous = static_cast<volatile unsigned char*>(integer->data);
        for (std::int32_t index = 0; index < integer->length; ++index)
            previous[index] = 0;
        free_nid_postfix(integer->data);
    }
    *integer = {0, value < 0 ? 0x102 : 2, nullptr, 0};
    std::uint64_t magnitude = static_cast<std::uint64_t>(value);
    if (value < 0) magnitude = std::uint64_t{0} - magnitude;
    std::array<unsigned char, sizeof(magnitude)> bytes;
    std::size_t first = bytes.size();
    do {
        bytes[--first] = static_cast<unsigned char>(magnitude);
        magnitude >>= 8;
    } while (magnitude != 0);
    auto* data = static_cast<unsigned char*>(malloc_nid_postfix(bytes.size()));
    if (!data) return 0;
    const auto length = bytes.size() - first;
    std::memcpy(data, bytes.data() + first, length);
    integer->data = data;
    integer->length = static_cast<std::int32_t>(length);
    return 1;
}
