#include "prx/libSceIcu/Digit.hpp"
#include <algorithm>
#include <array>
#include <cstdint>

namespace {

constexpr std::array<std::uint32_t, 77> DecimalZeroes{
    0x0030, 0x0660, 0x06f0, 0x07c0, 0x0966, 0x09e6, 0x0a66, 0x0ae6,
    0x0b66, 0x0be6, 0x0c66, 0x0ce6, 0x0d66, 0x0de6, 0x0e50, 0x0ed0,
    0x0f20, 0x1040, 0x1090, 0x17e0, 0x1810, 0x1946, 0x19d0, 0x1a80,
    0x1a90, 0x1b50, 0x1bb0, 0x1c40, 0x1c50, 0xa620, 0xa8d0, 0xa900,
    0xa9d0, 0xa9f0, 0xaa50, 0xabf0, 0xff10, 0x104a0, 0x10d30, 0x10d40,
    0x11066, 0x110f0, 0x11136, 0x111d0, 0x112f0, 0x11450, 0x114d0, 0x11650,
    0x116c0, 0x116d0, 0x116da, 0x11730, 0x118e0, 0x11950, 0x11bf0, 0x11c50,
    0x11d50, 0x11da0, 0x11de0, 0x11f50, 0x16130, 0x16a60, 0x16ac0, 0x16b50,
    0x16d70, 0x1ccf0, 0x1d7ce, 0x1d7d8, 0x1d7e2, 0x1d7ec, 0x1d7f6, 0x1e140,
    0x1e2f0, 0x1e4f0, 0x1e5f1, 0x1e950, 0x1fbf0
};

std::int32_t DecimalValue(std::int32_t character) {
    const auto codePoint = static_cast<std::uint32_t>(character);
    const auto next = std::upper_bound(DecimalZeroes.begin(), DecimalZeroes.end(), codePoint);
    if (next == DecimalZeroes.begin()) return -1;
    const auto value = codePoint - *(next - 1);
    return value < 10 ? static_cast<std::int32_t>(value) : -1;
}

} // namespace

extern "C" {

std::int32_t APS5_VABI u_charDigitValue_nid_postfix(std::int32_t character) {
    return DecimalValue(character);
}

std::int32_t APS5_VABI u_digit_nid_postfix(std::int32_t character, std::int8_t radix) {
    if (radix < 2 || radix > 36) return -1;
    std::int32_t value = DecimalValue(character);
    if (value < 0) {
        if (character >= 'a' && character <= 'z') value = character - 'a' + 10;
        else if (character >= 'A' && character <= 'Z') value = character - 'A' + 10;
        else if (character >= 0xff41 && character <= 0xff5a) value = character - 0xff41 + 10;
        else if (character >= 0xff21 && character <= 0xff3a) value = character - 0xff21 + 10;
    }
    return value < radix ? value : -1;
}

std::int8_t APS5_VABI u_isdigit_nid_postfix(std::int32_t character) {
    return DecimalValue(character) >= 0;
}

std::int8_t APS5_VABI u_isxdigit_nid_postfix(std::int32_t character) {
    return (character >= 'A' && character <= 'F') || (character >= 'a' && character <= 'f') ||
        (character >= 0xff21 && character <= 0xff26) || (character >= 0xff41 && character <= 0xff46) ||
        DecimalValue(character) >= 0;
}

}
