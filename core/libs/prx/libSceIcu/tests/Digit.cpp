#include "prx/libSceIcu/libSceIcu.hpp"
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <limits>
#include <source_location>

namespace {

void Require(bool condition, std::source_location location = std::source_location::current()) {
    if (condition) return;
    std::fprintf(stderr, "ICU digit check failed at line %u\n", location.line());
    std::abort();
}

void Radices(std::int32_t character, std::int32_t value) {
    for (int radix = -128; radix <= 127; ++radix) {
        const auto expected = radix >= 2 && radix <= 36 && value < radix ? value : -1;
        Require(u_digit_nid_postfix(character, static_cast<std::int8_t>(radix)) == expected);
    }
}

void Characters() {
    for (const auto zero : {0x30, 0x660, 0x6f0, 0x966, 0xff10, 0x104a0, 0x11de0,
                           0x16130, 0x1ccf0, 0x1d7ce, 0x1d7d8, 0x1d7e2, 0x1d7ec, 0x1d7f6, 0x1e5f1, 0x1e950}) {
        for (int value = 0; value <= 9; ++value) {
            Require(u_charDigitValue_nid_postfix(zero + value) == value);
            Require(u_isdigit_nid_postfix(zero + value) == 1);
            Require(u_isxdigit_nid_postfix(zero + value) == 1);
            Radices(zero + value, value);
        }
    }
    for (const auto first : {0x41, 0x61, 0xff21, 0xff41}) {
        for (int index = 0; index < 26; ++index) {
            Require(u_charDigitValue_nid_postfix(first + index) == -1);
            Require(u_isdigit_nid_postfix(first + index) == 0);
            Require(u_isxdigit_nid_postfix(first + index) == (index < 6));
            Radices(first + index, index + 10);
        }
    }
    for (const std::int32_t character : {std::numeric_limits<std::int32_t>::min(), -1, 0, 0x2f, 0x3a,
                                       0x40, 0x5b, 0x60, 0x7b, 0xb2, 0xbc, 0x6ef, 0x6fa, 0x2165,
                                       0x2460, 0x3007, 0xd800, 0xdfff, 0xff20, 0xff3b, 0xff40,
                                       0xff5b, 0x11ddf, 0x11dea, 0x1d7cd, 0x1d800, 0x1e5f0, 0x1e5fb,
                                       0x10ffff, 0x110000, std::numeric_limits<std::int32_t>::max()}) {
        Require(u_charDigitValue_nid_postfix(character) == -1);
        Require(u_isdigit_nid_postfix(character) == 0);
        Require(u_isxdigit_nid_postfix(character) == 0);
        Radices(character, -1);
    }
}

void UnicodeData() {
    std::uint64_t hash = 14695981039346656037ull;
    std::array<int, 10> counts{};
    for (std::int32_t character = 0; character <= 0x10ffff; ++character) {
        const auto value = u_charDigitValue_nid_postfix(character);
        Require(value >= -1 && value <= 9);
        hash = (hash ^ static_cast<std::uint8_t>(value + 1)) * 1099511628211ull;
        if (value >= 0) ++counts[value];
        Require(u_isdigit_nid_postfix(character) == (value >= 0));
        Require(u_digit_nid_postfix(character, 10) == value);
        const bool hexLetter = character == 'A' || character == 'B' || character == 'C' ||
            character == 'D' || character == 'E' || character == 'F' ||
            character == 'a' || character == 'b' || character == 'c' ||
            character == 'd' || character == 'e' || character == 'f' ||
            (character >= 0xff21 && character <= 0xff26) || (character >= 0xff41 && character <= 0xff46);
        Require(u_isxdigit_nid_postfix(character) == (value >= 0 || hexLetter));
        if (value >= 0) Radices(character, value);
    }
    Require(hash == 0xb81d4baa0f8080b0ull);
    for (const int count : counts) Require(count == 77);
}

} // namespace

int main() {
    Characters();
    UnicodeData();
    std::puts("ICU Unicode 17 digit tests passed");
}
