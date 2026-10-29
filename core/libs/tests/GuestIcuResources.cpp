#include "prx/libSceIcu/libSceIcu.hpp"
#include <algorithm>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <stdexcept>

namespace {

constexpr std::uint32_t Missing = 0xffffffff;

void Require(bool condition, const char* message) {
    if (condition) return;
    std::fprintf(stderr, "ICU resources: %s\n", message);
    std::abort();
}

template<class TCall>
bool Rejects(TCall call) {
    try {
        call();
    } catch (const std::invalid_argument&) {
        return true;
    }
    return false;
}

struct Bundle {
    std::array<std::int32_t, 512> words{};
    std::array<std::uint16_t, 512> units{};
    std::array<std::uint16_t, 64> poolStrings{};
    std::array<char, 128> poolKeys{};
    Icu::ResourceData data{};

    Bundle() {
        data.root = words.data();
        data.units = units.data();
        data.poolKeys = poolKeys.data();
        data.localKeyLimit = 1024;
        data.poolStrings = poolStrings.data();
    }

    template<class TValue>
    void Put(std::size_t offset, TValue value) {
        std::memcpy(reinterpret_cast<char*>(words.data()) + offset, &value, sizeof value);
    }

    const char* Key(std::size_t offset, const char* value) {
        auto pointer = reinterpret_cast<char*>(words.data()) + offset;
        std::strcpy(pointer, value);
        return pointer;
    }
};

Icu::ResourceDataInfo Info(std::uint8_t major, std::uint8_t minor = 0) {
    Icu::ResourceDataInfo info{};
    info.size = sizeof info;
    info.sizeofUChar = 2;
    std::memcpy(info.dataFormat, "ResB", 4);
    info.formatVersion[0] = major;
    info.formatVersion[1] = minor;
    return info;
}

void Reset(Icu::ResourceData& data) {
    std::memset(&data, 0xa5, sizeof data);
}

bool IsZero(const Icu::ResourceData& data) {
    const auto bytes = reinterpret_cast<const unsigned char*>(&data);
    return std::all_of(bytes, bytes + sizeof data, [](auto value) { return value == 0; });
}

void ReadBundles() {
    Bundle bundle;
    bundle.words[0] = 0x20000040;
    bundle.words[1] = 8;
    bundle.words[2] = 16;
    bundle.words[4] = 256;
    bundle.words[7] = 32;
    Icu::ResourceData data;
    for (const auto version : {std::array<std::uint8_t, 2>{1, 0}, {1, 1}, {2, 0}, {3, 0}, {3, 255}}) {
        const auto info = Info(version[0], version[1]);
        const bool legacy = version[0] == 1 && version[1] == 0;
        for (const auto rootType : {2u, 4u, 5u}) {
            bundle.Put(0, (rootType << 28) | 64);
            for (const auto length : {-1, 1024, 2048}) {
                Reset(data);
                std::int32_t error = -128;
                res_read_nid_postfix(&data, &info, bundle.words.data(), length, &error);
                Require(error == -128, "successful read preserves a warning status");
                Require(data.root == bundle.words.data() && data.rootResource == ((rootType << 28) | 64), "read retains the root and resource");
                Require(data.localKeyLimit == (legacy ? 65536 : 64), "key limit follows the format version");
                Require(data.units && (legacy ? *data.units == 0 : data.units == reinterpret_cast<const std::uint16_t*>(bundle.words.data() + 16)), "16-bit section selection");
                Require(data.data == nullptr && data.poolKeys == nullptr && data.poolStrings == nullptr, "read does not load or invent pool storage");
                Require(data.poolStringLimit == 0 && data.poolString16Limit == 0 && data.noFallback == 0 && data.isPoolBundle == 0 && data.usesPoolBundle == 0 && data.useNativeStrcmp == 1, "read initializes flags and limits");
            }
        }
    }
    auto info = Info(3);
    Reset(data);
    std::int32_t error = 7;
    res_read_nid_postfix(&data, nullptr, nullptr, 0, &error);
    Require(IsZero(data) && error == 7, "preexisting failure clears output without reading input");
    for (int field = 0; field < 8; ++field) {
        auto bad = info;
        if (field == 0) bad.size = 19;
        if (field == 1) bad.isBigEndian = 1;
        if (field == 2) bad.charsetFamily = 1;
        if (field == 3) bad.sizeofUChar = 4;
        if (field == 4) bad.dataFormat[0] = 'X';
        if (field == 5) bad.dataFormat[3] = 0;
        if (field == 6) bad.formatVersion[0] = 0;
        if (field == 7) bad.formatVersion[0] = 4;
        Reset(data);
        error = 0;
        res_read_nid_postfix(&data, &bad, nullptr, 0, &error);
        Require(error == 3 && IsZero(data), "incompatible header rejects before touching the body");
    }
    for (std::uint32_t type = 0; type < 16; ++type) {
        if (type == 2 || type == 4 || type == 5) continue;
        bundle.Put(0, type << 28);
        error = 0;
        res_read_nid_postfix(&data, &info, bundle.words.data(), 2048, &error);
        Require(error == 3 && data.root == bundle.words.data() && data.rootResource == type << 28 && data.useNativeStrcmp == 0, "non-table roots preserve initialized fields on failure");
    }
    bundle.words[0] = 0x20000040;
    for (const auto length : {0, 3, 4, 20, 23, 24, 35, 1023}) {
        error = 0;
        res_read_nid_postfix(&data, &info, bundle.words.data(), length, &error);
        Require(error == 3 && data.root == bundle.words.data() && data.units && *data.units == 0 && data.localKeyLimit == 0, "truncated body or index/bundle limits reject without completing initialization");
    }
    const auto legacy = Info(1);
    error = 0;
    res_read_nid_postfix(&data, &legacy, bundle.words.data(), 4, &error);
    Require(error == 0 && data.localKeyLimit == 65536, "legacy format only needs the root word");
    bundle.words[1] = 4;
    error = 0;
    res_read_nid_postfix(&data, &info, bundle.words.data(), -1, &error);
    Require(error == 3, "unknown length still requires five indexes");
    bundle.words[1] = 5;
    bundle.words[2] = 6;
    bundle.words[4] = 6;
    error = 0;
    res_read_nid_postfix(&data, &info, bundle.words.data(), 24, &error);
    Require(error == 0 && data.localKeyLimit == 0 && *data.units == 0, "minimal indexes omit keys, attributes and 16-bit data");
    bundle.words[1] = 7;
    bundle.words[2] = 8;
    bundle.words[4] = 8;
    bundle.words[7] = 8;
    for (int flags : {2, 4, 6}) {
        bundle.words[6] = flags;
        error = 0;
        res_read_nid_postfix(&data, &info, bundle.words.data(), 32, &error);
        Require(error == 3 && data.isPoolBundle == ((flags & 2) != 0) && data.usesPoolBundle == ((flags & 4) != 0), "pool flags require a checksum index");
    }
    bundle.Put(4, std::uint32_t{0x12345608});
    bundle.words[2] = 9;
    bundle.words[4] = 9;
    bundle.Put(24, std::uint32_t{0x5678a007});
    bundle.words[7] = 9;
    for (const auto major : {2, 3}) {
        info = Info(major);
        error = 0;
        res_read_nid_postfix(&data, &info, bundle.words.data(), 36, &error);
        Require(error == 0 && data.noFallback == 1 && data.isPoolBundle == 1 && data.usesPoolBundle == 1, "all resource attributes are preserved");
        Require(data.poolStringLimit == (major == 3 ? 0x0a123456 : 0x0a000000) && data.poolString16Limit == 0x5678, "pool indexes combine version and attribute bits");
    }
    bundle.words[4] = -1;
    error = 0;
    Require(Rejects([&] { res_read_nid_postfix(&data, &info, bundle.words.data(), 36, &error); }), "negative shifted bundle length throws");
    bundle.words[4] = INT32_MAX;
    error = 0;
    Require(Rejects([&] { res_read_nid_postfix(&data, &info, bundle.words.data(), 36, &error); }), "overflowing shifted bundle length throws");
    error = 0;
    Require(Rejects([&] { res_read_nid_postfix(nullptr, &info, bundle.words.data(), 36, &error); }), "null read output throws");
    Require(Rejects([&] { res_read_nid_postfix(&data, &info, bundle.words.data(), 36, nullptr); }), "null status throws");
    Require(Rejects([&] { res_read_nid_postfix(&data, nullptr, bundle.words.data(), 36, &error); }), "null info throws");
    Require(Rejects([&] { res_read_nid_postfix(&data, &info, nullptr, 36, &error); }), "null body throws");
}

void ReadAndLookup() {
    Bundle bundle;
    bundle.words[0] = 0x20000040;
    bundle.words[1] = 8;
    bundle.words[2] = 32;
    bundle.words[4] = 128;
    bundle.words[7] = 64;
    bundle.Key(64, "alpha");
    bundle.Key(80, "binary");
    bundle.Key(96, "vector");
    bundle.Put(148, char16_t{'A'});
    bundle.Put(150, char16_t{'B'});
    bundle.Put(256, std::uint16_t{3});
    bundle.Put(258, std::uint16_t{64});
    bundle.Put(260, std::uint16_t{80});
    bundle.Put(262, std::uint16_t{96});
    bundle.Put(264, std::uint32_t{0x6000000a});
    bundle.Put(268, std::uint32_t{0x10000050});
    bundle.Put(272, std::uint32_t{0xe0000060});
    bundle.words[80] = 2;
    bundle.Put(324, std::uint16_t{0x42ff});
    bundle.words[96] = 2;
    bundle.words[97] = -3;
    bundle.words[98] = 4;
    const auto info = Info(3);
    Icu::ResourceData data{};
    std::int32_t error = 0;
    res_read_nid_postfix(&data, &info, bundle.words.data(), 512, &error);
    Require(error == 0 && res_countArrayItems_nid_postfix(&data, data.rootResource) == 3, "read and enumerate a complete indexed bundle");
    std::int32_t length = -1;
    const auto string = res_getStringNoTrace_nid_postfix(&data, res_getResource_nid_postfix(&data, "alpha"), &length);
    Require(string && length == 2 && string[0] == 'A' && string[1] == 'B', "read, lookup and decode a compact string");
    const auto binary = res_getBinaryNoTrace_nid_postfix(&data, res_getResource_nid_postfix(&data, "binary"), &length);
    Require(binary && length == 2 && binary[0] == 0xff && binary[1] == 0x42, "read, lookup and return binary bytes");
    const auto vector = res_getIntVectorNoTrace_nid_postfix(&data, res_getResource_nid_postfix(&data, "vector"), &length);
    Require(vector && length == 2 && vector[0] == -3 && vector[1] == 4, "read, lookup and return integer values");
}

void Scalars() {
    constexpr std::array<int, 16> publicTypes{0, 1, 2, 3, 2, 2, 0, 7, 8, 8, -1, -1, -1, -1, 14, -1};
    Bundle bundle;
    for (std::uint32_t type = 0; type < 16; ++type) {
        for (const auto offset : {0u, 1u, 0x0fffffffu})
            Require(res_getPublicType_nid_postfix((type << 28) | offset) == publicTypes[type], "public type ignores offsets and covers every internal type");
        std::int32_t length = 99;
        const auto resource = type << 28;
        if (type != 0 && type != 6) Require(res_getStringNoTrace_nid_postfix(nullptr, resource, &length) == nullptr && length == 0, "string mismatch clears length");
        if (type != 3) Require(res_getAlias_nid_postfix(nullptr, resource, &length) == nullptr && length == 0, "alias mismatch clears length");
        if (type != 1) Require(res_getBinaryNoTrace_nid_postfix(nullptr, resource, &length) == nullptr && length == 0, "binary mismatch clears length");
        if (type != 14) Require(res_getIntVectorNoTrace_nid_postfix(nullptr, resource, &length) == nullptr && length == 0, "vector mismatch clears length");
        const auto scalar = type == 0 || type == 1 || type == 3 || type == 6 || type == 7 || type == 14;
        Require(res_countArrayItems_nid_postfix(&bundle.data, resource) == (scalar ? 1 : 0), "empty scalars count as one while containers and invalid types count zero");
    }
    std::int32_t length = 99;
    Require(*res_getStringNoTrace_nid_postfix(nullptr, 0, &length) == 0 && length == 0, "empty string requires no resource data");
    Require(*res_getAlias_nid_postfix(nullptr, 0x30000000, &length) == 0 && length == 0, "empty alias requires no resource data");
    Require(res_getBinaryNoTrace_nid_postfix(nullptr, 0x10000000, &length) != nullptr && length == 0, "empty binary has a nonnull pointer");
    Require(res_getIntVectorNoTrace_nid_postfix(nullptr, 0xe0000000, &length) != nullptr && length == 0, "empty vector has a nonnull pointer");
    bundle.words[12] = 3;
    bundle.Put(52, char16_t{'A'});
    bundle.Put(54, char16_t{0});
    bundle.Put(56, char16_t{0xdfff});
    const auto saved = bundle.words;
    const auto string = res_getStringNoTrace_nid_postfix(&bundle.data, 12, &length);
    Require(string == reinterpret_cast<const char16_t*>(bundle.words.data() + 13) && length == 3 && string[0] == 'A' && string[1] == 0 && string[2] == 0xdfff, "classic string preserves embedded NUL and surrogate units");
    Require(res_getAlias_nid_postfix(&bundle.data, 0x3000000c, &length) == string && length == 3, "alias returns UTF-16 payload");
    Require(res_getBinaryNoTrace_nid_postfix(&bundle.data, 0x1000000c, nullptr) == reinterpret_cast<const std::uint8_t*>(string), "binary returns its byte payload without optional length");
    Require(res_getIntVectorNoTrace_nid_postfix(&bundle.data, 0xe000000c, &length) == bundle.words.data() + 13 && length == 3, "vector returns its original word storage");
    Require(bundle.words == saved, "accessors preserve caller storage");
    bundle.words[12] = -7;
    Require(res_getStringNoTrace_nid_postfix(&bundle.data, 12, &length) == string && length == -7, "classic stored lengths are returned without invented validation");
    Require(Rejects([] { res_getStringNoTrace_nid_postfix(nullptr, 1, nullptr); }), "nonnull string resource requires data");
    Icu::ResourceData empty{};
    Require(Rejects([&] { res_getBinaryNoTrace_nid_postfix(&empty, 0x10000001, nullptr); }), "binary resource requires root storage");
}

void CompactStrings() {
    Bundle bundle;
    std::int32_t length = -1;
    bundle.units[10] = 'A';
    bundle.units[11] = 0xd800;
    bundle.units[12] = 0xdc00;
    Require(res_getStringNoTrace_nid_postfix(&bundle.data, 0x6000000a, &length) == reinterpret_cast<const char16_t*>(bundle.units.data() + 10) && length == 3, "implicit compact length scans UTF-16 units");
    struct Case {
        std::uint16_t first;
        std::uint16_t second;
        std::uint16_t third;
        int skip;
        int length;
    };
    constexpr Case cases[] = {
        {0xdc00, 0, 0, 1, 0}, {0xdc03, 0, 0, 1, 3}, {0xdfee, 0, 0, 1, 1006},
        {0xdfef, 3, 0, 2, 3}, {0xdff0, 7, 0, 2, 65543}, {0xdffe, 0xffff, 0, 2, 0xfffff},
        {0xdfff, 0, 4, 3, 4}, {0xdfff, 0x7fff, 0xffff, 3, INT32_MAX}
    };
    for (const auto& test : cases) {
        bundle.units[20] = test.first;
        bundle.units[21] = test.second;
        bundle.units[22] = test.third;
        Require(res_getStringNoTrace_nid_postfix(&bundle.data, 0x60000014, &length) == reinterpret_cast<const char16_t*>(bundle.units.data() + 20 + test.skip) && length == test.length, "compact length prefixes select the exact payload and length");
    }
    bundle.data.poolStringLimit = 32;
    bundle.poolStrings[2] = 'P';
    bundle.poolStrings[3] = 0;
    Require(res_getStringNoTrace_nid_postfix(&bundle.data, 0x60000002, &length) == reinterpret_cast<const char16_t*>(bundle.poolStrings.data() + 2) && length == 1, "compact strings select pool storage below the limit");
    Require(res_getStringNoTrace_nid_postfix(&bundle.data, 0x6000002a, nullptr) == reinterpret_cast<const char16_t*>(bundle.units.data() + 10), "local strings subtract the pool limit");
    Require(res_getStringNoTrace_nid_postfix(&bundle.data, 0x60000020, &length) == reinterpret_cast<const char16_t*>(bundle.units.data()) && length == 0, "the pool boundary selects local unit zero");
    bundle.data.poolStrings = nullptr;
    Require(Rejects([&] { res_getStringNoTrace_nid_postfix(&bundle.data, 0x60000002, &length); }), "missing selected pool storage throws");
    bundle.data.poolStringLimit = 0;
    bundle.units[20] = 0xdfff;
    bundle.units[21] = 0x8000;
    Require(Rejects([&] { res_getStringNoTrace_nid_postfix(&bundle.data, 0x60000014, &length); }), "compact lengths exceeding signed range throw");
}

void Arrays() {
    Bundle bundle;
    bundle.words[40] = 3;
    constexpr std::array<std::uint32_t, 3> items{0x0000000c, 0x70000007, 0xffffffff};
    for (int i = 0; i < 3; ++i) bundle.Put(164 + i * 4, items[i]);
    Require(res_countArrayItems_nid_postfix(&bundle.data, 0x80000028) == 3, "32-bit array length");
    for (int i = -2; i <= 4; ++i)
        Require(res_getArrayItem_nid_postfix(&bundle.data, 0x80000028, i) == (i >= 0 && i < 3 ? items[i] : Missing), "32-bit array values and bounds");
    bundle.words[40] = -1;
    Require(res_countArrayItems_nid_postfix(&bundle.data, 0x80000028) == -1 && res_getArrayItem_nid_postfix(&bundle.data, 0x80000028, 0) == Missing, "negative stored count does not expose an item");
    bundle.units[80] = 4;
    bundle.units[81] = 0;
    bundle.units[82] = 1;
    bundle.units[83] = 2;
    bundle.units[84] = 0xffff;
    bundle.data.poolString16Limit = 2;
    bundle.data.poolStringLimit = 1000;
    constexpr std::array<std::uint32_t, 4> expanded{0x60000000, 0x60000001, 0x600003e8, 0x600103e5};
    Require(res_countArrayItems_nid_postfix(&bundle.data, 0x90000050) == 4, "16-bit array length");
    for (int i = -1; i <= 4; ++i)
        Require(res_getArrayItem_nid_postfix(&bundle.data, 0x90000050, i) == (i >= 0 && i < 4 ? expanded[i] : Missing), "16-bit resources expand across the pool boundary");
    Require(res_getArrayItem_nid_postfix(nullptr, 0x80000000, 0) == Missing && res_getArrayItem_nid_postfix(nullptr, 0x90000001, -1) == Missing && res_getArrayItem_nid_postfix(nullptr, 0x70000001, 0) == Missing, "empty, negative-index and wrong-type array paths require no data");
    bundle.data.poolStringLimit = INT32_MAX;
    Require(Rejects([&] { res_getArrayItem_nid_postfix(&bundle.data, 0x90000050, 3); }), "overflowing compact resource expansion throws");
}

void Tables() {
    constexpr std::array<const char*, 6> names{"", "a", "b", "key", "prefix", "z"};
    for (const auto type : {2u, 4u, 5u}) {
        for (int count = 0; count <= 6; ++count) {
            Bundle bundle;
            bundle.data.poolStringLimit = 1000;
            bundle.data.poolString16Limit = 2;
            const auto resource = (type << 28) | (type == 5 ? 128 : 64);
            bundle.data.rootResource = resource;
            std::array<const char*, 6> pointers{};
            if (type == 5) bundle.units[128] = count;
            else if (type == 4) bundle.words[64] = count;
            else bundle.Put(256, static_cast<std::uint16_t>(count));
            for (int i = 0; i < count; ++i) {
                const bool pool = (i & 1) != 0;
                const auto keyOffset = pool ? i * 16 : 512 + i * 16;
                if (pool) {
                    pointers[i] = bundle.poolKeys.data() + keyOffset;
                    std::strcpy(bundle.poolKeys.data() + keyOffset, names[i]);
                } else pointers[i] = bundle.Key(keyOffset, names[i]);
                const auto narrowKey = static_cast<std::uint16_t>(pool ? 1024 + keyOffset : keyOffset);
                if (type == 5) {
                    bundle.units[129 + i] = narrowKey;
                    bundle.units[129 + count + i] = i + 2;
                } else if (type == 4) {
                    bundle.Put(260 + i * 4, static_cast<std::uint32_t>(keyOffset) | (pool ? 0x80000000 : 0));
                    bundle.Put(260 + (count + i) * 4, 0x70000000u + i);
                } else {
                    bundle.Put(258 + i * 2, narrowKey);
                    bundle.Put(256 + ((count + 2) & ~1) * 2 + i * 4, 0x70000000u + i);
                }
            }
            Require(res_countArrayItems_nid_postfix(&bundle.data, resource) == count, "all table layouts expose their count");
            for (int i = -1; i <= count; ++i) {
                const char* key = "unchanged";
                const auto oldKey = key;
                const auto expected = i >= 0 && i < count ? (type == 5 ? 0x600003e8u : 0x70000000u) + i : Missing;
                Require(res_getTableItemByIndex_nid_postfix(&bundle.data, resource, i, &key) == expected, "table indexing covers both ends and alignment");
                Require(key == (i >= 0 && i < count ? pointers[i] : oldKey), "table index returns the canonical key only on success");
                Require(res_getTableItemByIndex_nid_postfix(&bundle.data, resource, i, nullptr) == expected, "table index key output is optional");
            }
            for (const auto native : {0, 1}) {
                bundle.data.useNativeStrcmp = native;
                for (int i = 0; i < 6; ++i) {
                    std::array<char, 16> copy{};
                    std::strcpy(copy.data(), names[i]);
                    const char* key = copy.data();
                    std::int32_t index = 77;
                    const auto expected = i < count ? (type == 5 ? 0x600003e8u : 0x70000000u) + i : Missing;
                    Require(res_getTableItemByKey_nid_postfix(&bundle.data, resource, &index, &key) == expected, "table lookup finds local and pooled keys in ASCII order");
                    Require(index == (i < count ? i : -1) && key == (i < count ? pointers[i] : copy.data()), "lookup returns index and canonical key, preserving missing key");
                    Require(res_getResource_nid_postfix(&bundle.data, names[i]) == expected, "root lookup uses its table resource");
                }
                for (const auto missing : {"A", "aa", "c", "keys", "zz"}) {
                    const char* key = missing;
                    std::int32_t index = 77;
                    Require(res_getTableItemByKey_nid_postfix(&bundle.data, resource, &index, &key) == Missing && index == -1 && key == missing, "missing keys preserve their input pointer");
                }
            }
        }
    }
    const char* key = "key";
    std::int32_t index = 77;
    Require(res_getTableItemByKey_nid_postfix(nullptr, 0x20000000, &index, &key) == Missing && index == 77, "empty 32-bit offset preserves the index");
    Require(res_getTableItemByKey_nid_postfix(nullptr, 0x40000000, &index, &key) == Missing && index == 77, "empty wide-key table preserves the index");
    Require(res_getTableItemByKey_nid_postfix(nullptr, 0x70000000, &index, &key) == Missing && index == 77, "wrong table type preserves the index");
    Require(res_getTableItemByKey_nid_postfix(nullptr, 0x50000000, nullptr, nullptr) == Missing, "null lookup key is an immediate miss");
    key = nullptr;
    Require(res_getTableItemByKey_nid_postfix(nullptr, 0x20000040, nullptr, &key) == Missing, "null key string is an immediate miss");
    Bundle bundle;
    key = "key";
    Require(res_getTableItemByKey_nid_postfix(&bundle.data, 0x50000000, &index, &key) == Missing && index == -1, "empty compact table still updates index");
    bundle.words[64] = -1;
    index = 77;
    Require(res_getTableItemByKey_nid_postfix(&bundle.data, 0x40000040, &index, &key) == Missing && index == -1, "negative wide table count is a search miss");
    Require(Rejects([&] { res_getTableItemByKey_nid_postfix(&bundle.data, 0x50000000, nullptr, &key); }), "searched table requires an index output");
    Require(Rejects([] { res_getResource_nid_postfix(nullptr, nullptr); }), "root lookup requires resource data even for a null key");
}

}

int main() {
    ReadBundles();
    ReadAndLookup();
    Scalars();
    CompactStrings();
    Arrays();
    Tables();
}
