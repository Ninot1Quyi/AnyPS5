#include "prx/libSceIcu/Resources.hpp"
#include "prx/libc/include/General.hpp"
#include <array>
#include <cstring>
#include <limits>

namespace {

constexpr std::uint32_t Missing = 0xffffffff;
constexpr std::array<std::uint32_t, 2> EmptyWords{};
constexpr std::uint16_t EmptyUnit = 0;
constexpr char16_t EmptyString = 0;

std::uint32_t Type(std::uint32_t resource) {
    return resource >> 28;
}

std::uint32_t Offset(std::uint32_t resource) {
    return resource & 0x0fffffff;
}

template<class TValue>
TValue Read(const void* pointer) {
    if (!pointer) APS5_INVALID_ARG_EX;
    TValue value;
    std::memcpy(&value, pointer, sizeof value);
    return value;
}

const Icu::ResourceData& Data(const Icu::ResourceData* data) {
    if (!data) APS5_INVALID_ARG_EX;
    return *data;
}

const std::uint8_t* Words(const Icu::ResourceData* data, std::ptrdiff_t offset) {
    const auto root = Data(data).root;
    if (!root) APS5_INVALID_ARG_EX;
    return reinterpret_cast<const std::uint8_t*>(root) + offset * 4;
}

const std::uint8_t* Units(const Icu::ResourceData* data, std::uint32_t offset) {
    const auto units = Data(data).units;
    if (!units) APS5_INVALID_ARG_EX;
    return reinterpret_cast<const std::uint8_t*>(units) + static_cast<std::ptrdiff_t>(offset) * 2;
}

void SetLength(std::int32_t* output, std::int32_t value) {
    if (output) *output = value;
}

const std::uint8_t* Payload(const Icu::ResourceData* data, std::uint32_t resource, std::uint32_t expected, std::int32_t* length) {
    if (Type(resource) != expected) {
        SetLength(length, 0);
        return nullptr;
    }
    const auto offset = Offset(resource);
    const auto start = offset == 0 ? reinterpret_cast<const std::uint8_t*>(EmptyWords.data()) : Words(data, offset);
    SetLength(length, Read<std::int32_t>(start));
    return start + 4;
}

std::uint32_t Expand(const Icu::ResourceData* data, std::uint16_t resource) {
    const auto& state = Data(data);
    std::int64_t offset = resource;
    if (offset >= state.poolString16Limit) offset += static_cast<std::int64_t>(state.poolStringLimit) - state.poolString16Limit;
    if (offset < 0 || offset > std::numeric_limits<std::int32_t>::max()) APS5_INVALID_ARG_EX;
    return 0x60000000 | static_cast<std::uint32_t>(offset);
}

struct Table {
    const std::uint8_t* keys = nullptr;
    const std::uint8_t* values = nullptr;
    std::int32_t length = 0;
    bool wideKeys = false;
    bool narrowValues = false;
    bool searchable = false;
};

Table GetTable(const Icu::ResourceData* data, std::uint32_t resource) {
    const auto type = Type(resource);
    const auto offset = Offset(resource);
    if (type == 5) {
        const auto start = Units(data, offset);
        const auto count = Read<std::uint16_t>(start);
        return {start + 2, start + 2 + count * 2, count, false, true, true};
    }
    if ((type != 2 && type != 4) || offset == 0) return {};
    const auto start = Words(data, offset);
    if (type == 4) {
        const auto count = Read<std::int32_t>(start);
        if (count < 0) return {start + 4, nullptr, count, true, false, true};
        return {start + 4, start + 4 + static_cast<std::ptrdiff_t>(count) * 4, count, true, false, true};
    }
    const auto count = Read<std::uint16_t>(start);
    const auto aligned = (static_cast<std::uint32_t>(count) + 2) & ~1u;
    return {start + 2, start + aligned * 2, count, false, false, true};
}

const char* Key(const Icu::ResourceData* data, const Table& table, std::int32_t index) {
    const auto& state = Data(data);
    if (table.wideKeys) {
        const auto offset = Read<std::int32_t>(table.keys + static_cast<std::ptrdiff_t>(index) * 4);
        if (offset >= 0) return reinterpret_cast<const char*>(Words(data, 0)) + offset;
        if (!state.poolKeys) APS5_INVALID_ARG_EX;
        return state.poolKeys + (static_cast<std::uint32_t>(offset) & 0x7fffffff);
    }
    const auto offset = Read<std::uint16_t>(table.keys + index * 2);
    if (offset < state.localKeyLimit) return reinterpret_cast<const char*>(Words(data, 0)) + offset;
    if (!state.poolKeys) APS5_INVALID_ARG_EX;
    return state.poolKeys + static_cast<std::ptrdiff_t>(offset) - state.localKeyLimit;
}

std::uint32_t Item(const Icu::ResourceData* data, const Table& table, std::int32_t index) {
    if (table.narrowValues) return Expand(data, Read<std::uint16_t>(table.values + index * 2));
    return Read<std::uint32_t>(table.values + static_cast<std::ptrdiff_t>(index) * 4);
}

int Compare(const char* left, const char* right) {
    if (!left || !right) APS5_INVALID_ARG_EX;
    for (;;) {
        const auto a = static_cast<unsigned char>(*left++);
        const auto b = static_cast<unsigned char>(*right++);
        if (a != b) return a < b ? -1 : 1;
        if (a == 0) return 0;
    }
}

std::int32_t ByteLength(std::int32_t words) {
    if (words < 0 || words > std::numeric_limits<std::int32_t>::max() / 4) APS5_INVALID_ARG_EX;
    return words * 4;
}

}

extern "C" {

void APS5_VABI res_read_nid_postfix(Icu::ResourceData* data, const Icu::ResourceDataInfo* info, const void* bytes, std::int32_t length, std::int32_t* error) {
    if (!data) APS5_INVALID_ARG_EX;
    std::memset(data, 0, sizeof *data);
    if (!error) APS5_INVALID_ARG_EX;
    if (*error > 0) return;
    if (!info) APS5_INVALID_ARG_EX;
    if (info->size < 20 || info->isBigEndian != 0 || info->charsetFamily != 0 || info->sizeofUChar != 2 ||
        std::memcmp(info->dataFormat, "ResB", 4) != 0 || info->formatVersion[0] < 1 || info->formatVersion[0] > 3) {
        *error = 3;
        return;
    }
    data->root = static_cast<const std::int32_t*>(bytes);
    data->rootResource = Read<std::uint32_t>(bytes);
    data->units = &EmptyUnit;
    const bool legacy = info->formatVersion[0] == 1 && info->formatVersion[1] == 0;
    const auto rootType = Type(data->rootResource);
    if ((length >= 0 && length / 4 < (legacy ? 1 : 6)) || (rootType != 2 && rootType != 4 && rootType != 5)) {
        *error = 3;
        return;
    }
    if (legacy) {
        data->localKeyLimit = 0x10000;
    } else {
        const auto index = [data](std::ptrdiff_t slot) { return Read<std::int32_t>(Words(data, 1 + slot)); };
        const auto count = index(0) & 0xff;
        if (count <= 4 || (length >= 0 && (length < (1 + count) * 4 || length < ByteLength(index(3))))) {
            *error = 3;
            return;
        }
        const auto keysTop = index(1);
        if (keysTop > 1 + count) data->localKeyLimit = ByteLength(keysTop);
        if (info->formatVersion[0] >= 3) data->poolStringLimit = static_cast<std::uint32_t>(index(0)) >> 8;
        if (count > 5) {
            const auto flags = static_cast<std::uint32_t>(index(5));
            data->noFallback = flags & 1;
            data->isPoolBundle = (flags & 2) != 0;
            data->usesPoolBundle = (flags & 4) != 0;
            data->poolStringLimit |= (flags & 0xf000) << 12;
            data->poolString16Limit = flags >> 16;
        }
        if ((data->isPoolBundle || data->usesPoolBundle) && count <= 7) {
            *error = 3;
            return;
        }
        if (count > 6 && index(6) > keysTop) data->units = reinterpret_cast<const std::uint16_t*>(Words(data, keysTop));
    }
    data->useNativeStrcmp = 1;
}

std::int32_t APS5_VABI res_getPublicType_nid_postfix(std::uint32_t resource) {
    const auto type = Type(resource);
    if (type == 4 || type == 5) return 2;
    if (type == 6) return 0;
    if (type == 9) return 8;
    return type <= 8 || type == 14 ? static_cast<std::int32_t>(type) : -1;
}

const char16_t* APS5_VABI res_getStringNoTrace_nid_postfix(const Icu::ResourceData* data, std::uint32_t resource, std::int32_t* length) {
    if (resource == 0) {
        SetLength(length, 0);
        return &EmptyString;
    }
    if (Type(resource) != 6) return reinterpret_cast<const char16_t*>(Payload(data, resource, 0, length));
    const auto& state = Data(data);
    const auto offset = Offset(resource);
    const std::uint8_t* start;
    if (static_cast<std::int32_t>(offset) < state.poolStringLimit) {
        if (!state.poolStrings) APS5_INVALID_ARG_EX;
        start = reinterpret_cast<const std::uint8_t*>(state.poolStrings) + static_cast<std::ptrdiff_t>(offset) * 2;
    } else {
        start = Units(data, offset - state.poolStringLimit);
    }
    const auto first = Read<std::uint16_t>(start);
    std::uint32_t count;
    if (first < 0xdc00 || first > 0xdfff) {
        count = 0;
        while (Read<std::uint16_t>(start + static_cast<std::ptrdiff_t>(count) * 2) != 0) {
            if (count == std::numeric_limits<std::int32_t>::max()) APS5_INVALID_ARG_EX;
            ++count;
        }
    } else if (first < 0xdfef) {
        count = first & 0x3ff;
        start += 2;
    } else if (first < 0xdfff) {
        count = (static_cast<std::uint32_t>(first - 0xdfef) << 16) | Read<std::uint16_t>(start + 2);
        start += 4;
    } else {
        count = (static_cast<std::uint32_t>(Read<std::uint16_t>(start + 2)) << 16) | Read<std::uint16_t>(start + 4);
        start += 6;
    }
    if (count > std::numeric_limits<std::int32_t>::max()) APS5_INVALID_ARG_EX;
    SetLength(length, static_cast<std::int32_t>(count));
    return reinterpret_cast<const char16_t*>(start);
}

const char16_t* APS5_VABI res_getAlias_nid_postfix(const Icu::ResourceData* data, std::uint32_t resource, std::int32_t* length) {
    if (resource == 0x30000000) {
        SetLength(length, 0);
        return &EmptyString;
    }
    return reinterpret_cast<const char16_t*>(Payload(data, resource, 3, length));
}

const std::uint8_t* APS5_VABI res_getBinaryNoTrace_nid_postfix(const Icu::ResourceData* data, std::uint32_t resource, std::int32_t* length) {
    return Payload(data, resource, 1, length);
}

const std::int32_t* APS5_VABI res_getIntVectorNoTrace_nid_postfix(const Icu::ResourceData* data, std::uint32_t resource, std::int32_t* length) {
    return reinterpret_cast<const std::int32_t*>(Payload(data, resource, 14, length));
}

std::int32_t APS5_VABI res_countArrayItems_nid_postfix(const Icu::ResourceData* data, std::uint32_t resource) {
    const auto type = Type(resource);
    const auto offset = Offset(resource);
    if (type == 5 || type == 9) return Read<std::uint16_t>(Units(data, offset));
    if (type == 2) return offset ? Read<std::uint16_t>(Words(data, offset)) : 0;
    if (type == 4 || type == 8) return offset ? Read<std::int32_t>(Words(data, offset)) : 0;
    return type == 0 || type == 1 || type == 3 || type == 6 || type == 7 || type == 14 ? 1 : 0;
}

std::uint32_t APS5_VABI res_getArrayItem_nid_postfix(const Icu::ResourceData* data, std::uint32_t resource, std::int32_t index) {
    if (index < 0) return Missing;
    const auto offset = Offset(resource);
    if (Type(resource) == 9) {
        const auto start = Units(data, offset);
        if (index < Read<std::uint16_t>(start)) return Expand(data, Read<std::uint16_t>(start + (index + 1) * 2));
    } else if (Type(resource) == 8 && offset) {
        const auto start = Words(data, offset);
        if (index < Read<std::int32_t>(start)) return Read<std::uint32_t>(start + (static_cast<std::ptrdiff_t>(index) + 1) * 4);
    }
    return Missing;
}

std::uint32_t APS5_VABI res_getTableItemByIndex_nid_postfix(const Icu::ResourceData* data, std::uint32_t resource, std::int32_t index, const char** key) {
    if (index < 0) return Missing;
    const auto table = GetTable(data, resource);
    if (index >= table.length) return Missing;
    if (key) *key = Key(data, table, index);
    return Item(data, table, index);
}

std::uint32_t APS5_VABI res_getTableItemByKey_nid_postfix(const Icu::ResourceData* data, std::uint32_t resource, std::int32_t* index, const char** key) {
    if (!key || !*key) return Missing;
    const auto table = GetTable(data, resource);
    if (!table.searchable) return Missing;
    std::int32_t found = -1;
    std::int32_t lower = 0;
    auto upper = table.length;
    while (lower < upper) {
        const auto middle = lower + (upper - lower) / 2;
        const auto candidate = Key(data, table, middle);
        const auto order = Compare(*key, candidate);
        if (order == 0) {
            *key = candidate;
            found = middle;
            break;
        }
        if (order < 0) upper = middle;
        else lower = middle + 1;
    }
    if (!index) APS5_INVALID_ARG_EX;
    *index = found;
    return found < 0 ? Missing : Item(data, table, found);
}

std::uint32_t APS5_VABI res_getResource_nid_postfix(const Icu::ResourceData* data, const char* key) {
    std::int32_t index;
    return res_getTableItemByKey_nid_postfix(data, Data(data).rootResource, &index, &key);
}

}
