#pragma once
#include "prx/libc/include/general/VabiMacros.hpp"
#include <cstddef>
#include <cstdint>

namespace Icu {

struct ResourceData {
    void* data;
    const std::int32_t* root;
    const std::uint16_t* units;
    const char* poolKeys;
    std::uint32_t rootResource;
    std::int32_t localKeyLimit;
    const std::uint16_t* poolStrings;
    std::int32_t poolStringLimit;
    std::int32_t poolString16Limit;
    std::int8_t noFallback;
    std::int8_t isPoolBundle;
    std::int8_t usesPoolBundle;
    std::int8_t useNativeStrcmp;
};

struct ResourceDataInfo {
    std::uint16_t size;
    std::uint16_t reservedWord;
    std::uint8_t isBigEndian;
    std::uint8_t charsetFamily;
    std::uint8_t sizeofUChar;
    std::uint8_t reservedByte;
    std::uint8_t dataFormat[4];
    std::uint8_t formatVersion[4];
    std::uint8_t dataVersion[4];
};

static_assert(sizeof(ResourceData) == 64);
static_assert(offsetof(ResourceData, rootResource) == 32);
static_assert(offsetof(ResourceData, poolStrings) == 40);
static_assert(offsetof(ResourceData, noFallback) == 56);
static_assert(sizeof(ResourceDataInfo) == 20);

}

extern "C" {
void APS5_VABI res_read_nid_postfix(Icu::ResourceData* data, const Icu::ResourceDataInfo* info, const void* bytes, std::int32_t length, std::int32_t* error);
std::int32_t APS5_VABI res_getPublicType_nid_postfix(std::uint32_t resource);
const char16_t* APS5_VABI res_getStringNoTrace_nid_postfix(const Icu::ResourceData* data, std::uint32_t resource, std::int32_t* length);
const char16_t* APS5_VABI res_getAlias_nid_postfix(const Icu::ResourceData* data, std::uint32_t resource, std::int32_t* length);
const std::uint8_t* APS5_VABI res_getBinaryNoTrace_nid_postfix(const Icu::ResourceData* data, std::uint32_t resource, std::int32_t* length);
const std::int32_t* APS5_VABI res_getIntVectorNoTrace_nid_postfix(const Icu::ResourceData* data, std::uint32_t resource, std::int32_t* length);
std::int32_t APS5_VABI res_countArrayItems_nid_postfix(const Icu::ResourceData* data, std::uint32_t resource);
std::uint32_t APS5_VABI res_getArrayItem_nid_postfix(const Icu::ResourceData* data, std::uint32_t resource, std::int32_t index);
std::uint32_t APS5_VABI res_getTableItemByIndex_nid_postfix(const Icu::ResourceData* data, std::uint32_t resource, std::int32_t index, const char** key);
std::uint32_t APS5_VABI res_getTableItemByKey_nid_postfix(const Icu::ResourceData* data, std::uint32_t resource, std::int32_t* index, const char** key);
std::uint32_t APS5_VABI res_getResource_nid_postfix(const Icu::ResourceData* data, const char* key);
}
