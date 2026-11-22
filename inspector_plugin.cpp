// ============================================================================
//  MHW RNG Official Plugin: Inspector & Dictionary (`rng_inspector.dll`)
//  Version : 2.1.0 (SDK v2 Reference Implementation)
//
//  Role & SDK Best-Practice Highlights:
//    1. Zero-Kernel-Bloat Dictionary (`SetFallbackMetaResolver`):
//       - Supplies 1,697 static call-site entries + 793 enclosing function ranges
//         for MHW:I 15.23 (`rng_catalog_data.inl`), while respecting explicit
//         per-site metadata registered dynamically by feature plugins (`QuerySiteMeta`).
//    2. Discovery & Telemetry Subcommands:
//       - `$rng top`, `$rng find`, `$rng names`, `$rng list`, `$rng info`, `$rng dump`
//    3. ScaleKind-Aware Generic Manipulation Subcommands:
//       - `$rng fix`, `$rng seq`, `$rng slotseed`, `$rng bypass`, `$rng clear`
//       - Maps `kScaleFloat100` percentages strictly into the open float interval
//         `(0.0f, 100.0f)` (`[0x00000001U, 0xFFFFFF00U]`), preventing both `0.0f <= 0.0f`
//         zero-weight bucket hits on `min`/`0` and `100.0f` rounding overflow on `max`/`100`,
//         while preserving literal `raw:<u32>` / `0x<hex>` injection for low-level testing.
//    4. Strict Input Validation & Lock Discipline:
//       - Validates all integer bounds (`<= 0xFFFFFFFF`), optional `condId`s, and sequence
//         items atomically before mutating any kernel slot; never calls `g_host` under `g_idxMx`.
// ============================================================================
#include "mhw_rng_api.h"

#include <windows.h>
#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <string>
#include <vector>

namespace {

enum CategoryId : std::uint8_t {
    kCatEmStat   = 0,
    kCatEmAi     = 1,
    kCatEmAct    = 2,
    kCatQuest    = 3,
    kCatPlayer   = 4,
    kCatOtomo    = 5,
    kCatLoot     = 6,
    kCatHub      = 7,
    kCatBgAnimal = 8,
    kCatBgStage  = 9,
    kCatBgUi     = 10,
    kCatBgVfx    = 11,
    kCatBgOther  = 12
};

enum ScaleKind : std::uint8_t {
    kScaleFloat100 = 0, // `(float)u32 * (100.0f / 2^32)` or `(float)u32 * 2^-32`
    kScaleMod100   = 1, // `u32 % 100` (`0 .. 99`)
    kScaleIntMod   = 2, // `u32 % N`
    kScaleRawU32   = 3  // Raw 32-bit state / seed
};

struct CatalogSiteEntry {
    std::uint32_t rva;
    std::uint8_t  category;
    std::uint8_t  scaleKind;
    const char*   alias;
    const char*   cnDesc;
    const char*   techSym;
};

struct CatalogFuncRange {
    std::uint32_t rvaLo;
    std::uint32_t rvaHi;
    std::uint8_t  category;
    std::uint8_t  scaleKind;
    const char*   baseAlias;
    const char*   cnDesc;
    const char*   techSym;
};

struct ShortcutAliasEntry {
    const char* key;
    const char* targetPattern;
    const char* cnDesc;
};

#include "rng_catalog_data.inl"

constexpr std::size_t   kCatalogSiteCount = sizeof(kCatalogSites) / sizeof(kCatalogSites[0]);
constexpr std::size_t   kFuncRangeCount   = sizeof(kCatalogFuncRanges) / sizeof(kCatalogFuncRanges[0]);
constexpr std::size_t   kShortcutCount    = sizeof(kBuiltinShortcuts) / sizeof(kBuiltinShortcuts[0]);

// Open-interval `(0.0f, 100.0f)` IEEE-754 bounds for `kScaleFloat100`:
//   - `kMinSafeFloatU32` (`1U`)          -> `+2.3283064e-8f` (`> 0.0f`, skips `weight == 0` disabled rows under `<=`)
//   - `kMaxSafeFloatU32` (`0xFFFFFF00U`) -> `99.9999924f`    (`< 100.0f`, never rounds up to `100.0f` / `1.0f`)
constexpr std::uint32_t kMinSafeFloatU32  = 0x00000001U;
constexpr std::uint32_t kMaxSafeFloatU32  = 0xFFFFFF00U;

const MhwRngHostApi*       g_host   = nullptr;
MhwRngPluginId             g_selfId = 0U;

// Strict leaf mutex protecting `#序号` quick-reference table (`g_indexedRvas`) only:
std::mutex                 g_idxMx;
std::vector<std::uint32_t> g_indexedRvas;

// ============================================================================
//  String, Numeric & Catalog Lookup Helpers
// ============================================================================

std::string LowerAscii(std::string s) {
    for (char& c : s) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + ('a' - 'A'));
    }
    return s;
}

std::string TrimStr(const std::string& s) {
    std::size_t b = 0;
    while (b < s.size() && std::isspace(static_cast<unsigned char>(s[b]))) ++b;
    std::size_t e = s.size();
    while (e > b && std::isspace(static_cast<unsigned char>(s[e - 1]))) --e;
    return s.substr(b, e - b);
}

void CopyTrunc(char* dst, std::size_t cap, const char* src) noexcept {
    if (!dst || cap == 0U) return;
    if (!src) { dst[0] = '\0'; return; }
    std::size_t i = 0U;
    while (i + 1U < cap && src[i] != '\0') {
        dst[i] = src[i];
        ++i;
    }
    dst[i] = '\0';
}

bool ParseU64Auto(const char* str, std::uint64_t& outVal) noexcept {
    if (!str) return false;
    while (*str && std::isspace(static_cast<unsigned char>(*str))) ++str;
    if (*str == '\0' || *str == '-' || *str == '+') return false;
    char* endPtr = nullptr;
    errno = 0;
    const unsigned long long v = std::strtoull(str, &endPtr, 0);
    if (endPtr == str || errno == ERANGE) return false;
    while (*endPtr && std::isspace(static_cast<unsigned char>(*endPtr))) ++endPtr;
    if (*endPtr != '\0') return false;
    outVal = static_cast<std::uint64_t>(v);
    return true;
}

bool ParseU32Strict(const char* str, std::uint32_t& outVal) noexcept {
    std::uint64_t v = 0;
    if (!ParseU64Auto(str, v) || v > 0xFFFFFFFFULL) return false;
    outVal = static_cast<std::uint32_t>(v);
    return true;
}

bool WildcardMatchI(const char* pat, const char* str) noexcept {
    if (!pat || !str) return false;
    const char* starPat = nullptr;
    const char* starStr = nullptr;
    while (*str) {
        char pc = *pat;
        char sc = *str;
        if (pc >= 'A' && pc <= 'Z') pc = static_cast<char>(pc + ('a' - 'A'));
        if (sc >= 'A' && sc <= 'Z') sc = static_cast<char>(sc + ('a' - 'A'));
        if (pc == '*') { starPat = pat++; starStr = str; }
        else if (pc == '?' || pc == sc) { ++pat; ++str; }
        else if (starPat) { pat = starPat + 1; str = ++starStr; }
        else return false;
    }
    while (*pat == '*') ++pat;
    return *pat == '\0';
}

bool ContainsSubstringI(const char* haystack, const std::string& needleLower) noexcept {
    if (!haystack || needleLower.empty()) return false;
    const std::size_t nlen = needleLower.size();
    for (std::size_t i = 0; haystack[i] != '\0'; ++i) {
        std::size_t j = 0;
        while (j < nlen && haystack[i + j] != '\0') {
            char hc = haystack[i + j];
            if (hc >= 'A' && hc <= 'Z') hc = static_cast<char>(hc + ('a' - 'A'));
            if (hc != needleLower[j]) break;
            ++j;
        }
        if (j == nlen) return true;
    }
    return false;
}

const CatalogSiteEntry* BinarySearchSite(std::uint32_t rva) noexcept {
    std::size_t lo = 0, hi = kCatalogSiteCount;
    while (lo < hi) {
        const std::size_t mid = lo + ((hi - lo) >> 1);
        if (kCatalogSites[mid].rva == rva) return &kCatalogSites[mid];
        if (kCatalogSites[mid].rva < rva)  lo = mid + 1U;
        else                               hi = mid;
    }
    return nullptr;
}

const CatalogFuncRange* BinarySearchFuncRange(std::uint32_t rva) noexcept {
    std::size_t lo = 0, hi = kFuncRangeCount;
    while (lo < hi) {
        const std::size_t mid = lo + ((hi - lo) >> 1);
        if (kCatalogFuncRanges[mid].rvaLo <= rva) lo = mid + 1U;
        else                                      hi = mid;
    }
    if (lo > 0) {
        const CatalogFuncRange& cand = kCatalogFuncRanges[lo - 1U];
        if (rva >= cand.rvaLo && rva < cand.rvaHi) return &cand;
    }
    return nullptr;
}

const char* CategoryNameCn(std::uint8_t cat) noexcept {
    switch (cat) {
        case kCatEmStat:   return u8"怪物数值";
        case kCatEmAi:     return u8"怪物AI";
        case kCatEmAct:    return u8"怪物招式";
        case kCatQuest:    return u8"任务调查";
        case kCatPlayer:   return u8"猎人弹道";
        case kCatOtomo:    return u8"随从骑乘";
        case kCatLoot:     return u8"剥取报酬";
        case kCatHub:      return u8"猫饭炼金";
        case kCatBgAnimal: return u8"环境生物";
        case kCatBgStage:  return u8"据点机关";
        case kCatBgUi:     return u8"UI跳字";
        case kCatBgVfx:    return u8"特效音效";
        default:           return u8"底层其它";
    }
}

bool __fastcall InspectorMetaResolver(std::uint32_t rva, MhwRngSiteMeta* outMeta, void*) {
    if (!outMeta) return false;
    std::memset(outMeta, 0, sizeof(*outMeta));
    outMeta->rva = rva;

    if (const CatalogSiteEntry* exact = BinarySearchSite(rva)) {
        outMeta->category       = exact->category;
        outMeta->scaleKind      = exact->scaleKind;
        outMeta->isCoreGameplay = (exact->category <= kCatHub) ? 1U : 0U;
        outMeta->found          = 1U;
        CopyTrunc(outMeta->alias, sizeof(outMeta->alias), exact->alias);
        CopyTrunc(outMeta->description, sizeof(outMeta->description), exact->cnDesc);
        CopyTrunc(outMeta->techSymbol, sizeof(outMeta->techSymbol), exact->techSym);
        return true;
    }

    if (const CatalogFuncRange* fr = BinarySearchFuncRange(rva)) {
        outMeta->category       = fr->category;
        outMeta->scaleKind      = fr->scaleKind;
        outMeta->isCoreGameplay = (fr->category <= kCatHub) ? 1U : 0U;
        outMeta->found          = 1U;
        std::snprintf(outMeta->alias, sizeof(outMeta->alias), "%s@%X", fr->baseAlias, rva);
        CopyTrunc(outMeta->description, sizeof(outMeta->description), fr->cnDesc);
        CopyTrunc(outMeta->techSymbol, sizeof(outMeta->techSymbol), fr->techSym);
        return true;
    }

    outMeta->category       = (rva < 0x2400000U) ? kCatBgOther : kCatBgVfx;
    outMeta->scaleKind      = (rva < 0x80000000U) ? kScaleIntMod : kScaleRawU32;
    outMeta->isCoreGameplay = 0U;
    outMeta->found          = 1U;
    std::snprintf(outMeta->alias, sizeof(outMeta->alias), "rva.%07X", rva);
    CopyTrunc(outMeta->description, sizeof(outMeta->description),
              (rva < 0x80000000U) ? u8"动态/区间调用随机点" : u8"外部模块调用随机点");
    return true;
}

std::vector<MhwRngSlotSnapshot> CaptureActiveSlots() {
    if (!g_host) return {};
    const std::uint32_t est = std::min<std::uint32_t>(8192U, std::max<std::uint32_t>(g_host->GetActiveSlotCount() + 64U, 256U));
    std::vector<MhwRngSlotSnapshot> snaps(est);
    const std::uint32_t cnt = g_host->SnapshotActiveSlots(snaps.data(), est);
    snaps.resize(cnt);
    return snaps;
}

void UpdateIndexedRvas(const std::vector<std::uint32_t>& list) {
    std::lock_guard<std::mutex> lk(g_idxMx);
    g_indexedRvas = list;
}

bool LookupIndexedRva(std::uint32_t oneBased, std::uint32_t& outRva) {
    if (oneBased == 0U) return false;
    std::lock_guard<std::mutex> lk(g_idxMx);
    if (oneBased > g_indexedRvas.size()) return false;
    outRva = g_indexedRvas[oneBased - 1U];
    return outRva != 0U;
}

void PushUnique(std::vector<std::uint32_t>& v, std::uint32_t x) {
    if (x != 0U && std::find(v.begin(), v.end(), x) == v.end()) v.push_back(x);
}

bool ResolveTarget(const std::string& token, std::vector<std::uint32_t>& outRvas, std::string& outLabel) {
    outRvas.clear();
    outLabel.clear();
    if (token.empty() || !g_host) return false;

    // 1. `#序号` quick reference from most recent `top` / `find` / `list` / `dump`
    if (token[0] == '#' && token.size() > 1U) {
        std::uint32_t idx = 0;
        if (ParseU32Strict(token.c_str() + 1, idx) && idx >= 1U && idx <= 8192U) {
            std::uint32_t rva = 0;
            if (LookupIndexedRva(idx, rva)) {
                outRvas.push_back(rva);
                MhwRngSiteMeta m{};
                g_host->QuerySiteMeta(rva, &m);
                outLabel = "#" + std::to_string(idx) + " " + m.alias + " (" + m.description + ")";
                return true;
            }
        }
        return false;
    }

    // 2. Built-in shortcut expansion (`size` -> `em.size`, `meal` -> `meal.trigger`, `carve` -> `loot.carve.*`...)
    const std::string lowTok = LowerAscii(token);
    std::string effectivePat = token;
    std::string shortcutDesc;
    for (std::size_t i = 0; i < kShortcutCount; ++i) {
        if (LowerAscii(kBuiltinShortcuts[i].key) == lowTok) {
            effectivePat = kBuiltinShortcuts[i].targetPattern;
            shortcutDesc = kBuiltinShortcuts[i].cnDesc;
            break;
        }
    }

    const bool hasWild = (effectivePat.find('*') != std::string::npos ||
                          effectivePat.find('?') != std::string::npos);
    if (hasWild) {
        for (std::size_t i = 0; i < kCatalogSiteCount; ++i) {
            if (WildcardMatchI(effectivePat.c_str(), kCatalogSites[i].alias)) {
                PushUnique(outRvas, kCatalogSites[i].rva);
            }
        }
        // Also match dynamic aliases registered by loaded feature plugins on active slots
        const auto snaps = CaptureActiveSlots();
        for (const auto& s : snaps) {
            MhwRngSiteMeta m{};
            g_host->QuerySiteMeta(s.callSiteRva, &m);
            if (WildcardMatchI(effectivePat.c_str(), m.alias)) {
                PushUnique(outRvas, s.callSiteRva);
            }
        }
        if (!outRvas.empty()) {
            outLabel = !shortcutDesc.empty()
                           ? (token + " -> " + shortcutDesc + u8" (共" + std::to_string(outRvas.size()) + u8"处)")
                           : (effectivePat + u8" (共" + std::to_string(outRvas.size()) + u8"处)");
            return true;
        }
    } else {
        const std::string lowPat = LowerAscii(effectivePat);
        // Check active slots first so explicit plugin `RegisterSiteMeta` aliases take priority
        const auto snaps = CaptureActiveSlots();
        for (const auto& s : snaps) {
            MhwRngSiteMeta m{};
            g_host->QuerySiteMeta(s.callSiteRva, &m);
            if (LowerAscii(m.alias) == lowPat) {
                outRvas.push_back(s.callSiteRva);
                outLabel = std::string(m.alias) + " (" + m.description + ")";
                return true;
            }
        }
        for (std::size_t i = 0; i < kCatalogSiteCount; ++i) {
            if (LowerAscii(kCatalogSites[i].alias) == lowPat) {
                outRvas.push_back(kCatalogSites[i].rva);
                MhwRngSiteMeta m{};
                g_host->QuerySiteMeta(kCatalogSites[i].rva, &m);
                outLabel = std::string(m.alias) + " (" + m.description + ")";
                return true;
            }
        }
        // Range-resolved dynamic alias `func.alias@RVA` or `rva.0123ABC`
        const std::size_t atPos = effectivePat.find('@');
        if (atPos != std::string::npos && atPos + 1U < effectivePat.size()) {
            std::uint64_t raw = 0;
            const std::string hx = "0x" + effectivePat.substr(atPos + 1U);
            if (ParseU64Auto(hx.c_str(), raw)) {
                const std::uint32_t norm = g_host->NormalizeSiteAddress(raw, nullptr);
                if (norm != 0U) {
                    outRvas.push_back(norm);
                    MhwRngSiteMeta m{};
                    g_host->QuerySiteMeta(norm, &m);
                    outLabel = std::string(m.alias) + " (" + m.description + ")";
                    return true;
                }
            }
        }
        if (lowPat.rfind("rva.", 0) == 0 && lowPat.size() > 4U) {
            std::uint64_t raw = 0;
            const std::string hx = "0x" + effectivePat.substr(4U);
            if (ParseU64Auto(hx.c_str(), raw)) {
                const std::uint32_t norm = g_host->NormalizeSiteAddress(raw, nullptr);
                if (norm != 0U) {
                    outRvas.push_back(norm);
                    MhwRngSiteMeta m{};
                    g_host->QuerySiteMeta(norm, &m);
                    outLabel = std::string(m.alias) + " (" + m.description + ")";
                    return true;
                }
            }
        }
    }

    // 3. Raw hexadecimal/decimal RVA or full virtual address (`0x169BA15` / `0x14169BA10`)
    std::uint64_t rawAddr = 0;
    if (ParseU64Auto(token.c_str(), rawAddr)) {
        const std::uint32_t norm = g_host->NormalizeSiteAddress(rawAddr, nullptr);
        if (norm != 0U) {
            outRvas.push_back(norm);
            MhwRngSiteMeta m{};
            g_host->QuerySiteMeta(norm, &m);
            char buf[192]{};
            std::snprintf(buf, sizeof(buf), "%s (%s | 0x%07X)", m.alias, m.description, norm);
            outLabel = buf;
            return true;
        }
    }
    return false;
}

// ============================================================================
//  ScaleKind-Aware Value Parser (`[0x00000001U, 0xFFFFFF00U]` Open-Interval Float)
// ============================================================================

std::uint32_t PctToSafeFloatU32(double pct) noexcept {
    if (!(pct > 0.0)) return kMinSafeFloatU32;
    if (pct >= 100.0) return kMaxSafeFloatU32;
    const auto u = static_cast<std::uint64_t>((pct / 100.0) * static_cast<double>(kMaxSafeFloatU32) + 0.5);
    if (u <= kMinSafeFloatU32) return kMinSafeFloatU32;
    if (u >= kMaxSafeFloatU32) return kMaxSafeFloatU32;
    return static_cast<std::uint32_t>(u);
}

bool ParseSmartValue(const std::string& rawTok,
                     std::uint8_t scaleKind,
                     std::uint32_t& outVal,
                     std::string* outExplain) {
    const std::string tok = TrimStr(rawTok);
    if (tok.empty()) return false;
    const std::string low = LowerAscii(tok);

    auto explain = [&](const char* fmt, ...) {
        if (!outExplain) return;
        char b[128]{};
        va_list ap;
        va_start(ap, fmt);
        std::vsnprintf(b, sizeof(b), fmt, ap);
        va_end(ap);
        *outExplain = b;
    };

    if (low == "min") {
        if (scaleKind == kScaleFloat100) {
            outVal = kMinSafeFloatU32;
            explain(u8"最小安全浮点档 +0.0/100 (0x00000001)");
        } else {
            outVal = 0U;
            explain(u8"最小档 0");
        }
        return true;
    }
    if (low == "mid" || low == "half") {
        outVal = (scaleKind == kScaleMod100) ? 50U : 0x80000000U;
        explain(scaleKind == kScaleMod100 ? u8"中间档 余50/99" : u8"中间档 50.0/100");
        return true;
    }
    if (low == "max") {
        outVal = (scaleKind == kScaleMod100)
                     ? 99U
                     : (scaleKind == kScaleFloat100 ? kMaxSafeFloatU32 : 0xFFFFFFFFU);
        explain(scaleKind == kScaleMod100 ? u8"最大余数 99/99" : u8"最大安全档 100.0/100 (0xFFFFFF00)");
        return true;
    }
    if (low.rfind("raw:", 0) == 0) {
        if (!ParseU32Strict(tok.c_str() + 4, outVal)) return false;
        explain(u8"原始u32=%u (0x%08X)", outVal, outVal);
        return true;
    }
    if (low.rfind("0x", 0) == 0) {
        if (!ParseU32Strict(tok.c_str(), outVal)) return false;
        explain("0x%08X", outVal);
        return true;
    }
    if (tok.back() == '%' && tok.size() > 1U) {
        char* ep = nullptr;
        const double p = std::strtod(tok.c_str(), &ep);
        if (ep == tok.c_str() || !ep || *ep != '%' || ep[1] != '\0' || !std::isfinite(p) || p < 0.0 || p > 100.0) {
            return false;
        }
        outVal = (scaleKind == kScaleMod100)
                     ? ((p >= 99.0) ? 99U : static_cast<std::uint32_t>(p + 0.5))
                     : PctToSafeFloatU32(p);
        explain(u8"比例换算=%.1f%% (0x%08X)", p, outVal);
        return true;
    }
    if (scaleKind == kScaleFloat100) {
        char* ep = nullptr;
        const double num = std::strtod(tok.c_str(), &ep);
        if (ep != tok.c_str() && std::isfinite(num)) {
            while (*ep && std::isspace(static_cast<unsigned char>(*ep))) ++ep;
            if (*ep == '\0' && num >= 0.0 && num <= 100.0) {
                outVal = PctToSafeFloatU32(num);
                explain(u8"浮点换算=%.1f/100 (0x%08X)", num, outVal);
                return true;
            }
        }
    }

    std::uint32_t u32 = 0;
    if (!ParseU32Strict(tok.c_str(), u32)) return false;
    if (scaleKind == kScaleMod100 && u32 == 100U) {
        outVal = 99U;
        explain(u8"模100最大余数=99/99");
        return true;
    }
    outVal = u32;
    explain(scaleKind == kScaleMod100 ? u8"模100余数=%u/99" : u8"整数=%u",
            scaleKind == kScaleMod100 ? static_cast<unsigned>(outVal % 100U) : outVal);
    return true;
}

void FormatModeCn(const MhwRngSlotSnapshot& s, std::uint8_t scaleKind, char* buf, std::size_t cap) {
    if (g_host && g_host->FormatSlotCustom(&s, buf, cap)) return;
    switch (s.mode) {
        case kMhwRngSlotFixedValue:
            if (scaleKind == kScaleFloat100) {
                std::snprintf(buf, cap, u8"固定=%.1f/100", (static_cast<double>(s.fixedValue) * 100.0) / 4294967296.0);
            } else if (scaleKind == kScaleMod100) {
                std::snprintf(buf, cap, u8"固定余数=%u", static_cast<unsigned>(s.fixedValue % 100U));
            } else {
                std::snprintf(buf, cap, u8"固定值=%u", s.fixedValue);
            }
            break;
        case kMhwRngSlotCustomSeed:
            std::snprintf(buf, cap, u8"独立种子=%llu", static_cast<unsigned long long>(s.customSeed));
            break;
        case kMhwRngSlotSequence: {
            const char* pol = (s.seqEndPolicy == kMhwRngSeqHoldLast) ? u8"停住"
                              : (s.seqEndPolicy == kMhwRngSeqFallbackDerived ? u8"转随机" : u8"循环");
            std::snprintf(buf, cap, u8"序列[%u/%u %s]", s.seqCursor, s.seqLength, pol);
            break;
        }
        case kMhwRngSlotBypass:
            std::snprintf(buf, cap, u8"原版直通");
            break;
        default:
            std::snprintf(buf, cap, s.hasPluginHook ? u8"插件动态回调" : u8"跟随总种子");
            break;
    }
}

void FormatValCn(std::uint32_t val, std::uint8_t scaleKind, char* buf, std::size_t cap) {
    const double pct = (static_cast<double>(val) * 100.0) / 4294967296.0;
    const unsigned rem100 = static_cast<unsigned>(val % 100U);
    if (scaleKind == kScaleFloat100) {
        std::snprintf(buf, cap, u8"[浮点0~100] %5.1f  (0x%08X)", pct, val);
    } else if (scaleKind == kScaleMod100) {
        std::snprintf(buf, cap, u8"[模100抽签] 余%02u/99 (0x%08X)", rem100, val);
    } else if (scaleKind == kScaleIntMod) {
        std::snprintf(buf, cap, u8"[整数取模] 余100:%02u %4.0f%% (0x%08X)", rem100, pct, val);
    } else {
        std::snprintf(buf, cap, u8"[32位种子] 0x%08X (%10u)", val, val);
    }
}

// ============================================================================
//  Subcommand Handlers (`names`, `top`, `find`, `list`, `info`, `dump`,
//                       `fix`, `seq`, `slotseed`, `bypass`, `clear`)
// ============================================================================

void __fastcall Cmd_Names(int, const char* const*, const char*, void*) {
    if (!g_host) return;
    g_host->ChatPrint(u8"[inspector] 怪物: size(体型) dying(濒死) think(出招分支) target(仇恨) dung(异臭弹)");
    g_host->ChatPrint(u8"[inspector] 任务/据点: quest(接任务) bonus(天气) meal(猫饭) daily(每日猫饭) meld(炼金)");
    g_host->ChatPrint(u8"[inspector] 掉落/洗练: carve(剥取) shiny(掉落物) reward(报酬) item(道具表) awaken(觉醒)");
    g_host->ChatPrint(u8"[inspector] 专属怪: fatalis alatreon velkhana nergi rajang safi | 专用体型插件: `$rng size`");
}

void __fastcall Cmd_Top(int argc, const char* const* argv, const char*, void*) {
    if (!g_host) return;
    bool includeBg = false;
    std::size_t maxShow = 6U;
    for (int i = 0; i < argc; ++i) {
        const std::string t = LowerAscii(argv[i]);
        if (t == "all") {
            includeBg = true;
        } else {
            std::uint32_t n = 0;
            if (!ParseU32Strict(t.c_str(), n) || n == 0U) {
                g_host->ChatPrintf(u8"[inspector] 用法: `$rng top [1~20] [all]` (未知参数 `%s`)", argv[i]);
                return;
            }
            maxShow = std::min<std::size_t>(n, 20U);
        }
    }

    const auto snaps = CaptureActiveSlots();
    struct Item { MhwRngSlotSnapshot snap; MhwRngSiteMeta meta; };
    std::vector<Item> items;
    for (const auto& s : snaps) {
        if (s.epochCalls == 0ULL) continue;
        MhwRngSiteMeta m{};
        g_host->QuerySiteMeta(s.callSiteRva, &m);
        if (!includeBg && m.isCoreGameplay == 0U) continue;
        items.push_back(Item{s, m});
    }
    std::sort(items.begin(), items.end(), [](const Item& a, const Item& b) {
        if (a.snap.epochCalls != b.snap.epochCalls) return a.snap.epochCalls > b.snap.epochCalls;
        if (a.snap.callSiteRva != b.snap.callSiteRva) return a.snap.callSiteRva < b.snap.callSiteRva;
        return a.snap.condId < b.snap.condId;
    });

    if (items.empty()) {
        g_host->ChatPrint(u8"[inspector] 本轮未触发核心玩法随机点 (做个动作再试，或输 `$rng top all` 含背景)");
        return;
    }

    // Build 1-based `#序号` per unique RVA so displayed `#idx` always matches `ResolveTarget("#idx")`!
    std::vector<std::uint32_t> indexed;
    std::vector<std::uint32_t> itemOneBasedIdx(items.size(), 0U);
    for (std::size_t i = 0; i < items.size(); ++i) {
        const std::uint32_t rva = items[i].snap.callSiteRva;
        auto it = std::find(indexed.begin(), indexed.end(), rva);
        if (it == indexed.end()) {
            indexed.push_back(rva);
            itemOneBasedIdx[i] = static_cast<std::uint32_t>(indexed.size());
        } else {
            itemOneBasedIdx[i] = static_cast<std::uint32_t>((it - indexed.begin()) + 1);
        }
    }
    UpdateIndexedRvas(indexed);

    const std::size_t showN = std::min(items.size(), maxShow);
    g_host->ChatPrintf(u8"[inspector] 本轮%s随机点共 %zu 处 (前 %zu 处，可直接 `#序号` 点名)：",
                       includeBg ? u8"活跃" : u8"核心", items.size(), showN);
    for (std::size_t i = 0; i < showN; ++i) {
        const auto& it = items[i];
        const double pct = (static_cast<double>(it.snap.lastValue) * 100.0) / 4294967296.0;
        const unsigned rem = static_cast<unsigned>(it.snap.lastValue % 100U);
        char condTag[24]{};
        if (it.snap.condId != 0U) std::snprintf(condTag, sizeof(condTag), "[C:%u]", it.snap.condId);
        if (it.meta.scaleKind == kScaleFloat100) {
            g_host->ChatPrintf(u8"#%u %s%s [%s] %llu次 | 浮点:%.1f/100",
                               itemOneBasedIdx[i], it.meta.alias, condTag, it.meta.description,
                               static_cast<unsigned long long>(it.snap.epochCalls), pct);
        } else {
            g_host->ChatPrintf(u8"#%u %s%s [%s] %llu次 | 余100:%02u (%.0f%%)",
                               itemOneBasedIdx[i], it.meta.alias, condTag, it.meta.description,
                               static_cast<unsigned long long>(it.snap.epochCalls), rem, pct);
        }
    }
}

void __fastcall Cmd_Find(int argc, const char* const* argv, const char*, void*) {
    if (!g_host) return;
    if (argc < 1 || argv[0][0] == '\0') {
        g_host->ChatPrint(u8"[inspector] 用法: `$rng find <keyword>` (例: `$rng find meal` 或 `$rng find fatalis`)");
        return;
    }
    const std::string kwLow = LowerAscii(argv[0]);
    std::vector<std::uint32_t> indexed;
    std::size_t printed = 0U;

    for (std::size_t i = 0; i < kShortcutCount && printed < 6U; ++i) {
        if (ContainsSubstringI(kBuiltinShortcuts[i].key, kwLow) ||
            ContainsSubstringI(kBuiltinShortcuts[i].targetPattern, kwLow) ||
            ContainsSubstringI(kBuiltinShortcuts[i].cnDesc, kwLow)) {
            g_host->ChatPrintf(u8"[inspector] 短词 `%s` -> %s : %s",
                               kBuiltinShortcuts[i].key, kBuiltinShortcuts[i].targetPattern, kBuiltinShortcuts[i].cnDesc);
            ++printed;
        }
    }
    for (int pass = 0; pass < 2 && printed < 6U; ++pass) {
        for (std::size_t i = 0; i < kCatalogSiteCount && printed < 6U; ++i) {
            const bool isCore = (kCatalogSites[i].category <= kCatHub);
            if ((pass == 0) != isCore) continue;
            if (ContainsSubstringI(kCatalogSites[i].alias, kwLow) ||
                ContainsSubstringI(kCatalogSites[i].cnDesc, kwLow) ||
                ContainsSubstringI(kCatalogSites[i].techSym, kwLow)) {
                indexed.push_back(kCatalogSites[i].rva);
                g_host->ChatPrintf(u8"[inspector] #%zu %s : %s",
                                   indexed.size(), kCatalogSites[i].alias, kCatalogSites[i].cnDesc);
                ++printed;
            }
        }
    }
    if (!indexed.empty()) UpdateIndexedRvas(indexed);
    if (printed == 0U) {
        g_host->ChatPrintf(u8"[inspector] 未找到匹配 `%s` 的随机点", argv[0]);
    }
}

void __fastcall Cmd_List(int, const char* const*, const char*, void*) {
    if (!g_host) return;
    const auto snaps = CaptureActiveSlots();

    std::vector<MhwRngSlotSnapshot> ovrs;
    for (const auto& s : snaps) {
        if (s.mode != kMhwRngSlotMasterDerived || (s.condId == 0U && s.hasPluginHook != 0U)) {
            ovrs.push_back(s);
        }
    }
    if (ovrs.empty()) {
        g_host->ChatPrint(u8"[inspector] 当前无任何激活的锁定规则或条件钩子");
        return;
    }
    std::sort(ovrs.begin(), ovrs.end(), [](const MhwRngSlotSnapshot& a, const MhwRngSlotSnapshot& b) {
        if (a.callSiteRva != b.callSiteRva) return a.callSiteRva < b.callSiteRva;
        return a.condId < b.condId;
    });

    std::vector<std::uint32_t> indexed;
    for (const auto& s : ovrs) PushUnique(indexed, s.callSiteRva);
    UpdateIndexedRvas(indexed);

    const std::size_t showN = std::min<std::size_t>(ovrs.size(), 6U);
    g_host->ChatPrintf(u8"[inspector] 当前共激活 %zu 处规则：", ovrs.size());
    for (std::size_t i = 0; i < showN; ++i) {
        MhwRngSiteMeta m{};
        g_host->QuerySiteMeta(ovrs[i].callSiteRva, &m);
        char modeBuf[80]{};
        FormatModeCn(ovrs[i], m.scaleKind, modeBuf, sizeof(modeBuf));
        char condTag[24]{};
        if (ovrs[i].condId != 0U) std::snprintf(condTag, sizeof(condTag), "[Cond:%u]", ovrs[i].condId);
        g_host->ChatPrintf(u8"[%s] %s%s (%s) = %s [本轮%llu次]",
                           g_host->GetPluginShortName(ovrs[i].ownerPluginId),
                           m.alias, condTag, m.description, modeBuf,
                           static_cast<unsigned long long>(ovrs[i].epochCalls));
    }
    if (ovrs.size() > showN) {
        g_host->ChatPrintf(u8"[inspector] ...另有 %zu 处规则激活 (输 `$rng dump` 导出完整详表)", ovrs.size() - showN);
    }
}

void __fastcall Cmd_Info(int argc, const char* const* argv, const char*, void*) {
    if (!g_host) return;
    if (argc < 1) {
        g_host->ChatPrint(u8"[inspector] 用法: `$rng info <target|#idx> [condId]`");
        return;
    }
    std::vector<std::uint32_t> rvas;
    std::string label;
    if (!ResolveTarget(argv[0], rvas, label) || rvas.empty()) {
        g_host->ChatPrintf(u8"[inspector] 找不到目标 `%s`", argv[0]);
        return;
    }
    std::uint32_t cond = 0U;
    if (argc >= 2 && !ParseU32Strict(argv[1], cond)) {
        g_host->ChatPrintf(u8"[inspector] 无效条件编号(condId): `%s`", argv[1]);
        return;
    }

    const std::uint32_t rva = rvas[0];
    MhwRngSiteMeta m{};
    g_host->QuerySiteMeta(rva, &m);
    MhwRngSlotSnapshot snap{};
    if (!g_host->GetCondSlotInfo(rva, cond, &snap)) {
        g_host->ChatPrintf(u8"[inspector] %s [Cond:%u] (0x%07X) 尚未触发",
                           m.alias, cond, rva);
        return;
    }
    char modeBuf[80]{}, valBuf[96]{};
    FormatModeCn(snap, m.scaleKind, modeBuf, sizeof(modeBuf));
    FormatValCn(snap.lastValue, m.scaleKind, valBuf, sizeof(valBuf));
    g_host->ChatPrintf(u8"[inspector] %s [Cond:%u | 归属:%s] %s | 本轮%llu次 | %s",
                       m.alias, snap.condId, g_host->GetPluginShortName(snap.ownerPluginId),
                       modeBuf, static_cast<unsigned long long>(snap.epochCalls), valBuf);
}

bool WriteDumpFile(const std::string& path, std::uint32_t& outCount) {
    const auto snaps = CaptureActiveSlots();
    outCount = static_cast<std::uint32_t>(snaps.size());

    struct Row {
        MhwRngSlotSnapshot snap;
        MhwRngSiteMeta     meta;
        std::uint32_t      idx = 0;
    };
    std::vector<Row> ovrRows, coreRows, bgRows;
    for (const auto& s : snaps) {
        MhwRngSiteMeta m{};
        g_host->QuerySiteMeta(s.callSiteRva, &m);
        Row r{s, m, 0U};
        const bool isOvr = (s.mode != kMhwRngSlotMasterDerived || (s.condId == 0U && s.hasPluginHook != 0U));
        if (isOvr) ovrRows.push_back(r);
        if (m.isCoreGameplay != 0U) coreRows.push_back(std::move(r));
        else if (!isOvr)            bgRows.push_back(std::move(r));
    }

    auto cmp = [](const Row& a, const Row& b) {
        if (a.snap.epochCalls != b.snap.epochCalls) return a.snap.epochCalls > b.snap.epochCalls;
        if (a.snap.totalCalls != b.snap.totalCalls) return a.snap.totalCalls > b.snap.totalCalls;
        if (a.snap.callSiteRva != b.snap.callSiteRva) return a.snap.callSiteRva < b.snap.callSiteRva;
        return a.snap.condId < b.snap.condId;
    };
    std::sort(ovrRows.begin(),  ovrRows.end(),  cmp);
    std::sort(coreRows.begin(), coreRows.end(), cmp);
    std::sort(bgRows.begin(),   bgRows.end(),   cmp);

    std::vector<std::uint32_t> orderedRvas;
    auto assignIdx = [&](std::uint32_t rva) -> std::uint32_t {
        for (std::size_t i = 0; i < orderedRvas.size(); ++i) {
            if (orderedRvas[i] == rva) return static_cast<std::uint32_t>(i + 1U);
        }
        orderedRvas.push_back(rva);
        return static_cast<std::uint32_t>(orderedRvas.size());
    };
    for (auto& r : coreRows) r.idx = assignIdx(r.snap.callSiteRva);
    for (auto& r : ovrRows)  r.idx = assignIdx(r.snap.callSiteRva);
    for (auto& r : bgRows)   r.idx = assignIdx(r.snap.callSiteRva);
    UpdateIndexedRvas(orderedRvas);

    FILE* f = nullptr;
    fopen_s(&f, path.c_str(), "wb");
    if (!f) return false;

    static constexpr unsigned char kBom[3] = {0xEF, 0xBB, 0xBF};
    std::fwrite(kBom, 1, 3, f);

    SYSTEMTIME st{};
    ::GetLocalTime(&st);
    const std::uint64_t seed = g_host->GetMasterSeed();
    std::fprintf(f, "========================================================================================================================\r\n");
    std::fprintf(f, u8" 怪物猎人：世界 冰原 (15.23) — RNG 微内核 + 插件体系 触发详表 (由 rng_inspector.dll 生成)\r\n");
    const std::uint32_t engMode = g_host->GetEngineMode();
    const char* modeStr = (engMode == kMhwRngModeTakeover)
                              ? u8"全局接管"
                              : ((engMode == kMhwRngModeSelective)
                                     ? u8"按需接管"
                                     : ((engMode == kMhwRngModeObserveOnly) ? u8"仅观测" : u8"关闭"));
    std::fprintf(f, u8" 生成时间 : %04d-%02d-%02d %02d:%02d:%02d  |  模式:%s  |  总种子:%llu (0x%llX)  |  第 %llu 轮\r\n",
                 st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond,
                 modeStr,
                 static_cast<unsigned long long>(seed), static_cast<unsigned long long>(seed),
                 static_cast<unsigned long long>(g_host->GetEpoch()));
    std::fprintf(f, u8" 概览统计 : 共 %u 个活跃(RVA,Cond)槽  =  激活规则/插件钩子 %zu 处  |  核心玩法 %zu 处  |  背景环境/特效 %zu 处\r\n",
                 outCount, ovrRows.size(), coreRows.size(), bgRows.size());
    std::fprintf(f, "========================================================================================================================\r\n\r\n");

    auto writeRow = [&](const Row& r) {
        char idxBuf[16]{};
        std::snprintf(idxBuf, sizeof(idxBuf), "#%u", r.idx);
        char aliasCond[64]{};
        if (r.snap.condId == 0U) {
            std::snprintf(aliasCond, sizeof(aliasCond), "%s", r.meta.alias);
        } else {
            std::snprintf(aliasCond, sizeof(aliasCond), "%s[C:%u]", r.meta.alias, r.snap.condId);
        }
        char modeBuf[80]{}, valBuf[96]{};
        FormatModeCn(r.snap, r.meta.scaleKind, modeBuf, sizeof(modeBuf));
        if (r.snap.totalCalls == 0ULL && r.snap.mode != kMhwRngSlotFixedValue) {
            std::snprintf(valBuf, sizeof(valBuf), u8"（尚未触发抽取）                    ");
        } else {
            const std::uint32_t v = (r.snap.totalCalls == 0ULL && r.snap.mode == kMhwRngSlotFixedValue)
                                        ? r.snap.fixedValue
                                        : r.snap.lastValue;
            FormatValCn(v, r.meta.scaleKind, valBuf, sizeof(valBuf));
        }
        std::fprintf(f, "  %-6s %-24s [%-12s | %-9s] %-18s | " u8"本轮:%6llu次 (总:%7llu) | %s | %s [0x%07X %s]\r\n",
                     idxBuf, aliasCond, CategoryNameCn(r.meta.category),
                     g_host->GetPluginShortName(r.snap.ownerPluginId),
                     modeBuf,
                     static_cast<unsigned long long>(r.snap.epochCalls),
                     static_cast<unsigned long long>(r.snap.totalCalls),
                     valBuf, r.meta.description, r.snap.callSiteRva, r.meta.techSymbol);
    };

    std::fprintf(f, u8"【一、当前激活的插件钩子 / 条件锁定规则（共 %zu 处）】\r\n", ovrRows.size());
    if (ovrRows.empty()) std::fprintf(f, u8"  （无）\r\n\r\n");
    else { for (const auto& r : ovrRows) writeRow(r); std::fprintf(f, "\r\n"); }

    std::fprintf(f, u8"【二、本轮核心玩法随机点（共 %zu 处）】\r\n", coreRows.size());
    if (coreRows.empty()) std::fprintf(f, u8"  （尚未触发核心随机点）\r\n\r\n");
    else { for (const auto& r : coreRows) writeRow(r); std::fprintf(f, "\r\n"); }

    std::fprintf(f, u8"【三、背景环境与视觉特效随机点（共 %zu 处）】\r\n", bgRows.size());
    if (bgRows.empty()) std::fprintf(f, u8"  （无）\r\n");
    else { for (const auto& r : bgRows) writeRow(r); }

    std::fclose(f);
    return true;
}

void __fastcall Cmd_Dump(int argc, const char* const* argv, const char*, void*) {
    if (!g_host) return;
    const std::string path = (argc >= 1 && argv[0][0] != '\0')
                                 ? std::string(argv[0])
                                 : (std::string(g_host->GetRootPluginDir()) + "\\mhw_rng_dump.txt");
    std::uint32_t cnt = 0;
    if (WriteDumpFile(path, cnt)) {
        g_host->ChatPrintf(u8"[inspector] 已导出中文分类详表 -> mhw_rng_dump.txt (共%u槽，可直接用 #序号)", cnt);
    } else {
        g_host->ChatPrint(u8"[inspector] 导出 mhw_rng_dump.txt 失败");
    }
}

void __fastcall Cmd_Fix(int argc, const char* const* argv, const char*, void*) {
    if (!g_host) return;
    if (argc < 2 || argc > 3) {
        g_host->ChatPrint(u8"[inspector] 用法: `$rng fix <target|#idx> <0~100|min|mid|max|raw:u32> [condId]`");
        return;
    }
    std::vector<std::uint32_t> rvas;
    std::string label;
    if (!ResolveTarget(argv[0], rvas, label) || rvas.empty()) {
        g_host->ChatPrintf(u8"[inspector] 找不到目标 `%s`", argv[0]);
        return;
    }
    std::uint32_t cond = 0U;
    if (argc >= 3 && !ParseU32Strict(argv[2], cond)) {
        g_host->ChatPrintf(u8"[inspector] 无效条件编号(condId): `%s`", argv[2]);
        return;
    }

    // Validate all matched RVAs atomically before mutating kernel slots
    std::vector<std::pair<std::uint32_t, std::uint32_t>> plan;
    plan.reserve(rvas.size());
    std::string explain;
    for (std::size_t i = 0; i < rvas.size(); ++i) {
        MhwRngSiteMeta m{};
        g_host->QuerySiteMeta(rvas[i], &m);
        std::uint32_t val = 0;
        if (!ParseSmartValue(argv[1], m.scaleKind, val, i == 0 ? &explain : nullptr)) {
            g_host->ChatPrintf(u8"[inspector] 无效数值 `%s`", argv[1]);
            return;
        }
        plan.emplace_back(rvas[i], val);
    }

    for (const auto& kv : plan) {
        g_host->SetCondFixedValue(g_selfId, kv.first, cond, kv.second);
    }
    g_host->ChatPrintf(u8"[inspector] 已锁定 %s [Cond:%u] -> %s",
                       label.c_str(), cond, explain.c_str());
}

void __fastcall Cmd_Seq(int argc, const char* const* argv, const char*, void*) {
    if (!g_host) return;
    if (argc < 2 || argc > 4) {
        g_host->ChatPrint(u8"[inspector] 用法: `$rng seq <target|#idx> <v1,v2,...> [loop|hold|prng] [condId]`");
        return;
    }
    std::vector<std::uint32_t> rvas;
    std::string label;
    if (!ResolveTarget(argv[0], rvas, label) || rvas.empty()) {
        g_host->ChatPrintf(u8"[inspector] 找不到目标 `%s`", argv[0]);
        return;
    }

    std::vector<std::string> rawItems;
    const std::string csv = argv[1];
    std::size_t pos = 0;
    while (pos < csv.size()) {
        const std::size_t c = csv.find(',', pos);
        const std::string it = TrimStr(csv.substr(pos, c == std::string::npos ? std::string::npos : (c - pos)));
        if (!it.empty()) rawItems.push_back(it);
        if (c == std::string::npos) break;
        pos = c + 1U;
    }
    if (rawItems.empty()) {
        g_host->ChatPrint(u8"[inspector] 序列不能为空 (例: `10,50,90`)");
        return;
    }

    std::uint8_t  pol   = kMhwRngSeqLoop;
    const char*   polCn = u8"循环";
    std::uint32_t cond  = 0U;

    if (argc >= 3) {
        const std::string p = LowerAscii(argv[2]);
        if (p == "loop") {
            pol = kMhwRngSeqLoop; polCn = u8"循环";
        } else if (p == "hold") {
            pol = kMhwRngSeqHoldLast; polCn = u8"停在末项";
        } else if (p == "prng" || p == "derived") {
            pol = kMhwRngSeqFallbackDerived; polCn = u8"播完转随机";
        } else if (argc == 3 && ParseU32Strict(argv[2], cond)) {
            // Convenient shorthand: `$rng seq <target> <v1,v2> <condId>`
        } else {
            g_host->ChatPrintf(u8"[inspector] 无效结束策略 `%s`；支持 loop / hold / prng", argv[2]);
            return;
        }
    }
    if (argc >= 4 && !ParseU32Strict(argv[3], cond)) {
        g_host->ChatPrintf(u8"[inspector] 无效条件编号(condId): `%s`", argv[3]);
        return;
    }

    // Validate all sequence items across all matched RVAs before applying
    struct SeqPlan { std::uint32_t rva; std::vector<std::uint32_t> vals; };
    std::vector<SeqPlan> plans;
    plans.reserve(rvas.size());
    for (const std::uint32_t rva : rvas) {
        MhwRngSiteMeta m{};
        g_host->QuerySiteMeta(rva, &m);
        SeqPlan sp{rva, {}};
        sp.vals.reserve(rawItems.size());
        for (const auto& s : rawItems) {
            std::uint32_t v = 0;
            if (!ParseSmartValue(s, m.scaleKind, v, nullptr)) {
                g_host->ChatPrintf(u8"[inspector] 序列项无效: `%s`", s.c_str());
                return;
            }
            sp.vals.push_back(v);
        }
        plans.push_back(std::move(sp));
    }

    for (const auto& sp : plans) {
        g_host->SetCondSequence(g_selfId, sp.rva, cond,
                                sp.vals.data(), static_cast<std::uint32_t>(sp.vals.size()), pol);
    }
    g_host->ChatPrintf(u8"[inspector] 已设置 %s [Cond:%u] -> 序列(%zu步, %s)",
                       label.c_str(), cond, rawItems.size(), polCn);
}

void __fastcall Cmd_SlotSeed(int argc, const char* const* argv, const char*, void*) {
    if (!g_host) return;
    if (argc < 2 || argc > 3) {
        g_host->ChatPrint(u8"[inspector] 用法: `$rng slotseed <target|#idx> <seed> [condId]`");
        return;
    }
    std::vector<std::uint32_t> rvas;
    std::string label;
    if (!ResolveTarget(argv[0], rvas, label) || rvas.empty()) {
        g_host->ChatPrintf(u8"[inspector] 找不到目标 `%s`", argv[0]);
        return;
    }
    std::uint64_t seed = 0;
    if (!ParseU64Auto(argv[1], seed)) {
        g_host->ChatPrintf(u8"[inspector] 无效种子数值: `%s`", argv[1]);
        return;
    }
    std::uint32_t cond = 0U;
    if (argc >= 3 && !ParseU32Strict(argv[2], cond)) {
        g_host->ChatPrintf(u8"[inspector] 无效条件编号(condId): `%s`", argv[2]);
        return;
    }
    for (const std::uint32_t rva : rvas) {
        g_host->SetCondCustomSeed(g_selfId, rva, cond, seed);
    }
    g_host->ChatPrintf(u8"[inspector] %s [Cond:%u] -> 独立种子 %llu",
                       label.c_str(), cond, static_cast<unsigned long long>(seed));
}

void __fastcall Cmd_Bypass(int argc, const char* const* argv, const char*, void*) {
    if (!g_host) return;
    if (argc < 1 || argc > 2) {
        g_host->ChatPrint(u8"[inspector] 用法: `$rng bypass <target|#idx> [condId]`");
        return;
    }
    std::vector<std::uint32_t> rvas;
    std::string label;
    if (!ResolveTarget(argv[0], rvas, label) || rvas.empty()) {
        g_host->ChatPrintf(u8"[inspector] 找不到目标 `%s`", argv[0]);
        return;
    }
    std::uint32_t cond = 0U;
    if (argc >= 2 && !ParseU32Strict(argv[1], cond)) {
        g_host->ChatPrintf(u8"[inspector] 无效条件编号(condId): `%s`", argv[1]);
        return;
    }
    for (const std::uint32_t rva : rvas) {
        g_host->SetCondBypass(g_selfId, rva, cond);
    }
    g_host->ChatPrintf(u8"[inspector] %s [Cond:%u] -> 原版直通", label.c_str(), cond);
}

void __fastcall Cmd_Clear(int argc, const char* const* argv, const char*, void*) {
    if (!g_host) return;
    if (argc < 1) {
        g_host->ChatPrint(u8"[inspector] 用法: `$rng clear <target|#idx|all>`");
        return;
    }
    if (LowerAscii(argv[0]) == "all") {
        g_host->ClearAllRules();
        g_host->ChatPrint(u8"[inspector] 已清空全部覆盖规则");
        return;
    }
    std::vector<std::uint32_t> rvas;
    std::string label;
    if (!ResolveTarget(argv[0], rvas, label) || rvas.empty()) {
        g_host->ChatPrintf(u8"[inspector] 找不到目标 `%s`", argv[0]);
        return;
    }
    for (const std::uint32_t rva : rvas) {
        g_host->ClearSlotAllConditions(rva);
    }
    g_host->ChatPrintf(u8"[inspector] 已恢复 %s -> 跟随总种子", label.c_str());
}

const MhwRngPluginDescriptor kPluginDesc = {
    kMhwRngApiVersion,
    "inspector",
    u8"RNG全量词典与遥测探针",
    "2.1.0",
    u8"提供1697处随机点词典、开区间安全浮点换算及 top/find/names/list/info/dump/fix/seq 指令"
};

} // namespace

MHW_RNG_PLUGIN_EXPORT const MhwRngPluginDescriptor* MhwRngPlugin_GetInfo() {
    return &kPluginDesc;
}

MHW_RNG_PLUGIN_EXPORT bool MhwRngPlugin_Init(const MhwRngHostApi* host, MhwRngPluginId selfId) {
    if (!host || host->apiVersion != kMhwRngApiVersion) return false;
    g_host   = host;
    g_selfId = selfId;

    host->SetFallbackMetaResolver(selfId, &InspectorMetaResolver, nullptr);

    host->RegisterSubcommand(selfId, "top",      "$rng top [N|all]",       u8"查看本轮触发最多的核心随机点",   &Cmd_Top,      nullptr);
    host->RegisterSubcommand(selfId, "find",     "$rng find <kw>",         u8"按英文关键词搜索随机点",         &Cmd_Find,     nullptr);
    host->RegisterSubcommand(selfId, "names",    "$rng names",             u8"常用英文短词速查表",             &Cmd_Names,    nullptr);
    host->RegisterSubcommand(selfId, "list",     "$rng list",              u8"列出所有已激活的规则与条件槽",   &Cmd_List,     nullptr);
    host->RegisterSubcommand(selfId, "info",     "$rng info <target>",     u8"查看单个随机点详情",             &Cmd_Info,     nullptr);
    host->RegisterSubcommand(selfId, "dump",     "$rng dump [path]",       u8"导出三段式中文详表到txt",        &Cmd_Dump,     nullptr);
    host->RegisterSubcommand(selfId, "fix",      "$rng fix <target> <v>",  u8"通用按点换算锁定固定值",         &Cmd_Fix,      nullptr);
    host->RegisterSubcommand(selfId, "seq",      "$rng seq <target> <vs>", u8"通用按点换算注入序列",           &Cmd_Seq,      nullptr);
    host->RegisterSubcommand(selfId, "slotseed", "$rng slotseed <t> <s>",  u8"为随机点指定独立种子",           &Cmd_SlotSeed, nullptr);
    host->RegisterSubcommand(selfId, "bypass",   "$rng bypass <target>",   u8"让指定点走原版随机",             &Cmd_Bypass,   nullptr);
    host->RegisterSubcommand(selfId, "clear",    "$rng clear <target>",    u8"恢复指定点为跟随总种子",         &Cmd_Clear,    nullptr);
    return true;
}

MHW_RNG_PLUGIN_EXPORT void MhwRngPlugin_Shutdown() {
    std::lock_guard<std::mutex> lk(g_idxMx);
    g_indexedRvas.clear();
    g_host   = nullptr;
    g_selfId = 0U;
}
