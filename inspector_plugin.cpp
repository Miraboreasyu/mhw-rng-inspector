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
#include "mhw_rng_math.h"
#include "mhw_world_api.h"
#include "mhw_catalog_api.h"

#include <windows.h>
#include <algorithm>
#include <atomic>
#include <cctype>
#include <cmath>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <intrin.h>
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
    const char*   enDesc;
    const char*   techSym;
};

struct CatalogFuncRange {
    std::uint32_t rvaLo;
    std::uint32_t rvaHi;
    std::uint8_t  category;
    std::uint8_t  scaleKind;
    const char*   baseAlias;
    const char*   cnDesc;
    const char*   enDesc;
    const char*   techSym;
};

struct ShortcutAliasEntry {
    const char* key;
    const char* targetPattern;
    const char* cnDesc;
    const char* enDesc;
};

#include "rng_catalog_data.inl"

constexpr std::size_t   kCatalogSiteCount = sizeof(kCatalogSites) / sizeof(kCatalogSites[0]);
constexpr std::size_t   kFuncRangeCount   = sizeof(kCatalogFuncRanges) / sizeof(kCatalogFuncRanges[0]);
constexpr std::size_t   kShortcutCount    = sizeof(kBuiltinShortcuts) / sizeof(kBuiltinShortcuts[0]);

// Open-interval `(0.0f, 100.0f)` IEEE-754 bounds for `kScaleFloat100`:
using mhw_sdk::kMinSafeFloatU32;
using mhw_sdk::kMaxSafeFloatU32;

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

inline bool IsEn() noexcept {
    return MhwRng_HostIsEnglish(g_host);
}

const char* CategoryName(std::uint8_t cat, bool en) noexcept {
    switch (cat) {
        case kCatEmStat:   return en ? "Monster Stat" : u8"怪物数值";
        case kCatEmAi:     return en ? "Monster AI"   : u8"怪物AI";
        case kCatEmAct:    return en ? "Monster Act"  : u8"怪物招式";
        case kCatQuest:    return en ? "Quest/Invest" : u8"任务调查";
        case kCatPlayer:   return en ? "Player/Ammo"  : u8"猎人弹道";
        case kCatOtomo:    return en ? "Palico/Mount" : u8"随从骑乘";
        case kCatLoot:     return en ? "Carve/Loot"   : u8"剥取报酬";
        case kCatHub:      return en ? "Hub/Meld"     : u8"猫饭炼金";
        case kCatBgAnimal: return en ? "Endemic"      : u8"环境生物";
        case kCatBgStage:  return en ? "Stage/Hub"    : u8"据点机关";
        case kCatBgUi:     return en ? "UI/Damage"    : u8"UI跳字";
        case kCatBgVfx:    return en ? "VFX/Audio"    : u8"特效音效";
        default:           return en ? "Other"        : u8"底层其它";
    }
}

bool __fastcall InspectorMetaResolver(std::uint32_t rva, MhwRngSiteMeta* outMeta, void*) {
    if (!outMeta) return false;
    std::memset(outMeta, 0, sizeof(*outMeta));
    outMeta->rva = rva;
    const bool en = IsEn();

    if (const CatalogSiteEntry* exact = BinarySearchSite(rva)) {
        outMeta->category       = exact->category;
        outMeta->scaleKind      = exact->scaleKind;
        outMeta->isCoreGameplay = (exact->category <= kCatHub) ? 1U : 0U;
        outMeta->found          = 1U;
        CopyTrunc(outMeta->alias, sizeof(outMeta->alias), exact->alias);
        CopyTrunc(outMeta->description, sizeof(outMeta->description),
                  MhwRng_Tr(g_host, exact->cnDesc, exact->enDesc));
        CopyTrunc(outMeta->techSymbol, sizeof(outMeta->techSymbol), exact->techSym);
        return true;
    }

    if (const CatalogFuncRange* fr = BinarySearchFuncRange(rva)) {
        outMeta->category       = fr->category;
        outMeta->scaleKind      = fr->scaleKind;
        outMeta->isCoreGameplay = (fr->category <= kCatHub) ? 1U : 0U;
        outMeta->found          = 1U;
        std::snprintf(outMeta->alias, sizeof(outMeta->alias), "%s@%X", fr->baseAlias, rva);
        CopyTrunc(outMeta->description, sizeof(outMeta->description),
                  MhwRng_Tr(g_host, fr->cnDesc, fr->enDesc));
        CopyTrunc(outMeta->techSymbol, sizeof(outMeta->techSymbol), fr->techSym);
        return true;
    }

    outMeta->category       = (rva < 0x2400000U) ? kCatBgOther : kCatBgVfx;
    outMeta->scaleKind      = (rva < 0x80000000U) ? kScaleIntMod : kScaleRawU32;
    outMeta->isCoreGameplay = 0U;
    outMeta->found          = 1U;
    std::snprintf(outMeta->alias, sizeof(outMeta->alias), "rva.%07X", rva);
    CopyTrunc(outMeta->description, sizeof(outMeta->description),
              (rva < 0x80000000U) ? (en ? "Dynamic/range RNG site" : u8"动态/区间调用随机点")
                                  : (en ? "External module RNG site" : u8"外部模块调用随机点"));
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
            shortcutDesc = MhwRng_Tr(g_host, kBuiltinShortcuts[i].cnDesc, kBuiltinShortcuts[i].enDesc);
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
            const bool en = IsEn();
            outLabel = !shortcutDesc.empty()
                           ? (token + " -> " + shortcutDesc + (en ? " (" : u8" (共") + std::to_string(outRvas.size()) + (en ? " sites)" : u8"处)"))
                           : (effectivePat + (en ? " (" : u8" (共") + std::to_string(outRvas.size()) + (en ? " sites)" : u8"处)"));
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
    return mhw_sdk::PercentToOpenSafeU32(pct);
}

bool ParseSmartValue(const std::string& rawTok,
                     std::uint8_t scaleKind,
                     std::uint32_t& outVal,
                     std::string* outExplain) {
    const std::string tok = TrimStr(rawTok);
    if (tok.empty()) return false;
    const std::string low = LowerAscii(tok);
    const bool en = IsEn();

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
            explain(en ? "min safe float +0.0/100 (0x00000001)" : u8"最小安全浮点档 +0.0/100 (0x00000001)");
        } else {
            outVal = 0U;
            explain(en ? "min 0" : u8"最小档 0");
        }
        return true;
    }
    if (low == "mid" || low == "half") {
        outVal = (scaleKind == kScaleMod100) ? 50U : 0x80000000U;
        explain(scaleKind == kScaleMod100
                    ? (en ? "mid rem 50/99" : u8"中间档 余50/99")
                    : (en ? "mid 50.0/100" : u8"中间档 50.0/100"));
        return true;
    }
    if (low == "max") {
        outVal = (scaleKind == kScaleMod100)
                     ? 99U
                     : (scaleKind == kScaleFloat100 ? kMaxSafeFloatU32 : 0xFFFFFFFFU);
        explain(scaleKind == kScaleMod100
                    ? (en ? "max rem 99/99" : u8"最大余数 99/99")
                    : (en ? "max safe 100.0/100 (0xFFFFFF00)" : u8"最大安全档 100.0/100 (0xFFFFFF00)"));
        return true;
    }
    if (low.rfind("raw:", 0) == 0) {
        if (!ParseU32Strict(tok.c_str() + 4, outVal)) return false;
        explain(en ? "raw u32=%u (0x%08X)" : u8"原始u32=%u (0x%08X)", outVal, outVal);
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
        explain(en ? "pct=%.1f%% (0x%08X)" : u8"比例换算=%.1f%% (0x%08X)", p, outVal);
        return true;
    }
    if (scaleKind == kScaleFloat100) {
        char* ep = nullptr;
        const double num = std::strtod(tok.c_str(), &ep);
        if (ep != tok.c_str() && std::isfinite(num)) {
            while (*ep && std::isspace(static_cast<unsigned char>(*ep))) ++ep;
            if (*ep == '\0' && num >= 0.0 && num <= 100.0) {
                outVal = PctToSafeFloatU32(num);
                explain(en ? "float=%.1f/100 (0x%08X)" : u8"浮点换算=%.1f/100 (0x%08X)", num, outVal);
                return true;
            }
        }
    }

    std::uint32_t u32 = 0;
    if (!ParseU32Strict(tok.c_str(), u32)) return false;
    if (scaleKind == kScaleMod100 && u32 == 100U) {
        outVal = 99U;
        explain(en ? "mod100 max rem=99/99" : u8"模100最大余数=99/99");
        return true;
    }
    outVal = u32;
    explain(scaleKind == kScaleMod100
                ? (en ? "mod100 rem=%u/99" : u8"模100余数=%u/99")
                : (en ? "int=%u" : u8"整数=%u"),
            scaleKind == kScaleMod100 ? static_cast<unsigned>(outVal % 100U) : outVal);
    return true;
}

void FormatModeCn(const MhwRngSlotSnapshot& s, std::uint8_t scaleKind, char* buf, std::size_t cap) {
    if (g_host && g_host->FormatSlotCustom(&s, buf, cap)) return;
    const bool en = IsEn();
    switch (s.mode) {
        case kMhwRngSlotFixedValue:
            if (scaleKind == kScaleFloat100) {
                std::snprintf(buf, cap, en ? "Fixed=%.1f/100" : u8"固定=%.1f/100",
                              (static_cast<double>(s.fixedValue) * 100.0) / 4294967296.0);
            } else if (scaleKind == kScaleMod100) {
                std::snprintf(buf, cap, en ? "Fixed rem=%u" : u8"固定余数=%u",
                              static_cast<unsigned>(s.fixedValue % 100U));
            } else {
                std::snprintf(buf, cap, en ? "Fixed=%u" : u8"固定值=%u", s.fixedValue);
            }
            break;
        case kMhwRngSlotCustomSeed:
            std::snprintf(buf, cap, en ? "Seed=%llu" : u8"独立种子=%llu", static_cast<unsigned long long>(s.customSeed));
            break;
        case kMhwRngSlotSequence: {
            const char* pol = en
                                  ? ((s.seqEndPolicy == kMhwRngSeqHoldLast)
                                         ? "Hold"
                                         : (s.seqEndPolicy == kMhwRngSeqFallbackDerived ? "PRNG" : "Loop"))
                                  : ((s.seqEndPolicy == kMhwRngSeqHoldLast)
                                         ? u8"停住"
                                         : (s.seqEndPolicy == kMhwRngSeqFallbackDerived ? u8"转随机" : u8"循环"));
            std::snprintf(buf, cap, en ? "Seq[%u/%u %s]" : u8"序列[%u/%u %s]", s.seqCursor, s.seqLength, pol);
            break;
        }
        case kMhwRngSlotBypass:
            std::snprintf(buf, cap, en ? "Vanilla" : u8"原版直通");
            break;
        default:
            std::snprintf(buf, cap, s.hasPluginHook ? (en ? "Plugin hook" : u8"插件动态回调")
                                                    : (en ? "Master-derived" : u8"跟随总种子"));
            break;
    }
}

void FormatValCn(std::uint32_t val, std::uint8_t scaleKind, char* buf, std::size_t cap) {
    const bool en = IsEn();
    const double pct = (static_cast<double>(val) * 100.0) / 4294967296.0;
    const unsigned rem100 = static_cast<unsigned>(val % 100U);
    if (scaleKind == kScaleFloat100) {
        std::snprintf(buf, cap, en ? "[Float 0~100] %5.1f  (0x%08X)" : u8"[浮点0~100] %5.1f  (0x%08X)", pct, val);
    } else if (scaleKind == kScaleMod100) {
        std::snprintf(buf, cap, en ? "[Mod100] rem %02u/99 (0x%08X)" : u8"[模100抽签] 余%02u/99 (0x%08X)", rem100, val);
    } else if (scaleKind == kScaleIntMod) {
        std::snprintf(buf, cap, en ? "[IntMod] %%100:%02u %4.0f%% (0x%08X)" : u8"[整数取模] 余100:%02u %4.0f%% (0x%08X)", rem100, pct, val);
    } else {
        std::snprintf(buf, cap, en ? "[u32 Seed] 0x%08X (%10u)" : u8"[32位种子] 0x%08X (%10u)", val, val);
    }
}

// ============================================================================
//  Subcommand Handlers (`names`, `top`, `find`, `list`, `info`, `dump`,
//                       `fix`, `seq`, `slotseed`, `bypass`, `clear`)
// ============================================================================

void __fastcall Cmd_Names(int, const char* const*, const char*, void*) {
    if (!g_host) return;
    if (IsEn()) {
        g_host->ChatPrint("[inspector] Monster: size(crown/size) dying(limp) think(AI move) target(aggro) dung(dung pod)");
        g_host->ChatPrint("[inspector] Quest/Hub: quest(quest) bonus(weather) meal(canteen) daily(daily skill) meld(melder)");
        g_host->ChatPrint("[inspector] Drops/Aug: carve(carve) shiny(drop) reward(rewards) item(item table) awaken(Safi awaken)");
        g_host->ChatPrint("[inspector] Boss AI: fatalis alatreon velkhana nergi rajang safi | Dedicated size plugin: `$rng size`");
    } else {
        g_host->ChatPrint(u8"[inspector] 怪物: size(体型) dying(濒死) think(出招分支) target(仇恨) dung(异臭弹)");
        g_host->ChatPrint(u8"[inspector] 任务/据点: quest(接任务) bonus(天气) meal(猫饭) daily(每日猫饭) meld(炼金)");
        g_host->ChatPrint(u8"[inspector] 掉落/洗练: carve(剥取) shiny(掉落物) reward(报酬) item(道具表) awaken(觉醒)");
        g_host->ChatPrint(u8"[inspector] 专属怪: fatalis alatreon velkhana nergi rajang safi | 专用体型插件: `$rng size`");
    }
}

void __fastcall Cmd_Top(int argc, const char* const* argv, const char*, void*) {
    if (!g_host) return;
    const bool en = IsEn();
    bool includeBg = false;
    std::size_t maxShow = 6U;
    for (int i = 0; i < argc; ++i) {
        const std::string t = LowerAscii(argv[i]);
        if (t == "all") {
            includeBg = true;
        } else {
            std::uint32_t n = 0;
            if (!ParseU32Strict(t.c_str(), n) || n == 0U) {
                g_host->ChatPrintf(en ? "[inspector] Usage: `$rng top [1~20] [all]` (unknown arg `%s`)"
                                      : u8"[inspector] 用法: `$rng top [1~20] [all]` (未知参数 `%s`)",
                                   argv[i]);
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
        g_host->ChatPrint(en ? "[inspector] No core gameplay RNG sites triggered this epoch (try an action, or `$rng top all`)"
                             : u8"[inspector] 本轮未触发核心玩法随机点 (做个动作再试，或输 `$rng top all` 含背景)");
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
    g_host->ChatPrintf(en ? "[inspector] %s sites this epoch: %zu total (top %zu, selectable via `#idx`):"
                          : u8"[inspector] 本轮%s随机点共 %zu 处 (前 %zu 处，可直接 `#序号` 点名)：",
                       en ? (includeBg ? "Active" : "Core") : (includeBg ? u8"活跃" : u8"核心"),
                       items.size(), showN);
    for (std::size_t i = 0; i < showN; ++i) {
        const auto& it = items[i];
        const double pct = (static_cast<double>(it.snap.lastValue) * 100.0) / 4294967296.0;
        const unsigned rem = static_cast<unsigned>(it.snap.lastValue % 100U);
        char condTag[24]{};
        if (it.snap.condId != 0U) std::snprintf(condTag, sizeof(condTag), "[C:%u]", it.snap.condId);
        if (it.meta.scaleKind == kScaleFloat100) {
            g_host->ChatPrintf(en ? "#%u %s%s [%s] %llu draws | Float:%.1f/100"
                                  : u8"#%u %s%s [%s] %llu次 | 浮点:%.1f/100",
                               itemOneBasedIdx[i], it.meta.alias, condTag, it.meta.description,
                               static_cast<unsigned long long>(it.snap.epochCalls), pct);
        } else {
            g_host->ChatPrintf(en ? "#%u %s%s [%s] %llu draws | %%100:%02u (%.0f%%)"
                                  : u8"#%u %s%s [%s] %llu次 | 余100:%02u (%.0f%%)",
                               itemOneBasedIdx[i], it.meta.alias, condTag, it.meta.description,
                               static_cast<unsigned long long>(it.snap.epochCalls), rem, pct);
        }
    }
}

void __fastcall Cmd_Find(int argc, const char* const* argv, const char*, void*) {
    if (!g_host) return;
    const bool en = IsEn();
    if (argc < 1 || argv[0][0] == '\0') {
        g_host->ChatPrint(en ? "[inspector] Usage: `$rng find <keyword>` (e.g. `$rng find meal` or `$rng find fatalis`)"
                             : u8"[inspector] 用法: `$rng find <keyword>` (例: `$rng find meal` 或 `$rng find fatalis`)");
        return;
    }
    const std::string kwLow = LowerAscii(argv[0]);
    std::vector<std::uint32_t> indexed;
    std::size_t printed = 0U;

    for (std::size_t i = 0; i < kShortcutCount && printed < 6U; ++i) {
        if (ContainsSubstringI(kBuiltinShortcuts[i].key, kwLow) ||
            ContainsSubstringI(kBuiltinShortcuts[i].targetPattern, kwLow) ||
            ContainsSubstringI(kBuiltinShortcuts[i].cnDesc, kwLow) ||
            ContainsSubstringI(kBuiltinShortcuts[i].enDesc, kwLow)) {
            const char* desc = MhwRng_Tr(g_host, kBuiltinShortcuts[i].cnDesc, kBuiltinShortcuts[i].enDesc);
            g_host->ChatPrintf(en ? "[inspector] Shortcut `%s` -> %s : %s"
                                  : u8"[inspector] 短词 `%s` -> %s : %s",
                               kBuiltinShortcuts[i].key, kBuiltinShortcuts[i].targetPattern, desc);
            ++printed;
        }
    }
    for (int pass = 0; pass < 2 && printed < 6U; ++pass) {
        for (std::size_t i = 0; i < kCatalogSiteCount && printed < 6U; ++i) {
            const bool isCore = (kCatalogSites[i].category <= kCatHub);
            if ((pass == 0) != isCore) continue;
            if (ContainsSubstringI(kCatalogSites[i].alias, kwLow) ||
                ContainsSubstringI(kCatalogSites[i].cnDesc, kwLow) ||
                ContainsSubstringI(kCatalogSites[i].enDesc, kwLow) ||
                ContainsSubstringI(kCatalogSites[i].techSym, kwLow)) {
                indexed.push_back(kCatalogSites[i].rva);
                const char* desc = MhwRng_Tr(g_host, kCatalogSites[i].cnDesc, kCatalogSites[i].enDesc);
                g_host->ChatPrintf("[inspector] #%zu %s : %s",
                                   indexed.size(), kCatalogSites[i].alias, desc);
                ++printed;
            }
        }
    }
    if (!indexed.empty()) UpdateIndexedRvas(indexed);
    if (printed == 0U) {
        g_host->ChatPrintf(en ? "[inspector] No RNG site matches `%s`" : u8"[inspector] 未找到匹配 `%s` 的随机点", argv[0]);
    }
}

void __fastcall Cmd_List(int, const char* const*, const char*, void*) {
    if (!g_host) return;
    const bool en = IsEn();
    const auto snaps = CaptureActiveSlots();

    std::vector<MhwRngSlotSnapshot> ovrs;
    for (const auto& s : snaps) {
        if (s.mode != kMhwRngSlotMasterDerived || (s.condId == 0U && s.hasPluginHook != 0U)) {
            ovrs.push_back(s);
        }
    }
    if (ovrs.empty()) {
        g_host->ChatPrint(en ? "[inspector] No active override rules or conditional hooks"
                             : u8"[inspector] 当前无任何激活的锁定规则或条件钩子");
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
    g_host->ChatPrintf(en ? "[inspector] Active rules: %zu total:" : u8"[inspector] 当前共激活 %zu 处规则：", ovrs.size());
    for (std::size_t i = 0; i < showN; ++i) {
        MhwRngSiteMeta m{};
        g_host->QuerySiteMeta(ovrs[i].callSiteRva, &m);
        char modeBuf[80]{};
        FormatModeCn(ovrs[i], m.scaleKind, modeBuf, sizeof(modeBuf));
        char condTag[24]{};
        if (ovrs[i].condId != 0U) std::snprintf(condTag, sizeof(condTag), "[Cond:%u]", ovrs[i].condId);
        g_host->ChatPrintf(en ? "[%s] %s%s (%s) = %s [epoch %llu]"
                              : u8"[%s] %s%s (%s) = %s [本轮%llu次]",
                           g_host->GetPluginShortName(ovrs[i].ownerPluginId),
                           m.alias, condTag, m.description, modeBuf,
                           static_cast<unsigned long long>(ovrs[i].epochCalls));
    }
    if (ovrs.size() > showN) {
        g_host->ChatPrintf(en ? "[inspector] ...and %zu more active rule(s) (`$rng dump` for full table)"
                              : u8"[inspector] ...另有 %zu 处规则激活 (输 `$rng dump` 导出完整详表)", ovrs.size() - showN);
    }
}

void __fastcall Cmd_Info(int argc, const char* const* argv, const char*, void*) {
    if (!g_host) return;
    const bool en = IsEn();
    if (argc < 1) {
        g_host->ChatPrint(en ? "[inspector] Usage: `$rng info <target|#idx> [condId]`"
                             : u8"[inspector] 用法: `$rng info <target|#idx> [condId]`");
        return;
    }
    std::vector<std::uint32_t> rvas;
    std::string label;
    if (!ResolveTarget(argv[0], rvas, label) || rvas.empty()) {
        g_host->ChatPrintf(en ? "[inspector] Target `%s` not found" : u8"[inspector] 找不到目标 `%s`", argv[0]);
        return;
    }
    std::uint32_t cond = 0U;
    if (argc >= 2 && !ParseU32Strict(argv[1], cond)) {
        g_host->ChatPrintf(en ? "[inspector] Invalid condId: `%s`" : u8"[inspector] 无效条件编号(condId): `%s`", argv[1]);
        return;
    }

    const std::uint32_t rva = rvas[0];
    MhwRngSiteMeta m{};
    g_host->QuerySiteMeta(rva, &m);
    MhwRngSlotSnapshot snap{};
    if (!g_host->GetCondSlotInfo(rva, cond, &snap)) {
        g_host->ChatPrintf(en ? "[inspector] %s [Cond:%u] (0x%07X) not triggered yet"
                              : u8"[inspector] %s [Cond:%u] (0x%07X) 尚未触发",
                           m.alias, cond, rva);
        return;
    }
    char modeBuf[80]{}, valBuf[96]{};
    FormatModeCn(snap, m.scaleKind, modeBuf, sizeof(modeBuf));
    FormatValCn(snap.lastValue, m.scaleKind, valBuf, sizeof(valBuf));
    g_host->ChatPrintf(en ? "[inspector] %s [Cond:%u | owner:%s] %s | epoch %llu | %s"
                          : u8"[inspector] %s [Cond:%u | 归属:%s] %s | 本轮%llu次 | %s",
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

    const bool en = IsEn();
    SYSTEMTIME st{};
    ::GetLocalTime(&st);
    const std::uint64_t seed = g_host->GetMasterSeed();
    std::fprintf(f, "========================================================================================================================\r\n");
    std::fprintf(f, en ? " Monster Hunter World: Iceborne (15.23) - RNG Microkernel & Plugin Dump (rng_inspector.dll)\r\n"
                       : u8" 怪物猎人：世界 冰原 (15.23) — RNG 微内核 + 插件体系 触发详表 (由 rng_inspector.dll 生成)\r\n");
    const std::uint32_t engMode = g_host->GetEngineMode();
    const char* modeStr = (engMode == kMhwRngModeTakeover)
                              ? (en ? "Takeover" : u8"全局接管")
                              : ((engMode == kMhwRngModeSelective)
                                     ? (en ? "Selective" : u8"按需接管")
                                     : ((engMode == kMhwRngModeObserveOnly) ? (en ? "ObserveOnly" : u8"仅观测") : (en ? "Off" : u8"关闭")));
    std::fprintf(f, en ? " Generated: %04d-%02d-%02d %02d:%02d:%02d  |  Mode:%s  |  MasterSeed:%llu (0x%llX)  |  Epoch %llu\r\n"
                       : u8" 生成时间 : %04d-%02d-%02d %02d:%02d:%02d  |  模式:%s  |  总种子:%llu (0x%llX)  |  第 %llu 轮\r\n",
                 st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond,
                 modeStr,
                 static_cast<unsigned long long>(seed), static_cast<unsigned long long>(seed),
                 static_cast<unsigned long long>(g_host->GetEpoch()));
    std::fprintf(f, en ? " Summary  : %u active (RVA,Cond) slots  =  Active overrides/hooks %zu  |  Core %zu  |  Background %zu\r\n"
                       : u8" 概览统计 : 共 %u 个活跃(RVA,Cond)槽  =  激活规则/插件钩子 %zu 处  |  核心玩法 %zu 处  |  背景环境/特效 %zu 处\r\n",
                 outCount, ovrRows.size(), coreRows.size(), bgRows.size());
    {
        char worldBuf[128]{};
        if (MhwWorld_TryFormatSummary(g_host, worldBuf, sizeof(worldBuf), en)) {
            std::fprintf(f, en ? " World    : %s\r\n" : u8" 世界状态 : %s\r\n", worldBuf);
        }
    }
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
            std::snprintf(valBuf, sizeof(valBuf), en ? "(not triggered yet)                 "
                                                     : u8"（尚未触发抽取）                    ");
        } else {
            const std::uint32_t v = (r.snap.totalCalls == 0ULL && r.snap.mode == kMhwRngSlotFixedValue)
                                        ? r.snap.fixedValue
                                        : r.snap.lastValue;
            FormatValCn(v, r.meta.scaleKind, valBuf, sizeof(valBuf));
        }
        std::fprintf(f,
                     en ? "  %-6s %-24s [%-12s | %-9s] %-18s | epoch:%6llu (tot:%7llu) | %s | %s [0x%07X %s]\r\n"
                        : "  %-6s %-24s [%-12s | %-9s] %-18s | " u8"本轮:%6llu次 (总:%7llu) | %s | %s [0x%07X %s]\r\n",
                     idxBuf, aliasCond, CategoryName(r.meta.category, en),
                     g_host->GetPluginShortName(r.snap.ownerPluginId),
                     modeBuf,
                     static_cast<unsigned long long>(r.snap.epochCalls),
                     static_cast<unsigned long long>(r.snap.totalCalls),
                     valBuf, r.meta.description, r.snap.callSiteRva, r.meta.techSymbol);
    };

    std::fprintf(f, en ? "[1. Active Plugin Hooks / Conditional Overrides (%zu)]\r\n"
                       : u8"【一、当前激活的插件钩子 / 条件锁定规则（共 %zu 处）】\r\n", ovrRows.size());
    if (ovrRows.empty()) std::fprintf(f, en ? "  (none)\r\n\r\n" : u8"  （无）\r\n\r\n");
    else { for (const auto& r : ovrRows) writeRow(r); std::fprintf(f, "\r\n"); }

    std::fprintf(f, en ? "[2. Core Gameplay RNG Sites This Epoch (%zu)]\r\n"
                       : u8"【二、本轮核心玩法随机点（共 %zu 处）】\r\n", coreRows.size());
    if (coreRows.empty()) std::fprintf(f, en ? "  (none triggered yet)\r\n\r\n" : u8"  （尚未触发核心随机点）\r\n\r\n");
    else { for (const auto& r : coreRows) writeRow(r); std::fprintf(f, "\r\n"); }

    std::fprintf(f, en ? "[3. Background / Ambient RNG Sites (%zu)]\r\n"
                       : u8"【三、背景环境与视觉特效随机点（共 %zu 处）】\r\n", bgRows.size());
    if (bgRows.empty()) std::fprintf(f, en ? "  (none)\r\n" : u8"  （无）\r\n");
    else { for (const auto& r : bgRows) writeRow(r); }

    std::fclose(f);
    return true;
}

void __fastcall Cmd_Dump(int, const char* const*, const char* rawArgStr, void*) {
    if (!g_host) return;
    const bool en = IsEn();
    std::string customPath = rawArgStr ? TrimStr(rawArgStr) : "";
    if (customPath.size() >= 2U &&
        ((customPath.front() == '"' && customPath.back() == '"') ||
         (customPath.front() == '\'' && customPath.back() == '\''))) {
        customPath = customPath.substr(1U, customPath.size() - 2U);
    }
    const std::string path = !customPath.empty()
                                 ? customPath
                                 : (std::string(g_host->GetRootPluginDir()) + "\\mhw_rng_dump.txt");
    std::uint32_t cnt = 0;
    if (WriteDumpFile(path, cnt)) {
        g_host->ChatPrintf(en ? "[inspector] Exported table -> mhw_rng_dump.txt (%u slots, selectable via #idx)"
                              : u8"[inspector] 已导出中文分类详表 -> mhw_rng_dump.txt (共%u槽，可直接用 #序号)", cnt);
    } else {
        g_host->ChatPrint(en ? "[inspector] Failed to export mhw_rng_dump.txt"
                             : u8"[inspector] 导出 mhw_rng_dump.txt 失败");
    }
}

void __fastcall Cmd_Fix(int argc, const char* const* argv, const char*, void*) {
    if (!g_host) return;
    const bool en = IsEn();
    if (argc < 2 || argc > 3) {
        g_host->ChatPrint(en ? "[inspector] Usage: `$rng fix <target|#idx> <0~100|min|mid|max|raw:u32> [condId]`"
                             : u8"[inspector] 用法: `$rng fix <target|#idx> <0~100|min|mid|max|raw:u32> [condId]`");
        return;
    }
    std::vector<std::uint32_t> rvas;
    std::string label;
    if (!ResolveTarget(argv[0], rvas, label) || rvas.empty()) {
        g_host->ChatPrintf(en ? "[inspector] Target `%s` not found" : u8"[inspector] 找不到目标 `%s`", argv[0]);
        return;
    }
    std::uint32_t cond = 0U;
    if (argc >= 3 && !ParseU32Strict(argv[2], cond)) {
        g_host->ChatPrintf(en ? "[inspector] Invalid condId: `%s`" : u8"[inspector] 无效条件编号(condId): `%s`", argv[2]);
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
            g_host->ChatPrintf(en ? "[inspector] Invalid value `%s`" : u8"[inspector] 无效数值 `%s`", argv[1]);
            return;
        }
        plan.emplace_back(rvas[i], val);
    }

    for (const auto& kv : plan) {
        g_host->SetCondFixedValue(g_selfId, kv.first, cond, kv.second);
    }
    g_host->ChatPrintf(en ? "[inspector] Locked %s [Cond:%u] -> %s" : u8"[inspector] 已锁定 %s [Cond:%u] -> %s",
                       label.c_str(), cond, explain.c_str());
}

void __fastcall Cmd_Seq(int argc, const char* const* argv, const char*, void*) {
    if (!g_host) return;
    const bool en = IsEn();
    if (argc < 2 || argc > 4) {
        g_host->ChatPrint(en ? "[inspector] Usage: `$rng seq <target|#idx> <v1,v2,...> [loop|hold|prng] [condId]`"
                             : u8"[inspector] 用法: `$rng seq <target|#idx> <v1,v2,...> [loop|hold|prng] [condId]`");
        return;
    }
    std::vector<std::uint32_t> rvas;
    std::string label;
    if (!ResolveTarget(argv[0], rvas, label) || rvas.empty()) {
        g_host->ChatPrintf(en ? "[inspector] Target `%s` not found" : u8"[inspector] 找不到目标 `%s`", argv[0]);
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
        g_host->ChatPrint(en ? "[inspector] Sequence cannot be empty (e.g. `10,50,90`)"
                             : u8"[inspector] 序列不能为空 (例: `10,50,90`)");
        return;
    }

    std::uint8_t  pol      = kMhwRngSeqLoop;
    const char*   polLabel = en ? "loop" : u8"循环";
    std::uint32_t cond     = 0U;

    if (argc >= 3) {
        const std::string p = LowerAscii(argv[2]);
        if (p == "loop") {
            pol = kMhwRngSeqLoop; polLabel = en ? "loop" : u8"循环";
        } else if (p == "hold") {
            pol = kMhwRngSeqHoldLast; polLabel = en ? "hold last" : u8"停在末项";
        } else if (p == "prng" || p == "derived") {
            pol = kMhwRngSeqFallbackDerived; polLabel = en ? "fallback PRNG" : u8"播完转随机";
        } else if (argc == 3 && ParseU32Strict(argv[2], cond)) {
            // Convenient shorthand: `$rng seq <target> <v1,v2> <condId>`
        } else {
            g_host->ChatPrintf(en ? "[inspector] Invalid end policy `%s`; supported: loop / hold / prng"
                                  : u8"[inspector] 无效结束策略 `%s`；支持 loop / hold / prng", argv[2]);
            return;
        }
    }
    if (argc >= 4 && !ParseU32Strict(argv[3], cond)) {
        g_host->ChatPrintf(en ? "[inspector] Invalid condId: `%s`" : u8"[inspector] 无效条件编号(condId): `%s`", argv[3]);
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
                g_host->ChatPrintf(en ? "[inspector] Invalid sequence item: `%s`"
                                      : u8"[inspector] 序列项无效: `%s`", s.c_str());
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
    g_host->ChatPrintf(en ? "[inspector] %s [Cond:%u] -> sequence (%zu steps, %s)"
                          : u8"[inspector] 已设置 %s [Cond:%u] -> 序列(%zu步, %s)",
                       label.c_str(), cond, rawItems.size(), polLabel);
}

void __fastcall Cmd_SlotSeed(int argc, const char* const* argv, const char*, void*) {
    if (!g_host) return;
    const bool en = IsEn();
    if (argc < 2 || argc > 3) {
        g_host->ChatPrint(en ? "[inspector] Usage: `$rng slotseed <target|#idx> <seed> [condId]`"
                             : u8"[inspector] 用法: `$rng slotseed <target|#idx> <seed> [condId]`");
        return;
    }
    std::vector<std::uint32_t> rvas;
    std::string label;
    if (!ResolveTarget(argv[0], rvas, label) || rvas.empty()) {
        g_host->ChatPrintf(en ? "[inspector] Target `%s` not found" : u8"[inspector] 找不到目标 `%s`", argv[0]);
        return;
    }
    std::uint64_t seed = 0;
    if (!ParseU64Auto(argv[1], seed)) {
        g_host->ChatPrintf(en ? "[inspector] Invalid seed value: `%s`" : u8"[inspector] 无效种子数值: `%s`", argv[1]);
        return;
    }
    std::uint32_t cond = 0U;
    if (argc >= 3 && !ParseU32Strict(argv[2], cond)) {
        g_host->ChatPrintf(en ? "[inspector] Invalid condId: `%s`" : u8"[inspector] 无效条件编号(condId): `%s`", argv[2]);
        return;
    }
    for (const std::uint32_t rva : rvas) {
        g_host->SetCondCustomSeed(g_selfId, rva, cond, seed);
    }
    g_host->ChatPrintf(en ? "[inspector] %s [Cond:%u] -> slot seed %llu"
                          : u8"[inspector] %s [Cond:%u] -> 独立种子 %llu",
                       label.c_str(), cond, static_cast<unsigned long long>(seed));
}

void __fastcall Cmd_Bypass(int argc, const char* const* argv, const char*, void*) {
    if (!g_host) return;
    const bool en = IsEn();
    if (argc < 1 || argc > 2) {
        g_host->ChatPrint(en ? "[inspector] Usage: `$rng bypass <target|#idx> [condId]`"
                             : u8"[inspector] 用法: `$rng bypass <target|#idx> [condId]`");
        return;
    }
    std::vector<std::uint32_t> rvas;
    std::string label;
    if (!ResolveTarget(argv[0], rvas, label) || rvas.empty()) {
        g_host->ChatPrintf(en ? "[inspector] Target `%s` not found" : u8"[inspector] 找不到目标 `%s`", argv[0]);
        return;
    }
    std::uint32_t cond = 0U;
    if (argc >= 2 && !ParseU32Strict(argv[1], cond)) {
        g_host->ChatPrintf(en ? "[inspector] Invalid condId: `%s`" : u8"[inspector] 无效条件编号(condId): `%s`", argv[1]);
        return;
    }
    for (const std::uint32_t rva : rvas) {
        g_host->SetCondBypass(g_selfId, rva, cond);
    }
    g_host->ChatPrintf(en ? "[inspector] %s [Cond:%u] -> vanilla bypass"
                          : u8"[inspector] %s [Cond:%u] -> 原版直通", label.c_str(), cond);
}

void __fastcall Cmd_Clear(int argc, const char* const* argv, const char*, void*) {
    if (!g_host) return;
    const bool en = IsEn();
    if (argc < 1) {
        g_host->ChatPrint(en ? "[inspector] Usage: `$rng clear <target|#idx|all>`"
                             : u8"[inspector] 用法: `$rng clear <target|#idx|all>`");
        return;
    }
    if (LowerAscii(argv[0]) == "all") {
        g_host->ClearAllRules();
        g_host->ChatPrint(en ? "[inspector] Cleared all override rules" : u8"[inspector] 已清空全部覆盖规则");
        return;
    }
    std::vector<std::uint32_t> rvas;
    std::string label;
    if (!ResolveTarget(argv[0], rvas, label) || rvas.empty()) {
        g_host->ChatPrintf(en ? "[inspector] Target `%s` not found" : u8"[inspector] 找不到目标 `%s`", argv[0]);
        return;
    }
    for (const std::uint32_t rva : rvas) {
        g_host->ClearSlotAllConditions(rva);
    }
    g_host->ChatPrintf(en ? "[inspector] Restored %s -> master-derived"
                          : u8"[inspector] 已恢复 %s -> 跟随总种子", label.c_str());
}

// ============================================================================
//  Standardized Call-Site Stack Tracer (`$rng trace`)
// ============================================================================

constexpr std::size_t   kMaxTraceChains = 64U;
constexpr std::uint32_t kMaxTraceDepth  = 8U;

struct TraceChainRecord {
    bool          used        = false;
    std::uint32_t callSiteRva = 0U;
    std::uint8_t  sourceKind  = 0U;
    std::uint8_t  depth       = 0U;
    std::uint8_t  hasXmm      = 0U;
    std::uint32_t rvas[kMaxTraceDepth]{};
    std::uint64_t hits        = 0ULL;
    std::uint32_t lastVal     = 0U;
    float         lastXmm6    = 0.0f;
    float         lastXmm7    = 0.0f;
};

struct TraceSpinGuard {
    std::atomic_flag& flag;
    explicit TraceSpinGuard(std::atomic_flag& f) noexcept : flag(f) {
        while (flag.test_and_set(std::memory_order_acquire)) {
            _mm_pause();
        }
    }
    ~TraceSpinGuard() noexcept {
        flag.clear(std::memory_order_release);
    }
};

std::atomic_flag  g_traceLock         = ATOMIC_FLAG_INIT;
std::atomic<bool> g_traceActive{false};
bool              g_traceWildcardCore = false;
std::uint32_t     g_traceFilterRvas[kMaxTraceChains]{};
std::uint32_t     g_traceFilterCount  = 0U;
MhwRngHookHandle  g_traceObsHandle    = kMhwRngInvalidHandle;
TraceChainRecord  g_traceRecords[kMaxTraceChains]{};

bool IsCoreSiteStatic(std::uint32_t rva) noexcept {
    if (const CatalogSiteEntry* exact = BinarySearchSite(rva)) {
        return exact->category <= kCatHub;
    }
    if (const CatalogFuncRange* fr = BinarySearchFuncRange(rva)) {
        return fr->category <= kCatHub;
    }
    return false;
}

void __fastcall OnTraceObserver(const MhwRngDrawContext* ctx, void*) {
    if (!ctx || !g_host || !g_traceActive.load(std::memory_order_relaxed)) return;

    bool matched = false;
    {
        TraceSpinGuard lk(g_traceLock);
        if (g_traceWildcardCore) {
            matched = IsCoreSiteStatic(ctx->callSiteRva) ||
                      (ctx->origReturnRva != 0U && IsCoreSiteStatic(ctx->origReturnRva));
        } else {
            for (std::uint32_t i = 0; i < g_traceFilterCount; ++i) {
                const std::uint32_t f = g_traceFilterRvas[i];
                if (f == ctx->callSiteRva || (ctx->origReturnRva != 0U && f == ctx->origReturnRva)) {
                    matched = true;
                    break;
                }
            }
        }
    }
    if (!matched) return;

    std::uint32_t frames[kMaxTraceDepth]{};
    std::uint32_t n = MhwRng_HostCaptureCallerRvas(g_host, ctx, frames, kMaxTraceDepth);
    if (n == 0U && ctx->callSiteRva != 0U) {
        frames[0] = ctx->callSiteRva;
        n = 1U;
    }
    if (n == 0U) return;

    const bool hasXmm = ((ctx->callFlags & kMhwRngDrawFlagHasXmmRegs) != 0U && ctx->callerRegs != nullptr);
    const float xmm6Val = hasXmm ? ctx->callerRegs->xmm6.f32[0] : 0.0f;
    const float xmm7Val = hasXmm ? ctx->callerRegs->xmm7.f32[0] : 0.0f;

    TraceSpinGuard lk(g_traceLock);
    std::size_t emptyIdx     = kMaxTraceChains;
    std::size_t minHitsIdx   = 0U;
    std::uint64_t minHitsVal = ~0ULL;

    for (std::size_t i = 0; i < kMaxTraceChains; ++i) {
        TraceChainRecord& rec = g_traceRecords[i];
        if (!rec.used) {
            if (emptyIdx == kMaxTraceChains) emptyIdx = i;
            continue;
        }
        if (rec.hits < minHitsVal) {
            minHitsVal = rec.hits;
            minHitsIdx = i;
        }
        if (rec.callSiteRva == ctx->callSiteRva && rec.depth == n &&
            std::memcmp(rec.rvas, frames, static_cast<std::size_t>(n) * sizeof(std::uint32_t)) == 0) {
            ++rec.hits;
            rec.lastVal    = ctx->finalValue0;
            rec.sourceKind = ctx->sourceKind;
            if (hasXmm) {
                rec.hasXmm   = 1U;
                rec.lastXmm6 = xmm6Val;
                rec.lastXmm7 = xmm7Val;
            }
            return;
        }
    }

    const std::size_t dstIdx = (emptyIdx < kMaxTraceChains) ? emptyIdx : minHitsIdx;
    TraceChainRecord& dst = g_traceRecords[dstIdx];
    dst = TraceChainRecord{};
    dst.used        = true;
    dst.callSiteRva = ctx->callSiteRva;
    dst.sourceKind  = ctx->sourceKind;
    dst.depth       = static_cast<std::uint8_t>(n);
    dst.hasXmm      = hasXmm ? 1U : 0U;
    std::memcpy(dst.rvas, frames, static_cast<std::size_t>(n) * sizeof(std::uint32_t));
    dst.hits     = 1ULL;
    dst.lastVal  = ctx->finalValue0;
    dst.lastXmm6 = xmm6Val;
    dst.lastXmm7 = xmm7Val;
}

void StopTraceObserver() {
    g_traceActive.store(false, std::memory_order_release);
    if (g_host && g_traceObsHandle != kMhwRngInvalidHandle) {
        g_host->UnregisterGlobalObserver(g_selfId, g_traceObsHandle);
        g_traceObsHandle = kMhwRngInvalidHandle;
    }
}

void ClearTraceRecords() {
    TraceSpinGuard lk(g_traceLock);
    for (std::size_t i = 0; i < kMaxTraceChains; ++i) {
        g_traceRecords[i] = TraceChainRecord{};
    }
}

std::vector<TraceChainRecord> SnapshotSortedTraces() {
    std::vector<TraceChainRecord> out;
    out.reserve(kMaxTraceChains);
    {
        TraceSpinGuard lk(g_traceLock);
        for (std::size_t i = 0; i < kMaxTraceChains; ++i) {
            if (g_traceRecords[i].used && g_traceRecords[i].hits > 0ULL) {
                out.push_back(g_traceRecords[i]);
            }
        }
    }
    std::sort(out.begin(), out.end(), [](const TraceChainRecord& a, const TraceChainRecord& b) {
        if (a.hits != b.hits) return a.hits > b.hits;
        return a.callSiteRva < b.callSiteRva;
    });
    return out;
}

std::string FormatTraceRvaChain(const TraceChainRecord& rec) {
    std::string chain;
    for (std::uint8_t j = 0U; j < rec.depth; ++j) {
        if (j > 0U) chain += " <- ";
        char hbuf[16]{};
        std::snprintf(hbuf, sizeof(hbuf), "0x%X", rec.rvas[j]);
        chain += hbuf;
        if (const CatalogSiteEntry* exact = BinarySearchSite(rec.rvas[j])) {
            chain += "(";
            chain += exact->alias;
            chain += ")";
        } else if (const CatalogFuncRange* fr = BinarySearchFuncRange(rec.rvas[j])) {
            chain += "(";
            chain += fr->baseAlias;
            chain += ")";
        } else if (g_host) {
            MhwRngSiteMeta m{};
            if (g_host->QuerySiteMeta(rec.rvas[j], &m) && m.found &&
                m.alias[0] != '\0' && std::strncmp(m.alias, "rva.", 4) != 0) {
                chain += "(";
                chain += m.alias;
                chain += ")";
            }
        }
    }
    return chain;
}

bool WriteTraceDumpFile(const std::string& path, std::uint32_t& outCount) {
    const auto traces = SnapshotSortedTraces();
    outCount = static_cast<std::uint32_t>(traces.size());

    FILE* f = nullptr;
    fopen_s(&f, path.c_str(), "wb");
    if (!f) return false;

    static constexpr unsigned char kBom[3] = {0xEF, 0xBB, 0xBF};
    std::fwrite(kBom, 1, 3, f);

    const bool en = IsEn();
    SYSTEMTIME st{};
    ::GetLocalTime(&st);
    std::fprintf(f, "========================================================================================================================\r\n");
    std::fprintf(f, en ? " Monster Hunter World: Iceborne (15.23) - Call-Site Stack Trace Dump (rng_inspector.dll)\r\n"
                       : u8" 怪物猎人：世界 冰原 (15.23) — RNG 调用栈采集详表 (由 rng_inspector.dll 生成)\r\n");
    std::fprintf(f, en ? " Generated: %04d-%02d-%02d %02d:%02d:%02d  |  Unique Chains: %u\r\n"
                       : u8" 生成时间 : %04d-%02d-%02d %02d:%02d:%02d  |  唯一调用链: %u 组\r\n",
                 st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, outCount);
    std::fprintf(f, "========================================================================================================================\r\n\r\n");

    if (traces.empty()) {
        std::fprintf(f, en ? "  (no trace records captured yet)\r\n" : u8"  （尚未采集到调用栈记录）\r\n");
    } else {
        for (std::size_t i = 0; i < traces.size(); ++i) {
            const TraceChainRecord& rec = traces[i];
            const std::string chain = FormatTraceRvaChain(rec);
            if (rec.hasXmm) {
                std::fprintf(f, "  #%-3zu hits=%-6llu last=0x%08X (%u) xmm6=%.4g xmm7=%.4g | %s\r\n",
                             i + 1U, static_cast<unsigned long long>(rec.hits),
                             rec.lastVal, rec.lastVal,
                             static_cast<double>(rec.lastXmm6), static_cast<double>(rec.lastXmm7),
                             chain.c_str());
            } else {
                std::fprintf(f, "  #%-3zu hits=%-6llu last=0x%08X (%u) | %s\r\n",
                             i + 1U, static_cast<unsigned long long>(rec.hits),
                             rec.lastVal, rec.lastVal,
                             chain.c_str());
            }
        }
    }
    std::fclose(f);
    return true;
}

void PrintTraceLog(std::size_t maxShow) {
    if (!g_host) return;
    const bool en = IsEn();
    const auto traces = SnapshotSortedTraces();
    if (traces.empty()) {
        g_host->ChatPrint(en ? "[inspector] No call-stack traces captured yet (`$rng trace <target|#idx|*>`)"
                             : u8"[inspector] 暂未捕获任何调用栈记录 (先用 `$rng trace <目标|#序号|*>` 开启采集)");
        return;
    }

    std::vector<std::uint32_t> indexed;
    for (const auto& t : traces) PushUnique(indexed, t.callSiteRva);
    UpdateIndexedRvas(indexed);

    const std::size_t showN = std::min(traces.size(), maxShow);
    g_host->ChatPrintf(en ? "[inspector] Captured %zu call-stack chain(s) (showing top %zu):"
                          : u8"[inspector] 已捕获 %zu 组调用栈记录 (显示前 %zu 组)：",
                       traces.size(), showN);
    for (std::size_t i = 0; i < showN; ++i) {
        const TraceChainRecord& rec = traces[i];
        const std::string chain = FormatTraceRvaChain(rec);
        if (rec.hasXmm) {
            g_host->ChatPrintf("#%zu %s | %llu hits | 0x%08X | xmm6=%.2f xmm7=%.2f",
                               i + 1U, chain.c_str(),
                               static_cast<unsigned long long>(rec.hits), rec.lastVal,
                               static_cast<double>(rec.lastXmm6), static_cast<double>(rec.lastXmm7));
        } else {
            g_host->ChatPrintf("#%zu %s | %llu hits | 0x%08X",
                               i + 1U, chain.c_str(),
                               static_cast<unsigned long long>(rec.hits), rec.lastVal);
        }
    }
}

void __fastcall Cmd_Trace(int argc, const char* const* argv, const char* rawArgStr, void*) {
    if (!g_host) return;
    const bool en = IsEn();

    if (argc == 0) {
        if (!g_traceActive.load(std::memory_order_acquire) && SnapshotSortedTraces().empty()) {
            g_host->ChatPrint(en ? "[inspector] Usage: `$rng trace <target|#idx|*>` | `log [N]` | `dump [path]` | `off` | `clear`"
                                 : u8"[inspector] 用法: `$rng trace <目标|#序号|*>` | `log [N]` | `dump [path]` | `off` | `clear`");
            return;
        }
        PrintTraceLog(6U);
        return;
    }

    const std::string sub = LowerAscii(argv[0]);
    if (sub == "off" || sub == "stop") {
        StopTraceObserver();
        g_host->ChatPrint(en ? "[inspector] Call-stack trace stopped (results preserved; use `trace log` / `trace dump`)"
                             : u8"[inspector] 已停止调用栈追踪 (已采集记录已保留，可继续 `trace log` 或 `trace dump`)");
        return;
    }
    if (sub == "clear" || sub == "reset") {
        ClearTraceRecords();
        g_host->ChatPrint(en ? "[inspector] Trace buffer cleared" : u8"[inspector] 已清空调用栈追踪缓存");
        return;
    }
    if (sub == "log" || sub == "show" || sub == "list") {
        std::size_t n = 6U;
        if (argc >= 2) {
            std::uint32_t v = 0U;
            if (!ParseU32Strict(argv[1], v) || v == 0U) {
                g_host->ChatPrintf(en ? "[inspector] Invalid count `%s`" : u8"[inspector] 无效数量 `%s`", argv[1]);
                return;
            }
            n = std::min<std::size_t>(v, 20U);
        }
        PrintTraceLog(n);
        return;
    }
    if (sub == "dump") {
        std::string customPath;
        if (rawArgStr && rawArgStr[0] != '\0') {
            std::string rawTrim = TrimStr(rawArgStr);
            if (rawTrim.size() > 4U && LowerAscii(rawTrim.substr(0, 4U)) == "dump") {
                customPath = TrimStr(rawTrim.substr(4U));
                if (customPath.size() >= 2U &&
                    ((customPath.front() == '"' && customPath.back() == '"') ||
                     (customPath.front() == '\'' && customPath.back() == '\''))) {
                    customPath = customPath.substr(1U, customPath.size() - 2U);
                }
            }
        }
        const std::string path = !customPath.empty()
                                     ? customPath
                                     : (std::string(g_host->GetRootPluginDir()) + "\\mhw_rng_trace.txt");
        std::uint32_t cnt = 0U;
        if (WriteTraceDumpFile(path, cnt)) {
            g_host->ChatPrintf(en ? "[inspector] Exported %u call-stack trace(s) -> mhw_rng_trace.txt"
                                  : u8"[inspector] 已导出 %u 组调用栈记录 -> mhw_rng_trace.txt", cnt);
        } else {
            g_host->ChatPrint(en ? "[inspector] Failed to export mhw_rng_trace.txt"
                                 : u8"[inspector] 导出 mhw_rng_trace.txt 失败");
        }
        return;
    }

    const std::string targetArg = (sub == "on" && argc >= 2) ? argv[1] : argv[0];
    const std::string tLow      = LowerAscii(targetArg);

    bool wildcardCore = false;
    std::vector<std::uint32_t> rvas;
    std::string label;
    if (tLow == "*" || tLow == "all" || tLow == "core") {
        wildcardCore = true;
        label        = en ? "all core sites" : u8"全部核心随机点";
    } else if (!ResolveTarget(targetArg, rvas, label) || rvas.empty()) {
        g_host->ChatPrintf(en ? "[inspector] Target `%s` not found" : u8"[inspector] 找不到目标 `%s`", targetArg.c_str());
        return;
    }

    StopTraceObserver();
    ClearTraceRecords();
    {
        TraceSpinGuard lk(g_traceLock);
        g_traceWildcardCore = wildcardCore;
        g_traceFilterCount  = 0U;
        if (!wildcardCore) {
            for (const std::uint32_t r : rvas) {
                if (g_traceFilterCount >= kMaxTraceChains) break;
                g_traceFilterRvas[g_traceFilterCount++] = r;
            }
        }
    }

    if (g_host->GetEngineMode() == kMhwRngModeOff) {
        g_host->SetEngineMode(kMhwRngModeObserveOnly);
    }

    const std::uint32_t rvaFilter = (!wildcardCore && rvas.size() == 1U) ? rvas[0] : 0U;
    g_traceActive.store(true, std::memory_order_release);
    g_traceObsHandle = g_host->RegisterGlobalObserver(g_selfId, rvaFilter, 0U, &OnTraceObserver, nullptr);
    if (g_traceObsHandle == kMhwRngInvalidHandle) {
        g_traceActive.store(false, std::memory_order_release);
        g_host->ChatPrint(en ? "[inspector] Failed to register trace global observer"
                             : u8"[inspector] 注册全局调用栈观测器失败");
        return;
    }
    g_host->ChatPrintf(en ? "[inspector] Tracing started: %s (`$rng trace log` / `dump` / `off`)"
                          : u8"[inspector] 已开启调用栈追踪: %s (`$rng trace log` / `dump` / `off`)",
                       label.c_str());
}

void EmitInspectorTargets(const char* prefix, MhwRngCompletionSinkFn addCand, void* sinkCtx) {
    if (!addCand) return;
    for (std::size_t i = 0; i < kShortcutCount; ++i) {
        addCand(kBuiltinShortcuts[i].key, sinkCtx);
    }

    std::size_t idxCount = 0U;
    {
        std::lock_guard<std::mutex> lk(g_idxMx);
        idxCount = std::min<std::size_t>(g_indexedRvas.size(), 16U);
    }
    for (std::size_t i = 1U; i <= idxCount; ++i) {
        char idxBuf[16]{};
        std::snprintf(idxBuf, sizeof(idxBuf), "#%zu", i);
        addCand(idxBuf, sinkCtx);
    }

    if (g_host) {
        const auto snaps = CaptureActiveSlots();
        for (const auto& s : snaps) {
            MhwRngSiteMeta m{};
            if (g_host->QuerySiteMeta(s.callSiteRva, &m) && m.alias[0] != '\0') {
                const bool isOvr = (s.mode != kMhwRngSlotMasterDerived || s.hasPluginHook != 0U);
                if (m.isCoreGameplay != 0U || isOvr) {
                    addCand(m.alias, sinkCtx);
                }
            }
        }
    }

    const std::string prefLow = prefix ? LowerAscii(prefix) : std::string();
    if (prefLow.size() >= 2U) {
        std::size_t extra = 0U;
        for (std::size_t i = 0; i < kCatalogSiteCount && extra < 64U; ++i) {
            const char* al = kCatalogSites[i].alias;
            if (!al || al[0] == '\0') continue;
            bool match = true;
            for (std::size_t j = 0U; j < prefLow.size(); ++j) {
                char c = al[j];
                if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + ('a' - 'A'));
                if (c == '\0' || c != prefLow[j]) {
                    match = false;
                    break;
                }
            }
            if (match) {
                addCand(al, sinkCtx);
                ++extra;
            }
        }
    }
}

void __fastcall Complete_Inspector(const char* subcmd,
                                   int argc,
                                   const char* const* argv,
                                   const char* prefix,
                                   MhwRngCompletionSinkFn addCand,
                                   void* sinkCtx,
                                   void*) {
    if (!subcmd || !addCand) return;
    const std::string cmd = LowerAscii(subcmd);

    if (cmd == "names" || cmd == "list" || cmd == "dump") {
        return;
    }
    if (cmd == "top") {
        if (argc == 0) addCand("all", sinkCtx);
        return;
    }
    if (cmd == "find") {
        if (argc == 0) {
            for (std::size_t i = 0; i < kShortcutCount; ++i) {
                addCand(kBuiltinShortcuts[i].key, sinkCtx);
            }
        }
        return;
    }
    if (cmd == "info" || cmd == "bypass" || cmd == "slotseed") {
        if (argc == 0) EmitInspectorTargets(prefix, addCand, sinkCtx);
        return;
    }
    if (cmd == "clear") {
        if (argc == 0) {
            addCand("all", sinkCtx);
            EmitInspectorTargets(prefix, addCand, sinkCtx);
        }
        return;
    }
    if (cmd == "fix") {
        if (argc == 0) {
            EmitInspectorTargets(prefix, addCand, sinkCtx);
        } else if (argc == 1) {
            static const char* const kVals[] = { "min", "mid", "max", "raw:" };
            for (const char* v : kVals) addCand(v, sinkCtx);
        }
        return;
    }
    if (cmd == "seq") {
        if (argc == 0) {
            EmitInspectorTargets(prefix, addCand, sinkCtx);
        } else if (argc == 2) {
            static const char* const kPolicies[] = { "loop", "hold", "prng" };
            for (const char* p : kPolicies) addCand(p, sinkCtx);
        }
        return;
    }
    if (cmd == "trace") {
        if (argc == 0) {
            static const char* const kTraceTop[] = {
                "*", "all", "core", "log", "dump", "off", "clear", "on"
            };
            for (const char* t : kTraceTop) addCand(t, sinkCtx);
            EmitInspectorTargets(prefix, addCand, sinkCtx);
        } else if (argc == 1 && argv && argv[0] && LowerAscii(argv[0]) == "on") {
            addCand("*", sinkCtx);
            addCand("all", sinkCtx);
            addCand("core", sinkCtx);
            EmitInspectorTargets(prefix, addCand, sinkCtx);
        }
    }
}

bool __fastcall CatalogResolveAliasToRva(const char* aliasOrShortcut, std::uint32_t* outRva) {
    if (!aliasOrShortcut || aliasOrShortcut[0] == '\0' || !outRva) return false;
    *outRva = 0U;
    std::vector<std::uint32_t> rvas;
    std::string label;
    if (!ResolveTarget(aliasOrShortcut, rvas, label) || rvas.empty()) return false;
    *outRva = rvas[0];
    return *outRva != 0U;
}

bool __fastcall CatalogQuerySite(std::uint32_t rva, MhwRngSiteMeta* outMeta) {
    if (!outMeta || rva == 0U) return false;
    if (g_host && g_host->QuerySiteMeta) {
        return g_host->QuerySiteMeta(rva, outMeta);
    }
    return InspectorMetaResolver(rva, outMeta, nullptr);
}

const MhwCatalogApi kCatalogServiceApi = {
    kMhwCatalogServiceVersion,
    sizeof(MhwCatalogApi),
    &CatalogResolveAliasToRva,
    &CatalogQuerySite
};

const MhwRngPluginDescriptor kPluginDesc = {
    kMhwRngApiVersion,
    "inspector",
    u8"RNG全量词典与遥测探针",
    "2.4.0",
    u8"提供1697处随机点词典、开区间安全浮点换算及 top/find/names/list/info/dump/fix/seq/trace 指令"
};

} // namespace

MHW_RNG_PLUGIN_EXPORT const MhwRngPluginDescriptor* MhwRngPlugin_GetInfo() {
    return &kPluginDesc;
}

MHW_RNG_PLUGIN_EXPORT bool MhwRngPlugin_Init(const MhwRngHostApi* host, MhwRngPluginId selfId) {
    if (!host || host->apiVersion != kMhwRngApiVersion) return false;
    g_host   = host;
    g_selfId = selfId;

    MhwRng_RegisterPluginInfoBi(
        host, selfId,
        u8"RNG全量词典与遥测探针",
        "RNG Catalog & Telemetry Inspector",
        u8"提供1697处随机点词典、安全浮点换算与调用栈追踪",
        "1,697-site RNG dictionary, safe float solver & trace/dump telemetry");

    host->SetFallbackMetaResolver(selfId, &InspectorMetaResolver, nullptr);

    MhwRng_RegisterSubcommandBi(host, selfId, "top",      "$rng top [N|all]",       u8"查看本轮触发最多的核心随机点",   "List top core RNG sites this epoch",          &Cmd_Top,      nullptr);
    MhwRng_RegisterSubcommandBi(host, selfId, "find",     "$rng find <kw>",         u8"按中英文关键词搜索随机点",       "Search RNG sites by keyword",                 &Cmd_Find,     nullptr);
    MhwRng_RegisterSubcommandBi(host, selfId, "names",    "$rng names",             u8"常用英文短词速查表",             "Quick reference for built-in shortcuts",      &Cmd_Names,    nullptr);
    MhwRng_RegisterSubcommandBi(host, selfId, "list",     "$rng list",              u8"列出所有已激活的规则与条件槽",   "List active rules and conditional hooks",     &Cmd_List,     nullptr);
    MhwRng_RegisterSubcommandBi(host, selfId, "info",     "$rng info <target>",     u8"查看单个随机点详情",             "Show detailed snapshot for one RNG site",     &Cmd_Info,     nullptr);
    MhwRng_RegisterSubcommandBi(host, selfId, "dump",     "$rng dump [path]",       u8"导出三段式详表到txt",            "Export categorized active RNG table to txt",  &Cmd_Dump,     nullptr);
    MhwRng_RegisterSubcommandBi(host, selfId, "fix",      "$rng fix <target> <v>",  u8"通用按点换算锁定固定值",         "Lock RNG site(s) to scale-aware fixed value", &Cmd_Fix,      nullptr);
    MhwRng_RegisterSubcommandBi(host, selfId, "seq",      "$rng seq <target> <vs>", u8"通用按点换算注入序列",           "Inject value sequence into RNG site(s)",      &Cmd_Seq,      nullptr);
    MhwRng_RegisterSubcommandBi(host, selfId, "slotseed", "$rng slotseed <t> <s>",  u8"为随机点指定独立种子",           "Assign custom seed to RNG site(s)",           &Cmd_SlotSeed, nullptr);
    MhwRng_RegisterSubcommandBi(host, selfId, "bypass",   "$rng bypass <target>",   u8"让指定点走原版随机",             "Bypass RNG site(s) to vanilla",               &Cmd_Bypass,   nullptr);
    MhwRng_RegisterSubcommandBi(host, selfId, "clear",    "$rng clear <target>",    u8"恢复指定点为跟随总种子",         "Clear rules on RNG site(s)",                  &Cmd_Clear,    nullptr);
    MhwRng_RegisterSubcommandBi(host, selfId, "trace",    "$rng trace <t|*|log|dump|off>", u8"标准化多跳调用栈与XMM探针", "Capture .pdata caller stack & XMM6/7 trace", &Cmd_Trace,    nullptr);

    static const char* const kInspectorCmds[] = {
        "top", "find", "names", "list", "info", "dump",
        "fix", "seq", "slotseed", "bypass", "clear", "trace"
    };
    for (const char* sc : kInspectorCmds) {
        MhwRng_RegisterSubcommandCompleter(host, selfId, sc, &Complete_Inspector, nullptr);
    }
    MhwRng_HostRegisterService(host, selfId, kMhwCatalogServiceName, kMhwCatalogServiceVersion, &kCatalogServiceApi);
    return true;
}

MHW_RNG_PLUGIN_EXPORT void MhwRngPlugin_Shutdown() {
    StopTraceObserver();
    ClearTraceRecords();
    const MhwRngHostApi* hostCopy = nullptr;
    MhwRngPluginId       selfCopy = 0U;
    {
        std::lock_guard<std::mutex> lk(g_idxMx);
        hostCopy = g_host;
        selfCopy = g_selfId;
        g_indexedRvas.clear();
        g_host   = nullptr;
        g_selfId = 0U;
    }
    MhwRng_HostUnregisterService(hostCopy, selfCopy, kMhwCatalogServiceName);
}
