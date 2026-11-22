# `rng_inspector` 官方插件技术文档（调用点词典与遥测探针）

- **插件标识**：`inspector`（编译产物 `rng_inspector.dll`，版本 `2.1.0`）
- **源码位置**：[inspector_plugin.cpp](inspector_plugin.cpp)、[rng_catalog_data.inl](rng_catalog_data.inl)
- **离线词典生成工具**：[gen_rng_catalog.py](https://github.com/Miraboreasyu/mhw-rng/blob/main/tools/gen_rng_catalog.py)
- **宿主依赖**：`mhw_rng.dll`（Plugin SDK `kMhwRngApiVersion == 3`，头文件 [mhw_rng_api.h](include/mhw_rng_api.h)）

本文档说明 `rng_inspector` 插件的词典数据结构、元数据解析优先级、按消费尺度的数值换算规则以及各调试与导出子命令的行为。

---

## 一、插件职责与运行开销特征

`rng_inspector` 用于将底层的十六进制返回地址（`CallSiteRVA`）映射为可读的分类名称、函数符号与数值尺度，并提供游戏内实时观测（`top`、`list`、`info`、`dump`）及通用探索性锁定（`fix`、`seq`、`slotseed`、`bypass`、`clear`）命令。

- **无抽签热路径介入**：本插件不调用 `RegisterSlotHook` 挂载任何抽签时回调，游戏运行过程中的随机数抽取不经过 `rng_inspector` 代码段。插件仅在玩家输入聊天命令或导出报表时被调用。
- **按需加载与卸载**：若仅需运行确定好的业务插件（如 `rng_size.dll`），可随时通过 `$rng unload inspector` 卸载本插件以释放约 440 KB 词典只读数据，不会影响微内核或其它插件的运行。

---

## 二、词典数据构成与元数据解析流程

### 1. 三张静态只读表（`rng_catalog_data.inl`）
词典数据由离线脚本 [gen_rng_catalog.py](https://github.com/Miraboreasyu/mhw-rng/blob/main/tools/gen_rng_catalog.py) 对 15.23 版本 `.text` 段交叉引用、Ghidra 函数符号与虚表归属分析自动生成，编译为静态常量数组：
1. **`kCatalogSites`（共 1,697 项）**：按 `rva` 严格升序排列的精确调用点表。每项包含 `rva`、`category`（功能分类 `0..12`）、`scaleKind`（返回值消费尺度 `0..3`）、英文点分短别名 `alias`（如 `meal.trigger`、`em013.act.1`）、中文说明 `cnDesc` 及外层函数符号 `techSym`。查询复杂度为二分查找 `O(log N)`。
2. **`kCatalogFuncRanges`（共 793 项）**：按起始地址 `rvaLo` 升序排列的外层函数区间 `[rvaLo, rvaHi)` 表。当遇到通过循环或间接调用产生的未单独编号返回点时，通过区间二分查找将其格式化为 `<baseAlias>@<RVA>`。
3. **`kBuiltinShortcuts`（共 62 项）**：面向聊天框输入的常用英文短词表，将简短单词映射为精确别名或通配符模式（如 `meal -> meal.trigger`、`carve -> loot.carve.*`、`awaken -> awakening.lot.*`、`rajang -> em023*`）。

### 2. 13 个功能分类（`CategoryId`）与核心/背景划分
为避免粒子、雪地脚印、环境虫鸟等高频视觉随机点淹没玩法相关的随机点，词典将调用点划分为两类：
- **核心玩法分类（`isCoreGameplay == 1`，`category` 为 `0..7`）**：
  `0: 怪物数值`、`1: 怪物AI`、`2: 怪物招式`、`3: 任务调查`、`4: 猎人弹道`、`5: 随从骑乘`、`6: 剥取报酬`、`7: 猫饭炼金`。`$rng top` 默认仅统计此范围内的调用点。
- **背景与表现层分类（`isCoreGameplay == 0`，`category` 为 `8..12`）**：
  `8: 环境生物`、`9: 据点机关`、`10: UI跳字`、`11: 特效音效`、`12: 底层其它`。可通过 `$rng top all` 查看，或在 `$rng dump` 导出的第三节中查阅。

### 3. 与业务插件的元数据优先级协作
`rng_inspector` 在初始化时调用 `host->SetFallbackMetaResolver` 注册为**兜底解析器**。当调用 `host->QuerySiteMeta(rva, &meta)` 时，宿主按以下顺序合成元数据：
1. 若某业务插件（例如 `rng_size.dll` 对 `0x169BA15`）调用过 `RegisterSiteMeta`，宿主优先使用该业务插件注册的 `alias`、`description` 与自定义状态格式化函数 `FormatSlotCustom`；
2. 同时宿主调用 `InspectorMetaResolver` 补全该点位的 `category`、`scaleKind` 与 `techSymbol`（C++ 函数符号）；
3. 若没有任何业务插件显式认领该 `rva`，则完全采用 `InspectorMetaResolver` 返回的词典信息。

---

## 三、返回值消费尺度（`ScaleKind`）与换算规则

不同游戏函数在拿到 `MtRandom::nrand` 返回的 32 位无符号整数 `u32` 后，会采用不同的算术方式消费该数值。词典统计了全部 1,697 个静态点位后部的指令特征，将其归纳为 4 种 `ScaleKind`：

| 枚举名称 | 静态点数量 | 游戏内典型算术形式 | 换算策略说明 |
| :--- | :-: | :--- | :--- |
| `kScaleFloat100` (`0`) | 762 | `(float)u32 * (100.0f / 2^32)` 或 `(float)u32 * 2^-32` | 将输入比例 `[0, 100]` 线性映射到安全开区间整数 `[0x00000001U, 0xFFFFFF00U]` |
| `kScaleMod100` (`1`) | 148 | `u32 % 100`（使用魔数乘法 `0x51EB851F` 求余） | 将输入 `0~99` 直接作为余数写入（输入 `100` 或 `max` 自动映射为最大余数 `99`） |
| `kScaleIntMod` (`2`) | 464 | `u32 % N` 或 `MtRandom::between(a, b)` | 默认按无符号整数直接写入；若输入带 `%` 后缀（如 `50%`）则按比例映射 |
| `kScaleRawU32` (`3`) | 323 | 作为子生成器种子或位掩码使用 | 按 32 位原始无符号整数写入 |

### `ParseSmartValue` 输入换算对照表

| 用户输入写法 | `kScaleFloat100` 写入值 | `kScaleMod100` 写入值 | `kScaleIntMod` / `kScaleRawU32` 写入值 |
| :--- | :--- | :--- | :--- |
| `min` | `0x00000001`（约 `+2.33e-8 / 100`） | `0`（余 `0`） | `0` |
| `mid` / `half` | `0x80000000`（`50.0 / 100`） | `50`（余 `50`） | `0x80000000` |
| `max` | `0xFFFFFF00`（`99.999992 / 100`） | `99`（余 `99`） | `0xFFFFFFFF` |
| `0` ~ `100`（纯数字） | 按比例映射至 `[0x00000001, 0xFFFFFF00]` | `0` ~ `99`（`100` 自动取 `99`） | 字面无符号整数 `0` ~ `100` |
| `<p>%`（如 `25%`） | 按 `p%` 映射至 `[0x00000001, 0xFFFFFF00]` | `round(p)`（上限 `99`） | 按 `p%` 映射至 `[0x00000001, 0xFFFFFF00]` |
| `0x<hex>` 或 `raw:<u32>` | 字面 `uint32_t`（不做任何缩放） | 字面 `uint32_t` | 字面 `uint32_t` |

> [!NOTE]
> **关于 `kScaleFloat100` 不使用字面 `0` 与 `0xFFFFFFFF` 的说明**
> 游戏内多处浮点概率表（如体型表、部分道具/词条权重表）通过循环累加权重并判断 `roll <= cumWeight` 选择行。若注入字面 `0U`（`roll == 0.0f`），当表首行权重为 `0`（禁用行）时，`0.0f <= 0.0f` 仍为真，会误选禁用行；而注入 `0x00000001U`（`roll = 2.3283064e-8f`）可自动跳过所有前导 `0` 权重行并命中首个正权重行。若调试时确实需要注入字面 `0`，可使用 `$rng fix <target> raw:0` 或 `0x0`。

---

## 四、目标寻址规则（`ResolveTarget`）与快捷序号

在 `info`、`fix`、`seq`、`slotseed`、`bypass`、`clear` 命令中，`<target>` 参数按以下顺序解析：
1. **快捷序号 `#<N>`**（如 `#1`、`#3`）：引用最近一次执行 `top`、`find`、`list` 或 `dump` 时生成的唯一 RVA 序号表（`g_indexedRvas`，受独立互斥锁 `g_idxMx` 保护）。
2. **内置短词展开**：若匹配 `kBuiltinShortcuts`（如 `meal`、`carve`、`size`），先展开为对应的目标模式。
3. **精确或通配别名匹配**：支持 `*` 与 `?` 通配符（如 `loot.carve.*`、`em013*`）。同时检索活跃槽位上由业务插件动态注册的 `RegisterSiteMeta` 别名与静态词典 `kCatalogSites`。
4. **函数区间动态名或 `rva.` 前缀**：如 `ai.think@1339C8C` 或 `rva.0169BA15`。
5. **原始地址**：十进制或 `0x` 十六进制的 RVA（如 `0x169BA15`）及完整虚拟地址（如 `0x14169BA10`，由宿主自动归一化）。

对于 `fix` 与 `seq` 等可能通过通配符一次匹配多个点位的命令，插件会先对所有匹配点位完成数值与参数合法性校验（包括检查整数不超过 `0xFFFFFFFF`、校验可选 `condId` 格式），全部通过后再统一写入微内核槽位，避免部分成功、部分失败的半修改状态。

---

## 五、子命令参考手册

### 1. 观测、搜索与导出指令

| 命令格式 | 作用说明 |
| :--- | :--- |
| `$rng top [1~20] [all]` | 按本轮（`Epoch`）调用次数降序显示活跃随机点（默认前 6 处、仅含核心玩法；加 `all` 包含背景与特效），并更新 `#序号` |
| `$rng find <keyword>` | 按英文关键词模糊搜索内置短词、点位别名、函数符号或描述，并更新 `#序号` |
| `$rng names` | 在聊天框显示常用英文短词速查提示 |
| `$rng list` | 列出当前所有处于非默认模式或挂载了插件回调的复合槽 |
| `$rng info <target> [condId]` | 查看单个随机点（及指定条件号 `condId`，默认 `0`）的归属插件、当前模式、本轮次数与最近一次输出值 |
| `$rng dump [path]` | 导出带 UTF-8 BOM 的完整中文报表（默认输出至 `nativePC\plugins\mhw_rng_dump.txt`），同时更新 `#序号` |

`mhw_rng_dump.txt` 报表按三段组织：
- **第一节**：当前激活了锁定规则或挂载了插件钩子的槽位；
- **第二节**：本轮触发过的核心玩法随机点（按本轮调用次数降序）；
- **第三节**：背景环境、UI 与视觉音效随机点。

### 2. 通用操纵指令

| 命令格式 | 作用说明 |
| :--- | :--- |
| `$rng fix <target> <val> [condId]` | 按目标点位的 `ScaleKind` 换算 `<val>`，将 `(rva, condId)` 设为固定值模式 |
| `$rng seq <target> <v1,v2,...> [loop\|hold\|prng] [condId]` | 为目标槽位注入逗号分隔的序列；支持结束策略 `loop`（默认循环）、`hold`（停在末项）、`prng`（播完切回确定性随机流） |
| `$rng slotseed <target> <seed> [condId]` | 为目标槽位指定不受全局 `MasterSeed` 影响的独立 64 位种子 |
| `$rng bypass <target> [condId]` | 将目标槽位设为原版直通模式 |
| `$rng clear <target\|all>` | 清除目标点位全部条件槽的覆盖规则（传 `all` 清空全局全部覆盖规则） |

---

## 六、词典更新、头文件同步与独立构建

本插件目录包含完整的本地头文件副本与独立构建脚本，可直接作为单独的 Git 仓库维护：

- `inspector_plugin.cpp`：插件主源码
- `rng_catalog_data.inl`：离线生成的 1,697 处静态调用点与 793 处函数区间只读表
- `include/mhw_rng_api.h`：本地携带的 `mhw_rng` Plugin SDK v3 头文件副本
- `sync_sdk.bat`：从核心框架目录同步 `include\mhw_rng_api.h`
- `build.bat`：自动定位本机 MSVC x64 编译环境并输出 `build\rng_inspector.dll`

常用命令：
```bat
:: 1. （可选）在核心仓库中重新生成静态词典表
python tools\gen_rng_catalog.py

:: 2. 同步最新 SDK 头文件（不传参默认查找 ..\..\include 或 %MHW_RNG_SDK_DIR%）
sync_sdk.bat <path-to-mhw-rng>

:: 3. 独立编译至 build\rng_inspector.dll
build.bat

:: 4. 编译并直接覆盖至 Steam 游戏目录 nativePC\plugins\mhw_rng\rng_inspector.dll
build.bat --deploy
```

覆盖完成后，在游戏聊天框输入 `$rng reload inspector` 即可热加载生效。
