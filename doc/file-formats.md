# 容器与格式

本作（9-nine-:Episode 1，appid 976390）用到的三种格式，工具实现见 `tool/`；§1.3 另外记录系列第 5 作（9-nine-NewEpisode）的另一套 Cx 参数与插件。

## 1. `data.xp3`：XP3 的 **Cx 加密变体**

```
00: 58 50 33 0d 0a 20 0a 1a 8b 67 01 | 17 00 00 00 00 00 00 00   <- XP3 签名 + 「伪」索引偏移 0x17
0x13: 00 00 00 01 | 00 00 00 80 | ...
0x17: 80                            <- Cx 变体标记
0x20: 68 38 b4 22 00 00 00 00        <- **真索引偏移**（u64）
```

* 索引本身是明文 chunk 树，`dir_offset` 处首字节 `1` 表示 zlib 压缩的索引。
* 条目名 = `md5(UTF-16LE 全路径)` 的十六进制（如 `scn/a01.txt.scn` → `269c14bc5e2bf313d1e646e5d5be25e5`）；`startup.tjs` 是唯一用真名的条目。
* `adlr` 哈希 = **`adler32(明文内容)`**：既是完整性校验，也是 Cx 的密钥（`a09` 明文 adler32 = `0xbea696eb` = 索引里的 `adlr`）。
* **条目内容**是 Cx 加密（`info.flags` 带 `0x80000000`）；索引、条目名不加密。
* 段（`segm`）可能先 zlib 压缩再加密 —— 解密要作用在**解压后**的流上，且偏移按解压后的位置累计。

### 1.1 Cx 参数（每作一组）

公开方案标作 `CxEncryption(0x12B, 0x7AB)`：

| 项 | 值 |
|---|---|
| `mask` / `offset` | `0x12B` / `0x7AB`（`base_offset = (hash & mask) + offset`，越过它密钥换成 `(hash>>16)^hash`） |
| `prolog_order` | `[0, 2, 1]` |
| `odd_branch_order` / `even_branch_order` | 6 / 8 项（见 `resource/cx/profile_9nine.json`） |
| `control_block` | 1024 × u32（GARbro 的「 Encryption control block」表，取反后参与运算） |

来源：GARbro 的 `GameData/Formats.dat`（`GameRes.Formats.KiriKiri.CxEncryption`），字段经反射导出成 `resource/cx/profile_9nine.json`；`tool/cx.py` 是 GARbro `ArcFormats/KiriKiri/KiriKiriCx.cs` 的**逐语义移植**（Cx 程序生成 + 字节码 VM + 三层密钥）。

依据：对 `data.xp3` 里 21 个条目（17 个 scn + `startup.tjs` + `syslangtext_cn.ini` + `help_conf_cn.txt` + `embfontlist.tjs`），`tool/cx.py` 的输出与 GARbro 的 `ICrypt.Decrypt` **逐字节一致**（21/21）。加解密同一算式（XOR），因此同一实现也用来**写**补丁包。

### 1.2 明文包（`adlr=0` 的另一种 XP3 形态，本项目不用）

另有一种普通 XP3：`adlr=0`（不加密标记），索引未压缩，同一内容登记三别名（全路径 / basename / `md5(UTF-16LE 全路径)`）。这种包引擎读不了，必须配 `version.dll`（KirikiriUnencryptedArchive），因此本项目交付物用 Cx 加密包。

### 1.3 第 5 作（9-nine-NewEpisode）：Cxdec V2

系列第 2–4 作与第 1 作同参数（`resource/cx/profile_9nine.json` 通用）；**第 5 作换了插件与参数**，旧 profile 解不开（实测解出签名不对）。判型仍与 §1 相同（`0x17` 处 `0x80`、索引明文 zlib、条目内容加密），差别在密钥怎么算：

| 项 | 第 1 作（旧 `cxdec_tpm.dll`） | 第 5 作（新 `cxdec.tpm.dll`） |
|---|---|---|
| 代码位置 | 参数/程序编进 exe | 两作 exe 的 `.text` **逐字节相同**，差异只在 `.rdata` 里内嵌的一个 PE |
| 注册方式 | `TVPRegisterStorageMedia` + 私有 `CxFilterFS` | `TVPSetXP3ArchiveExtractionFilter`（krkr 公共过滤器 API） |
| 控制块 TABLE | 存的是**取反表**（用前再取反） | 存**原表**（`table[idx]` 直接读） |
| 程序生成 | 固定字节码解释 | `DynamicCodeGen`：128 lane，运行时生成，`seed = lane 索引`，随机源 LCG（`flags` bit7=1 时改 MT19937） |
| branch order 数组 | index = 随机值 | index = **form**（value 是命中该 form 的随机值；与 GARbro 的数组互为逆排列） |
| 索引里的条目名 | `md5(UTF-16LE 全路径)` | **真名**（`scn/e01a.txt.scn`） |

exe `.rdata` 内嵌模块的布局：`"module\0"` 起 16 字节名字槽 + u16(原长/256) + `0x00` + u32(zlib 长) + zlib(PE)，解出来是 32 位 PE（`TVPSetXP3ArchiveExtractionFilter` 的提供者）。

模块自带两段数据（`sub_10003010` 按名字找：名字 + u16 字节长 + 数据）：

* `--data--PARAMS`（22 B）：`[0:8]` even、`[8:14]` odd、`[14:17]` prolog（三者都是「按 form 索引」的排列）、`[17]` flags、`[18:20]` mask、`[20:22]` offset；
* `TABLE`（4096 B = 1024 × u32）：控制块原表。

每条目密钥（`sub_10001980`，入参 = `adlr`）：

```
lane     = adlr & 0x7F ; src = adlr >> 7
key64_a  = exec(lane, src) | (exec(lane, ~src) << 32)   # 低 32：key3 与两处附加字节；高 32：两处位置
base_off = offset + (adlr & mask)
key64_b  = 同上，key = adlr ^ (adlr >> 16)
```

解密与 Cx 同一算式（两作共用 `tool/cx.py` 的 `crypt_stream`）：`[0, base_off)` 用 a 段、之后用 b 段；`pos` 落在段内才 XOR，先 zlib 解压再解密、偏移按明文累计。

本作取值：`mask=0x190`、`offset=0x27E`、even `[5,3,4,7,1,2,6,0]`、odd `[3,0,1,2,5,4]`、prolog `[2,1,0]`、flags `0x00`（LCG 支路），整表见 `resource/cx/profile_9nine_ep5.json`；条目密钥缓存 `resource/cx/keys_9nine_ep5.json`（1389 条 adlr）。工具 `tool/cxdec_v2.py`，解包/校验 `script/unpack_ep5.py`。

密钥必须由**插件本体**算（生成器是运行时产物，静态复现性价比低）：模块是 32 位 PE，故借 Windows 自带的 32 位 PowerShell 加载并调 `sub_10001980`（模块内地址随构建变化，记在 profile 的 `module.filter_rvas`）；算一次缓存成 JSON 后，整条流程纯 Python。

判据：`bgimage/bg001a.png`（adlr `0x98DEC45C`）→ `key64_a = 0x288C4798_288C4798`、`base_off = 654`，解出 PNG 全 chunk CRC 通过、IDAT inflate 长度与 IHDR 一致（1,280×720×3+720 = 2,765,520 B）。


打包（写回）：容器写法与第 1 作共用 `tool/xp3build.write_archive`，形态按官方包对齐——`info` 里的条目名是**真名**、**不带 `hnfn`**（第 1 作官方包是 `md5` 名 + 每文件一条 `hnfn`，两作不同，`write_archive` 的 `name_style="real"` / `emit_hnfn=False` 就是给这里用的）。内容 = `zlib.compress(encrypt(明文), 9)`，`adlr` = **明文** adler32，加密与解密同一算式（`tool/cxdec_v2.KeyCrypt` 直接喂给 `write_archive`）。改过的明文必然是新 `adlr`、也就是新密钥，所以打包要先把所有明文的 adler32 收齐、一次性调插件补算密钥（`script/pack_ep5.py --exe`），写完立刻回读逐字节比对。
## 2. `.scn`：裸 PSB v3

本作的剧情脚本**没有** `mdf\0 + zlib` 外壳，直接是 `PSB\0`（版本 3，header_encrypt=0）。
`tool/psb.py` 按 FreeMote 公开规格解析；`tool/mdf.py` 给出本作的文本模型（见 `text-model.md`）。

PSB 头 `0x28` 处 4 字节是 checksum。**注意**：现存的 scn checksum 取自官方原文件（`adler32`/`crc32` 都对不上任何前缀），说明**引擎不校验**该字段；本项目重建时由 `tool/psb.py` 重新计算。

## 3. TVP 加扰文本（`main/*.tjs`、`syslangtext`、`help`）

部分文件以 `FE FE | mode | FF FE | 正文(UTF-16LE)` 存放，mode 1 对每个 uint16 做奇偶位交换（对合）。`tool/krkr_text.py` 支持 mode 0/1/2 的 decode/encode/往返校验。

`data.xp3` 里的分布：

| 文件 | 形态 | 说明 |
|---|---|---|
| `main/default.tjs`、`main/config.tjs`、`main/custom.tjs`、`main/storages.tjs`、`appconfig.tjs`、`font/embfontlist.tjs` | 加扰文本（mode 1） | **TJS 源码**，可直接读改 |
| `startup.tjs`、`system/initialize.tjs`、`system/conductor.tjs`、`system/mainwindow.tjs` | `TJS2` 编译字节码 | 只读（字符串表仍可提取） |
| `main/syslangtext_cn.ini`、`main/help_conf_cn.txt` | 加扰文本 / 明文 | UI 文案（不在补丁范围） |

## 3.5 本项目补丁包的头部（与官方同构）

`script/build_patch.py` 写出的补丁归档（`releases/steam.xp3` 与 `releases/patch3.xp3`）头部与官方 `data.xp3` 完全同构：`0x0B` 处 u64=0x17（伪索引偏移）、`0x17` 处 u32=0x80（变体标记）、`0x1B` 5 字节填充、`0x20` 处 u64=真索引偏移、内容区从 `0x28` 开始；索引 zlib 压缩（首字节 `1`）。
写入器只有一份：`tool/xp3build.write_archive`（`script/build_patch.py` 调用，`hnfn` 每文件一条等约束见上）。
不加密的 `releases/unencrypted.xp3` 则是标准 XP3 头（`0x0B` 直接是索引偏移）、`adlr=0`、不加密。

## 4. 名字反查

官方索引名是哈希，要按路径取文件就必须先算出 md5。可用的候选名登记在 `resource/name_candidates.txt`；`script/unpack_xp3.py --only scn/` 会连同内置候选一起尝试。

## 5. `.pimg`：PSB + TLG 位图 chunk

界面贴图（`uipsd/*.pimg`）对象图里 `layers[]` 描述图层，位图本身放在**chunk 资源区**：每个图层一份，键名 `<layer_id>.tlg`，内容是 TLG 位图。**两个 PSB 版本同时在用**，改图前先判版本：

| 来源 | PSB 版本 | chunk 里的 TLG |
|---|---|---|
| 官方 `uipsd/*.pimg`（含繁中变体 `uipsd/cn/*_cn.pimg`） | v3 | TLG5 |
| 民汉素材 `uipsd/sc/*_sc.pimg`（20 张） | **v2** | **TLG6**（个别已被我们改成 TLG5） |
| 本项目自造 `uipsd/sc/conf_lang_sc.pimg` | v3 | TLG5 |

**改 chunk 不需要关心版本**：用 `tool/pimg.py` 的统一入口，两个版本返回同一套接口（`version` / `len()` / `original_bytes` / `resource_bytes(i)` / `replace_resources(mapping)`）：

```python
from tool import pimg, tlg
f = pimg.open_pimg(data)                     # v2 / v3 自动分派
img = tlg.decode(f.resource_bytes(3))        # 拿到 Image（带 .kind）
out = f.replace_resources({3: tlg.encode(img.width, img.height, img.rgba)})
```

要按**图层名**找 chunk（只有 v3 有名字池）才直接用 `tool/psb.py` 的 `PsbFile`。

PSB 的 chunk 表在对象图之后：`chunk_offsets`（相对 chunk 数据区起点）、`chunk_lengths`、然后 chunk 数据区。**官方打包器把每个 chunk 起点按 4 字节对齐**，两张表后面还有一段对齐填充（例：`uipsd/conf_lang.pimg` 表区 35 字节 = 17 + 18，chunk 起点 0/704/1412/…，全部 4 的倍数）。改资源时对齐和填充都要照抄，否则「原样替换」都不能逐字节往返。`tool/psb.PsbFile.replace_resources()`实现这套重排（零改动往返、同内容替换都逐字节一致）。

### 5.1 TLG5（`TLG5.0\0raw\x1a`）

```
"TLG5.0\0raw" (10) | 0x1a | colors | width u32 | height u32 | blockheight u32
blocksize[nblocks] u32 × nblocks
逐块、逐颜色平面：
    u8 mark        0 = LZSS 压缩，非 0 = 原始字节
    u32 size
    payload
```

- 平面数据是「行差分 + 颜色相关」：`g` 直接累加，`b`/`r` 先加 `g` 再累加，累加值再加**上一行**
  同列像素；alpha 单独累加。首行与其它行一样以 0 为基准（GARbro 的首行 alpha 写死 `0xff`是移植偏差，引擎实测按 0 基准）。
- LZSS 的 4096 字节滑窗在整张图的所有块、所有平面之间**连续**复用；匹配允许与当前位置重叠
  （逐字节复制的 run-length）。**不是 zlib**，第一次实现时踩过这个坑。
- `colors` 是 3（BGR）或 4（BGRA）；TLG5 内部通道顺序是 **BGRA**。

**外壳**：TLG5 与 TLG6 都可能被包在 `TLG0.0\0sds\x1a` 里（15 字节，其后从 +15 起才是裸 TLG）。第 4 作民汉素材的 1280×720 背景就是「外壳 + TLG5」；`tool/tlg.py` 的 `decode()` 自动跳过外壳。

### 5.2 TLG6（`TLG6.0\0raw\x1a`）

```
"TLG6.0\0raw" (10) | 0x1a | colors(1/3/4) | 0 | 0 | 0 | width u32 | height u32
u32 max_bit_length
u32 inbuf_size | LZSS(色度过滤类型表，每 8×8 块 1 字节)
逐 8 行组、逐颜色平面：
    u32 bit_length（高 2 位 = 熵编码方法，0 = Golomb；其余未实现）
    payload
```

两个必须踩过才知道的点（`lessons-learned.md` §18 有留档）：

1. **色度过滤表的 LZSS 初始字典**是 `for i in 32: for j in 16: [i,i,i,i,j,j,j,j]`，`i`/`j` 各占 4 个**相同**字节（不是 `[i,0,0,0]`）。填错时首块过滤类型全错，图像呈块状色斑。
2. **过滤类型要「先把 v 按通道相关式展开，再喂 MED/AVG」**（偶数 = MED 中值边缘检测，奇数 = AVG 平均）。只照抄那 30 项表会漏掉「先展开」这一步。

另外两条结构事实（不踩坑但实现时必须照做）：

- **逐行蛇形扫描**：行方向按 `(y & 1) ^ 1` 交替，反向行要先把 inbuf 游标推到行尾再往回走，块间再按 `oddskip` 补偿。整张图当同一方向解会得到锯齿状错位。
- **行尾有「零头块」**：宽高不一定是 8 的倍数（`main_count = width // 8`、`fraction = width - main_count * 8`），`main_count` 段与零头段**共用同一行的预测器状态**，但各自在 `pixelbuf` 里的起点不同（`8 × 组内行号` 与 `fraction × 组内行号`）。零头段漏解或起点算错，表现为每行右侧一条竖带乱码。

**写入端只做 TLG5**：TLG6 要写 Golomb 编码器 + 30 种预测器的编码侧，成本远大于收益，而引擎两个变体都读。`tool/tlg.py encode()` 因此永远产出 TLG5 —— **这不是漏做**。

解码/编码实现：`tool/tlg.py`（GARbro `ArcFormats/KiriKiri/ImageTLG.cs` 的 Python 移植；TLG5/6 解码与 GARbro **逐像素一致** —— 跨两作 16 张跨页样本 RGBA 全字节相等 16/16；编码侧是自写的 TLG5 LZSS）。PNG 读写：`tool/pngio.py`。

### 5.3 v2 容器（民汉素材）

v2 只有 7 个 u32，第 5/6/7 个才是三个 chunk 偏移：

```
0x00 "PSB\0" | 0x04 u16 version(=2) | 0x06 u16 encrypt
0x08 u32 ×7：前四个与 names / strings 有关（改贴图用不到），
              [4] chunk_offsets  [5] chunk_lengths  [6] chunk_data
```

与 v3 的差别：**chunk 数据在文件尾部**（其后只剩 16 B 尾巴），对象图在数据区之前。所以替换某个 chunk 只改两个整数阵列 + 尾部数据，其余字节一个不动（**零改动重建**时两个阵列的字段宽度当然也不变）。实测 20 张 `_sc.pimg` 按此法零改动往返 **20/20 逐字节一致**。

> 字段宽度**不是固定的**：两个阵列各自是 PSB 自描述数组（type byte 0x0d–0x14 给 count 宽度，紧跟的 entry type 给元素宽度），换进来的 chunk 变大后可以把元素宽度加宽。实例：替换 `conf_dlg_sc` 的标签 chunk（50096 → 76781 B）后，chunk offsets 阵列从 2 字节（entry type `0x0e`）变 3 字节（`0x0f`），同时要把头部 `0x1c`（chunk_lengths 位置）与 `0x20`（chunk_data 位置）两个 u32 跟着变大（本例各 +4，因为阵列长了 4 B）。引擎按宽度读：`conf_mes_sc` / `conf_key_sc` 本来就是 3 字节 offsets、`conf_sys_sc` 的 chunk 起点并不 4 字节对齐（801/4803/8839），实机都正常 ⇒ 既不要求固定宽度，也不要求 chunk 起点对齐。

读写与重编码：**`tool/pimg.py`** 的 `PimgV2`（经 `open_pimg()` 分派）。规则与判据：

1. 表区先尽量保持原长（照抄原填充）⇒「同内容替换」能逐字节往返；本作 20 张 `_sc.pimg` 实测 **零改动 20/20 + 同内容替换 20/20 均逐字节一致**。
2. 新表比原表长时**就让表变长**，头部 `[5]`/`[6]` 跟着推（实测 `conf_sys_sc` 把 chunk3 撑大后 offsets 阵列 2→3 字节，回读正确）。
3. chunk 之间的对齐粒度按原文件推（本批 20 张全部**紧密排列、gap=0**，与 v3 官方包的 4 字节对齐不同）。
4. 文件尾不属于任何 chunk 的字节原样带过。

改图流程：`PimgV2.resource_bytes()` 取 chunk → `tool/tlg.py` 解码（v2 素材是 TLG6，本仓库已支持）→ 改字 → `tool/tlg.py encode()` 一律以 **TLG5** 写回（引擎两种都读）。官方繁中变体（`uipsd/cn/*_cn.pimg`）是 v3 + TLG5，用 `tool/psb.py` 读出来当**对齐基准**（左边界/画布裁切）。

## 6. 民汉补丁的容器：Enigma Virtual Box

樱空汉化组的第 4/5 作补丁**不是 XP3**，是 Enigma Virtual Box（EVB）：把文件塞进宿主 PE 的 `.enigma1` 段尾部，或单独存成外部 `.pck`。它与 krkr 引擎无关，是第三方打包器。

| 载体 | 魔数位置 | 本作例 |
|---|---|---|
| exe 内嵌 | `.enigma1` 段内 | 第 5 作 `nine_new_chs.exe`（`EVB\0` @ `0x435cce`） |
| 外部包 | 文件偏移 0 | 第 4 作 `chsdata.pck`（479 文件）、`update.pck`（54 个 scn） |

节点表布局（PE-external 变体）：

```
EVB_PACK_HEADER  "EVB\0" + 60s
EVB_NODE_MAIN    u32 size | 8s | u32 objects_count
逐节点（顺序 = 文件系统树的前序遍历）：
  EVB_HEADER_NODE   u32 size | 8s | u32 objects_count
  EVB_NODE_NAMED    u16 名（UTF-16LE，双 0 结尾）| u8 type
  type=2（文件）    + 2s | u32 original_size | 4s | 8s×3(FILETIME) | 15s | u32 stored_size
  type=3（目录）    + 25 字节
```

要点（都是踩过的坑）：

* 主节点之后要**回退 1 字节**才是第一个头节点起点（`evbunpack::pe_external_tree` 的行为）。不回退会把下一个 u32 读成 0，整棵树只解出主节点。
* 节点 `offset` 是**相对文件开头的绝对偏移**（内容区起点已含魔数）。早期把魔数偏移又加了一次，外部包（魔数为 0）看不出差别、exe 内嵌时读到错位置。
* 目录 `%DEFAULT FOLDER%` 是虚拟根，路径要折叠掉。
* 包里的 `.tjs`/`.txt`/`.ks` 是 **UTF-16LE 明文**（不是 TVP 打散，与 XP3 里的不同）。

**分块压缩：本库不解压，只报错。** `stored_size != original_size` 的条目是 EVB 的分块 aPLib 压缩（每块 aPLib，块长表 = 8 字节头 + 每 3 个 u32 取一个长度）。本项目接触的全部真实包（第 4/5 作 4 个包共 663 个条目）与 `evbunpack` 自带 11 个测试包，压缩条目数均为 **0**，没有真实样本可验证 aPLib 解码器，按「报错优先」不实现（`tool/evb.py` 文末有 TODO 标记）。宁可靠错，也不放一个跑不通的分块解压器——解错了会静默产出坏文件。

工具：`tool/evb.py`（纯标准库重写，不依赖 `evbunpack`/`aplib`）+ `script/unpack_evb.py`（`list` / `extract --png`）。
判据：3 个真实包共 650 个文件，与 `evbunpack` 的提取结果**逐个 sha256 一致**。
