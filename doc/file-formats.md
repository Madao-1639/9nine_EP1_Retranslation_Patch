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

## 5. `.pimg`：PSB v3 + TLG5 位图 chunk

界面贴图（`uipsd/*.pimg`）是 PSB v3，对象图里 `layers[]` 描述图层，位图本身放在**chunk 资源区**：每个图层一份，键名 `<layer_id>.tlg`，内容是该层位图的 TLG5。

**但民汉素材里的 20 张 `uipsd/sc/*_sc.pimg` 是 PSB v2**（头部没有 `header_length`，`tool/psb.py` 会报 `unsupported PSB version 2`），见 §5.2。

PSB 的 chunk 表在对象图之后：`chunk_offsets`（相对 chunk 数据区起点）、`chunk_lengths`、然后 chunk 数据区。**官方打包器把每个 chunk 起点按 4 字节对齐**，两张表后面还有一段对齐填充（例：`uipsd/conf_lang.pimg` 表区 35 字节 = 17 + 18，chunk 起点 0/704/1412/…，全部 4 的倍数）。改资源时对齐和填充都要照抄，否则「原样替换」都不能逐字节往返。`tool/psb.PsbFile.replace_resources()`实现这套重排（零改动往返、同内容替换都逐字节一致）。

### 5.2 v2 容器（民汉素材）

v2 只有 7 个 u32，第 5/6/7 个才是三个 chunk 偏移：

```
0x00 "PSB\0" | 0x04 u16 version(=2) | 0x06 u16 encrypt
0x08 u32 ×7：前四个与 names / strings 有关（改贴图用不到），
              [4] chunk_offsets  [5] chunk_lengths  [6] chunk_data
```

与 v3 的差别：**chunk 数据在文件尾部**（其后只剩 16 B 尾巴），对象图在数据区之前。所以替换某个 chunk 只改两个整数阵列 + 尾部数据，其余字节一个不动（两个阵列的字段宽度不能变，否则拒绝写出）。实测 20 张 `_sc.pimg` 按此法零改动往返 **20/20 逐字节一致**。

> 容器读写与重编码是一次性脚本（`tmp/`，任务结束即清理，不随仓库分发）。要重做时照上面的布局自己写：解析两个阵列 → 算新 offsets/lengths → 拼 `head + off_arr + len_arr + 新 chunk 数据 + tail`。

注意：chunk 数据的 TLG 是 **TLG6**（`TLG0.0` 魔数），而 `tool/tlg.py` 只实现 TLG5 编解码。官方繁中变体（`data.xp3` 里的 `uipsd/cn/*_cn.pimg`）是 PSB **v3 + TLG5**，可以直接用 `tool/psb.py` + `tool/tlg.py` 读出来当**对齐基准**（改 sc 版贴图时用它对齐左边界/画布裁切方式）。改图时先把 TLG6 解成 PNG（用 GARbro 的 `TlgFormat.Read`，本仓库不往里加 TLG6 解码器），改完再以 **TLG5** 写回 —— 引擎两种都读（官方 v3 pimg 本身就是 TLG5）。

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
- 归档里也可能出现 **TLG6**（`TLG0.0\0sds\x1a` + `TLG6.0…`，Golomb 编码）：民汉素材的 20 张 `pimg` 就是 TLG6，本项目只实现 TLG5 的编解码（`tool/tlg.py`），写出去的 `_sc` 贴图一律 TLG5；引擎两种都读，实测 TLG5 产物能正常显示。依据：`resource/ui_sc/uipsd/sc/*.pimg` 里 `TLG6` 魔数计数 24 次（民汉）vs 我们产出的 `conf_lang_sc.pimg` 全是 TLG5。


解码/编码实现：`tool/tlg.py`（GARbro `ArcFormats/KiriKiri/ImageTLG.cs` TLG5 分支的 Python 移植，编码侧是自写的 LZSS）；PNG 读写：`tool/pngio.py`。
