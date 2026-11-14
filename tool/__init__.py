"""9-nine-:Episode 1 简中补丁：长期复用库。

模块清单（纯标准库，无第三方依赖）：

- xp3:        普通 xp3 归档读写（索引/条目/段、adler32、TVP 文本打散 FE FE）
- cx:         本作的 Cx 加密层（XOR 对称，可读可写；参数在 resource/cx/profile_9nine.json）
- psb:        PSB v3 对象图读取与字符串池级重写（零改动往返逐字节一致）
- scn:        MDF 剧情脚本（.scn = `mdf\\0` + u32 + zlib + PSB）的文本模型
- textset:    按脚本分片的文本集存储（resource/<set>/scripts/<script>.jsonl）
- krkr_text:  Kirikiri TVP 加扰文本编解码（syslangtext / help 等，mode 0/1/2）
- cxdec_v2:  M2「Cxdec V2」（新版 `cxdec` 插件）内容解密层：密钥由插件本体重算 + JSON 缓存，流式 XOR 复用 `cx.stream`（第 5 作，参数在 resource/cx/profile_9nine_ep5.json）
- tlg:        TLG5 / TLG6 位图编解码（含 `TLG0.0\0sds` 外壳；写入端只出 TLG5）
- pngio:      极小 PNG 读写（8bit RGBA，只依赖 zlib），用于贴图人工检查与外部渲染图回灌
- pimg:      `.pimg` chunk 资源读写**统一入口**（`open_pimg()` 按 PSB v2/v3 自动分派；
             v3 委派 `psb.PsbFile`，v2 内置）
- evb:        Enigma Virtual Box 虚拟文件系统读取（民汉补丁的 `*.exe` / `*.pck`；**不是 krkr 能力**）

来源：xp3/psb/scn 来自本机知识库 `../../../../GalRevserse/GalRev/galrev/krkr/`（2026-11-08 复制；
引擎级结论改动需两边同步，`tlg` 已于 2026-11 补入 TLG6 分支、需同样同步）；`cx.py` 依据 GARbro
的 `KiriKiriCx.cs` 独立移植（与 GARbro 逐字节一致）；`tlg`/`pngio` 依据 GARbro 的 `ImageTLG.cs`
语义移植（TLG 两侧解码与 GARbro 逐像素一致）；`evb.py` 依据 `GalRevserse/evbunpack` 的
`pe_external_tree` 纯标准库重写（不依赖 evbunpack/aplib）；textset 来自纯白交响曲 FHD 移植项目；
krkr_text 是 TVP 加扰文本实现（参考早期补丁工具重写）。

本作是 **Cx 变体**（不是 Hxv4），因此没有把 galrev 的 hxv4/hxv4_write/hxv4hash 带进来。
"""
