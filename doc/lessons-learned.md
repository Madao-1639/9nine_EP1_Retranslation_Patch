# 踩坑与返工教训

每条格式：规则（结论）+ 为什么（症状/依据）。

## 1. 「Hxv4」这个标签是错的，判型只看事实

早先的判型文档把本作归档称作 Hxv4（wamsoft XChaCha20 + DRIP），实际是 **Cx 变体**：索引明文、条目名是 md5、`adlr = adler32(明文)`、条目内容走 Cx 的字节码 VM 密钥流。
症状：Hxv4 的 `hxv4.py` 在这份 `data.xp3` 上完全用不上。
⇒ 规则：`0x17` 处 `0x80` + 索引可解析 + 内容解不开 = 名字哈希加密变体，再去对 GARbro 的方案库（实现见 `tool/cx.py`）。

## 2. 别自己造密钥：参数在 GARbro 的 `Formats.dat` 里

公开方案 `CxEncryption(0x12B, 0x7AB)` 只是 mask/offset，真正要跑的是 `prolog/odd/even_branch_order` + 1024 项 `control_block`。这些都在 GARbro 的 `GameData/Formats.dat`（BinaryFormatter + deflate）里，按游戏标题索引。
⇒ 规则：用 `reflection` 从 `ArcFormats.dll` 直接取字段（`tmp/garbo_host/cxtool.cs --dump`），一次导出成 `resource/cx/profile_9nine.json`；从 exe 静态推导拿不到这套参数。

## 3. `GARbro.Console.exe` 认不出本作，但方案就在它自己的数据库里

症状：`GARbro.Console data.xp3` 报 `unknown format` —— `Xp3Opener.GuessCryptAlgorithm` 只按 `FormatCatalog.LookupGame()`（存档文件名 / 同目录 exe 名 → 游戏标题）查方案，而 `m_game_map` 里没有 `nine_kokoiro.exe`。
⇒ 规则：走反射 + 自己的解包路径（`tool/cx.py`），别在 Console 上耗时间。

## 4. C# 一次性宿主不可入库，密钥逻辑必须移植回 Python

症状：用 `csc.exe` + GARbro DLL 的宿主（`cxtool.exe --decrypt`）只能放在 `tmp/` 里、且依赖 .NET Framework，既不复跑也不可交付。
⇒ 规则：`tool/cx.py` 按语义逐条移植，等价性以 C# 宿主的输出为基准（21 个条目逐字节比对一致）。

## 5. 共享字符串槽会让「只改一处」变成改一片

症状：官方 482 行的 jp 与 cn 正文**同槽**（同一偏移），`patch_ints` 改指向会连累日文。
⇒ 规则：写操作先按「字节位置」分组判定共享，再决定跳过；本项目对 3 行无可避免的冲突保留原文，并在产物里列清单（`_skipped_shared.json`）。

## 6. PSB checksum 不可当等价性基准

症状：重建过的 scn 仍保留官方原文件的旧 header checksum（`adler32`、`crc32` 都对不上任何前缀）⇒ 引擎不校验它。
⇒ 规则：零改动往返按「除 `0x28` 4 字节 checksum 外逐字节一致」判定。

## 7. 逻辑行数一致不等于可翻译位置一致：还要看控制码

症状：行数、场景标签、选择支都对得上，但民汉正文的 `\\n` 比官方日文少 498 处、ruby 少 3 处（简中重排段落）。
⇒ 规则：控制码守恒按「产物 == 民汉源」判定，与日文的差异只作提示（原 `script/verify_roundtrip.py` 报 508 行提示，该脚本随三轨路径一并删除）。

## 8. 民汉源本身有缺口，缺口不是 bug

* 选择支（9 条）在民汉包里仍是**官方繁中**（民汉源里选项仍是官方繁中，未经翻译），本项目依日文原文**就地翻译**一份写进语料（`resource/chs_text/scripts/*.selects.jsonl`，见 `doc/text-model.md` §4）；
* 民汉正文残留少量繁体字形（本语料命中 27 个），同样**直接改在语料里**，不做旁路覆盖表（见 `doc/text-model.md` §6）；
* 482 行共享槽里另有 19 行的民汉文本与官中不同但能正常替换，真正无法处理的只有 3 行。
* **显示名列漏翻**：民汉只翻了正文，`blocks[2][0]` 有时仍是日文/注音（如 `a06` `ㄔㄨㄣㄈㄥ`、`・ソフィーティア`），上屏就是「人名未翻译」（见 8.9）。

### 8.1 语料即源：禁止旁路覆盖表

症状：给选项加一张 `_overrides.json`、由 `writeback.py` 在回写时套用，会让同一套规则在两处维护（当时的 `writeback.py` 套表、`verify_patch.py` 也得读同一张表；两者属于已废弃并删除的三轨路径），而且繁体字形只改了选项，正文与显示名仍在。
⇒ 规则：错的是**语料本身**就该修 —— 改语料、回写只负责拍过去；表与双份规则全部删掉。

### 8.2 别把「字体 cmap 覆盖率」当渲染结论

症状：`script/check_font_coverage.py` 读 OTF 的 cmap 能算出「TC 字体对语料 2460 个字符缺字 0、JP 缺 613」，而第 4 轨即便指向 TC 字体仍然乱码。
⇒ 规则：cmap 覆盖只说明「码位在表里」，不说明引擎真用它画、也不说明该语言变体的字形能被接受；字形问题以游戏内截图/人工确认为准，离线结果只能当线索。

### 8.3 运行期探针可以随便用，但只能在测试构建里

`System.inform` 是最可靠的运行期判据（能直接读出 `LanguageTags`、`getPlacedPath`、`kag.chDefaultFace` 之类的内部状态），测试阶段尽管用。代价是：`after-init` 里弹窗会让主窗口底部留一条白边（重启恢复），弹窗还会阻塞初始化，所以抓取脚本要即时关闭。
⇒ 边界：**发布物里不许出现探针**。`script/build_patch.py` 的 `verify()` 会对钩子做 `System.inform` / `Debug.notice` / `getPlacedPath` 检查并判失败，只有 `--allow-probe` 的测试构建才豁免。另外运行期试验前备份 `%APPDATA%\ぱれっと\nine_kokoiro`，收尾一律 `WM_CLOSE` 优雅退出，不 `Stop-Process -Force`。

### 8.4 别脚本化连点启动游戏：会撞 0xc0000142

症状：脚本反复 `Start-Process` 启动游戏（还夹着 `tasklist` 判定失误导致的重复拉起），Windows 报 `应用程序无法正常启动(0xc0000142)`（DLL 初始化失败），进程挂着不退；同一时刻 `steam.xp3`/`patch3.xp3` 的 md5 与构建产物一致。
⇒ 规则：这类错误是**运行环境/进程堆积**问题（桌面堆耗尽、单实例锁、残留实例），不是归档损坏；一次只跑一个实例，启动前先确认无残留（`tasklist | findstr nine_kokoiro`），不在循环里自动重启；玩家端遇到 0xc0000142 先杀干净进程（或重启机器）。

### 8.5 归档域别名只对归档里第一条条目生效，scn 交付必须走松散目录

症状：加了第 4 轨后，开场 `a01` 是简中，`a02` 起回日文。查法：给 patch3 里 `a02` 的**日文块**首句加 `JPMARK:` —— 游戏里看不到，说明引擎**根本没读 patch3 的 a02**；把同一批 scn 放进 `<游戏目录>/scn/`（钩子注册 `System.exePath + "scn/"`）后 `JPMARK` 与四轨简中都生效。
⇒ 规则：`patch3.xp3>scn/` 的域别名只对「开场那种裸名请求」有效；后续章节的取法不同（`getPlacedPath`：裸名 → patch3，`scn/xxx.scn` 全路径 → data.xp3），双前缀别名 `scn/scn/xxx.scn` 也无效（结构依据见 `doc/engine-mechanics.md` §3.1）。
⇒ 规则：别拿一个脚本的生效情况推断整包生效；覆盖类方案要用「在官方文件里埋标记」验证覆盖面（JPMARK 法），而不是看某一句对不对。

### 8.6 自建 xp3 的索引：`hnfn` 必须每个文件一条

官方打包器写的是「每个文件一条 `hnfn`」（hnfn 全部在前、File 在后；`data.xp3` 943/944、`adult.xp3` 925/925）。本项目早期把全部名字塞进一条 `hnfn`，引擎只认第一条，于是 `addAutoPath("patch3.xp3>scn/")` 只暴露第一个 scn，其余裸名请求全落回 `data.xp3` —— 表现像「域别名只认第一条」，实则是自己把索引写坏了。
⇒ 自建归档一律照官方结构写；判据用「换顺序看赢家」+「给目标文件埋标记看游戏内是否出现」，不要只看某个脚本是否生效。

### 8.7 字体运行期注册可以，但要把「谁实例化 PreRenderFontEx」算进时机

`PreRenderFontEx.AddTrueTypeFont` 依赖 `global.PreRenderFontEx` 与 `System.addFont`：前者在 `sysscn/PreRenderFontEx.tjs` 里只被赋成**类**，实例由游戏启动流程创建；后者在本作是现成的（`typeof System.addFont == "Object"`，不需要 `addFont.dll`）。
⇒ 在 `addAfterInitCallback` 里注册（此时两者就绪）会成功；若在实例就绪前调用、或重复 `KAGLoadScript("PreRenderFontEx.tjs")` 把实例覆盖回类，就会抛 `Cannot convert the variable type ((void) to Object)`。注册成功后别名可直接被 `kag.chDefaultFace` / `scflags["langUserFontFace3"]` 使用。

### 8.8 「更早注入」要先证明时机，不是证明路径

`patch3.xp3>main/` 在索引修好后确实能被解析到（`getPlacedPath` 返回 patch3 路径），但 `main/*.tjs` 的加载早于钩子，覆盖**无效**；把 `ConfigEx.tjs` 放进更早注册的 `steam.xp3` 则直接把引擎打到 Access Violation（空文件、两种编码都试过）。
⇒ 判据顺序应是「先证实该文件在注入点之后才被加载（埋标记看是否生效），再谈能不能放进去」；只验证路径解析会得出错误结论。

### 8.9 显示名漏翻的两种形态，以及外部补全语料怎么收

症状：实机有人名显示为 `ㄔㄨㄣㄈㄥ` / `ㄒㄧㄧㄚ` / `・ソフィーティア`。前者不是乱码、也不是缺字形，而是**官方 `cn` 轨用注音符号表示「只知发音、不知汉字」**（对应 `jp` 轨的 `ハルカ` / `ノア`），民汉只把正文换成了汉字，显示名那列照抄官方注音 → 直接上屏。

* 判定：注音 28 行全部落在官方 `cn` 的注音区间内（`a06` scene0 row60–338、`a08` scene3 row76–86）；`・ソフィーティア` 2 行的官方三轨 `name` 槽本来就是 `？？？`（玩偶说话，身份未揭示），民汉把 `speaker` 原样当了显示名。
* 规则一：`name` 槽**跟官方判定、跟民汉用字**——该不该露真名看官方（`？？？` 切换点逐行一致），露真名时用字跟民汉正文（`索菲` / `缇娅`，官方是 `蘇菲堤雅`）。
* 规则二：换掉注音**不泄底**——正文 `a06` scene0 row21 / scene7 row82 早已写出真名，`？？？` 段落一个没动。

外部补全语料（第三方提供的 `EP1-简中语料-给原作者` 包）的收纳纪律：

* 只按 `(script, scene, row)` **定点 patch**，不整体覆盖 jsonl：对方 `script` 字段写 `a01.txt`、`_index` 无 `hash`、字段顺序也不同，直接复制会让 git diff 变成 9327 行全量，并且丢掉 `a01.txt.scn` 的写法。
* 先对拍再采信：对方自述 184 行改动，其中 89 行我们语料**本来就是新值**，实际差异是 327 行显示名 + 28 行正文 + 2060 行 `plain`（后者产物侧无影响，因为 `extend_lang.py` 的 `plain` 是现算的）。
* 验收：搬完逐行与来源比残差 0，`verify_extract` / `extend_lang` / `verify_lang4` 问题项 0，行内标记（`%p-1;` / `%fuser;` / `\n`）总量与改前一致。

### 8.10 别把外部构建的 `patch3.xp3` 当交付物

外部拿到/别人给的 `patch3.xp3`，md5 与大小只要与 `releases/` 不一致就说明是不同构建——文本同源只能说明语料对得上。交付必须自己重跑 `extend_lang` → `build_patch` → `verify_lang4`，不要拿外部包当交付物。

### 8.11 plain/plain2 的真实语义：读音版 vs 基字版，且必须删控制码

症状：`plain_of()` 把 `[しろみつがわ,3]白巳津川` 换成 `しろみつがわ` 却**没删后面 3 个基字**，也不删 `%p-1;%fＭＳ ゴシック;` 这类控制码，结果产物 plain 里残留 `%…;`；同时 `tool/mdf.py` 与 `doc/text-model.md` 把两槽写反了（称 `plain` 去 ruby、`plain2` 只留基字）。

* 正确语义（以官方数据反推，**而不是看字段名猜**）：`plain` = ruby 展开成**读音**，`plain2` = ruby 展开成**基字**；两者都删行内标记与 `\n`。
* ruby 的基字跨度是 **N+1**（N 是 `[よみ,N]` 的第二参数，不是基字总数）：`[しろみつがわ,3]白巳津川` → 读音 7 字、基字 3 字 = 3+1。
* arity 的触发条件是「正文含行内标记」，不是「有 `\n`」：jp 2444 个 arity-4 = 2395 含换行 + 49 只含控制码。

⇒ 规则：改这类“格式语义”先用**官方数据当 oracle** 反推（`tool/mdf.plain_variants()` 对 4839 个 arity-4 块命中 4839/4839，含 100 个带控制码的块；回归脚本 `script/verify_plain.py`），再改代码；不要根据旧注释/字段名推。同时：**不要自作聪明加“arity 必须与正文标记匹配”的闸**——官方 `cn` 的 arity 与民汉译文标记并不对应（330 行 cn 有 plain 而 sc 正文无标记、56 行相反），第 4 块只能搁抄 cn。

### 8.12 UI 文案有一半是「烘死的位图」，不在 ini/txt 里

症状：实机设置页有「前进到下一个**选择肢**的确认」「改变已选择过的**选择肢**颜色」这种直搬日文汉字的词，但 `syslangtext_sc.ini` / `help_conf_sc.txt` 里全是「选项」，grep 不到。

* 原因：界面标签文字被 **烘进位图**（`uipsd/sc/*_sc.pimg`），而 `syslangtext` 只管菜单/按钮这类动态文字。实测四套写法并存：`conf_sys_sc`/`conf_dlg_sc`/`dialog_sc` 用「**选择肢**」、`conf_key_sc`/`message_sc` 用「**选择项**」、我们的 ini/txt 用「**选项**」、官方繁中用「**選擇肢**」。注意 `dialog_sc_17/18` 才是**运行时确认框**（「确定回到前一个选择肢吗」），`conf_dlg_sc_2` 只是设置页里那排「XX 的确认」图标说明，两者都要改。
* 定位方法：先 `grep` 不到就 **OCR**（Windows `Windows.Media.Ocr`，透明图叠白/黑底各识别一次，3 倍放大）。OCR 会认错字（把「肢」认成「吱」、「项」认成「顶」），所以**只按单字搜**（择/選/肢/项/項）再做人工核对；把每张 pimg 的文字条竖排成一张「对照页」逐条看，比逐图打开可靠。
* 改图链路：`uipsd/sc/*_sc.pimg` 是 **PSB v2 + TLG6**（官方是 v3 + TLG5），`tool/psb.py` 解不了；TLG6 也没有 Python 解码器。做法：GARbro `TlgFormat` 解 TLG6 → PNG（一次性）→ 改字 → TLG5 写回（引擎两种都读）。

⇒ 规则：改 UI 文案前先判定它属于「文本」还是「位图」。**改完必须做「原图/改后」逐条对照**（把每处上下拼成一张对照页）：OCR 会把「跳过」认成「确定」、「重放」认成「播放」、「变更游戏设定」认成「更改初始设定」，只靠 OCR 转录重排会静默改错字。位图那侧必须**先量字体与笔画**再动手：本作是华康圆体 W9、字号 16（设置/确认页）与 17–18（快捷键页，逐行不同）；直接渲染会比原图粗 ~20%，用「4× 超采样 + alpha 减 40 + 盒式降采样」才能对齐墨量（实测 1.00×、IoU 0.706）。摆放位置用模板匹配（先 1-D 列投影粗对齐、再局部 IoU 细化）确定，比手动量 bbox 可靠——尤其遇到 keycap/引导线贴着文字的时候。

## 9. 无离线证据的路径必须真的带回退实现

症状：本项目的验收全部是离线证据，`patch.xp3` 能否被引擎直接接受（免 DLL）没有离线证明。
⇒ 规则：交付物必须**真的**带上 `version.dll` 回退路径（不是只在文档里写一句），并在 `releases/README.txt` 里写明。

## 10. 归档内**路径前缀**会丢，回读自证会掩盖它

症状：用 `os.path.relpath(file, indir)` 当归档路径、而 `--indir` 指向只含文件名的目录（`tmp/build/scn/`）时，别名退化成 `a01.txt.scn` + `md5("a01.txt.scn")`，引擎真正查找的 `md5("scn/a01.txt.scn")` 根本不存在；更糟的是回读校验复用同一个 `aliases()`，于是「三别名齐备、回读通过」变成了自证。

⇒ 硬闸（`script/build_patch.py`）：

* 归档内路径必须显式带前缀（`scn/` 域即 `scn/<名>`），别名 = `全路径 / basename / md5(全路径)` 且去重；
* 命名约定必须拿**别人的归档**核对：`md5(全路径)` 要同时存在于官方 `data.xp3` 与本补丁；
* 回读校验不能只验「我写了什么」，还要验「引擎会按什么键找」。

## 11. 注册与优先级

依据：`doc/engine-mechanics.md` §3/§4。

1. **XP3 索引必须有 `hnfn` 表**（`adlr → 真名`），否则引擎按真名找不到条目（表现为 `steam.tjs not found`）。条目名 = `md5(UTF-16LE 真名)`。
2. **`File` 内 chunk 顺序**：`time, adlr, segm, info`；加密条目 `segm.flags = 1`（zlib），`info.zsize` 同步。
3. **`.sig` 不参与引擎校验**（替换 `steam.xp3` 后游戏照常启动，`.sig` 仍是官方的）。
4. **`adult.xp3` 不是"覆盖"而是"补充"**：925 条里 924 条是 `data.xp3` 没有的新文件，唯一重叠是那个 `$$$ This is a protected archive…txt` 占位。
5. **`@if (DEBUG)` 是编译期指令**，release 版整块剔除 —— 别指望 DEBUG 分支里的脚本会加载。
6. **语言菜单/系统设置**：`main/default.tjs` 的 `multiLangFirstTag = "en"`，首次启动（或配置丢失）会回落英文；玩家手动切一次「繁體中文」后即保持，与补丁无关。

## 12. TLG5 不是 zlib，首行 alpha 也不特殊

`uipsd/*.pimg` 的位图是 TLG5（`TLG5.0\0raw\x1a`）。两个坑：

- 平面数据用的是 TVP 自带的 **LZSS**（4096 字节滑窗，跨块/跨平面连续复用），不是 zlib；
  拿 `zlib.decompress` 去试只会得到「不是流」的结论，浪费时间。
- 解码端首行的 alpha **和别的行一样以 0 为基准累加**。GARbro 的 C# 移植在首行分支把 alpha
  写死成 `0xff`，照抄会导致「自己编的图回放正常、进游戏却是全透明」——实测把标题图编进去后三行标签整块消失，就是这个偏差。判据：解官方 `conf_lang.pimg` 的 `14.tlg`，透明背景应占大头（alpha=0 ≈ 3.9 万像素），文字像素 alpha≈255。

## 13. PSB chunk 表要照抄对齐，`.func` 也是加扰文本

- 改 `pimg` 里的位图资源要重排 chunk 表：官方把每个 chunk 起点按 **4 字节对齐**，两张表后面还有
  对齐填充。不照抄的话，「原样替换」都不能逐字节往返，也容易把后面的数据整体错位。验证方式：`replace_resources({})` 与「同内容替换」都必须与原文件逐字节一致。
- `uipsd/*.func`（UI 布局脚本）和 `syslangtext`、`help` 一样是 **TVP 加扰文本（mode 1）**。
  把 UTF-8 明文塞进归档，引擎会直接报`option.ks 行:20 Cannot convert given narrow string to wide string` 然后崩在设置页。打包时的文本扩展名要包含 `.func`。

## 14. 合成粗体不算字体；字重差异要量化后再改

- GDI+ 的 `FontStyle.Bold` 在字体没有粗体面时会**合成**假粗体：笔画被均匀加粗、字面宽度变化，和真正的粗体设计不是一回事。拿合成粗体去做「哪种字体更像」的对照，会得出错误结论（本项目就先把「华康圆体 W5 + 合成 Bold」误判成最像）。现在 `script/render_ui_labels.ps1` 遇到非真实字重直接报错退出。
- 判断「粗/细」不要只靠眼睛：把候选与参照都按「每像素墨覆盖率」量化（按各自背景归一化），民汉 UI 贴图 = 0.400，华康圆体 W9 = 0.437、W7/W5 ≈ 0.30、思源圆黑体 ≈ 0.20，一眼就能看出候选差在哪个方向，避免在「粗一点/细一点」之间来回返工。

## 15. PowerShell 脚本必须带 UTF-8 BOM（Windows PowerShell 5.1 按 ANSI 读）

`script/render_ui_labels.ps1` 用 `powershell.exe` 跑时，脚本文件若是**无 BOM 的 UTF-8**，5.1 会按当前 ANSI 代码页解释：中文注释被拆成乱码、甚至把注释行当命令执行（报 `The term 'System.Drawing' is not recognized`），本会话就在这上面浪费过一轮。约定：

- 仓库里的 `.ps1` 一律存成 **UTF-8 with BOM**（`path.write_text(s, encoding="utf-8-sig")`）；
- 需要传中文参数时不要塞进命令行/脚本字面量，改为**写 JSON 传路径**（本项目的 `--Spec` 就是这么做的），
  中文只在 JSON 里出现，脚本本身保持 ASCII；
- 用 Python 改写 `.ps1` 时先 `read_text(encoding="utf-8-sig")` 再 `write_text(..., encoding="utf-8-sig")`，
  否则会把 BOM 当普通字符读进来、写回变成**双 BOM**，PowerShell 直接把首行当命令。

## 16. 不要用脚本模拟点击/按键来驱动游戏做验证

为了拿设置页截图，写过一批 `SendKeys`/`mouse_event` 脚本（按坐标点 Config、按 `Alt+M`+`O` 开菜单）。结果不可靠：窗口位置/缩放/DPI 一变坐标就漂，一次误点把「Config」点成了「End Game」，还顺带触发了退出确认框；抓到的截图是退出框而不是设置页，据此得出的"链路失效"判断也是错的。
⇒ 规则：实机验证的截图与现象由**人工**提供（或人工操作后截图），`tmp/` 里不留模拟输入脚本；探针弹窗同理，弹出来人工看、人工关。真正需要自动化的是**离线闸**——结构、槽位、回读、往返重建、文本行数这些都能在 Python 里判定，不必驱动 GUI。


## 17. 跨作差异先做二进制比对，别一上来就假设算法变了

第 5 作（9-nine-NewEpisode）解不开时，第一反应是「算法换了」，其实 `nine_newEP.exe` 与第 1 作（去 DRM 版）的 `.text` **逐字节相同**，`table` 以外的地址全等；差异只在 `.rdata` 里一小段：`"module\0" + u16 + u32 + zlib(PE)`——一个内嵌插件（旧作 `cxdec_tpm.dll` / 新作 `cxdec.tpm.dll`）。定位方法很简单：按节表逐段比较两个 exe，把差异区间按上面那 7 字节头解包出来看导出表，就能立刻看出是「换插件」而不是「换算法」。

配套几条经验：

- **GARbro 的 `CxScheme` 只按标题索引，没收录的构建不要猜参数**：参数优先从模块自带数据里读（本作是 `--data--PARAMS` / `TABLE` 两段自描述数据），读不到就调插件本体算。
- **order 数组的方向最容易搞反**：插件里是「index = form，value = 命中该 form 的随机值」，GARbro 是「index = 随机值，value = form」，两者互为逆排列。方向错了 RNG 消耗序列整体错位，表现是「一条都解不开」，很容易误判成算法错误。
- **生成器是运行时产物时，别重写生成器**：把内嵌模块当 DLL 加载、直接调它自己的求值函数（本作 `sub_10001980`），密钥算一次缓存成 JSON，之后就是纯 Python；重写 128 lane 的代码生成 + 解释执行性价比极低，而且极难自证等价。
- **密钥只与 `adlr` 有关**：同内容的多条别名天然共享一条密钥；`adlr` 也是明文 adler32，能用它反查「解出来的明文对不对」。
- **隔行 PNG 的原始长度不等于 `w × channels × depth × h`**：`rule/*.png` 全是 Adam7 隔行，若按非隔行公式校验 IDAT 长度，会把 116 张「解密完全正确」的图判成失败。校验要么按隔行算，要么退化成「inflate 完整 + CRC 全过」。
