"""第 5 作（9-nine-NewEpisode）打包 —— 把松散文件写成 Cxdec V2 加密的 XP3。

与第 1 作的 `script/build_patch.py` 是同一容器写法（`tool/xp3build.write_archive`），
差别只有两处形态与一处密钥来源：

| 项 | 第 1 作 | 第 5 作 |
|---|---|---|
| 索引里的条目名 | `md5(UTF-16LE 路径)` | **真名**（官方包如此） |
| `hnfn` 名字表 | 每文件一条 | 无 |
| 内容密钥 | `adler32(明文)` → Cx 程序（`tool/cx.py` 本地算） | 同上哈希 → **插件本体**算（`tool/cxdec_v2.py`） |

用法（从项目根执行）：

    # 打包（srcdir 里的相对路径就是归档里的逻辑路径，'/' 分隔）
    mamba run -n GalRev python script/pack_ep5.py out/patch.xp3 <srcdir> \\
        --exe <nine_newEP.exe> [--keys resource/cx/keys_9nine_ep5.json]

    # 只要「同一内容重打包」时不必给 --exe：密钥缓存命中即可
    mamba run -n GalRev python script/pack_ep5.py out/patch.xp3 <srcdir>

要点：

* 内容 = `zlib.compress(encrypt(明文), 9)`，`adlr` = 明文 adler32 —— 与官方逐条同构；
  加密与解密同一算式，所以引擎的过滤器能直接读。
* **写完立刻回读**：重新解析产物、逐条解密、与输入明文逐字节比对（不过即失败），
  顺便复算每条 `adlr` 是否等于索引里的值。
* 新 plaintext（改过的文本）必然是新 `adlr`，也就是新密钥 —— 密钥缓存里没有的必须在
  `--exe` 下补算，脚本会把补算结果写回缓存。
"""

from __future__ import annotations

import argparse
import os
import sys
import zlib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tool import cxdec_v2, xp3build

PROFILE = "resource/cx/profile_9nine_ep5.json"
KEYS = "resource/cx/keys_9nine_ep5.json"


def collect(srcdir: str, only) -> list[tuple[str, bytes]]:
    """`[(逻辑路径, 明文)]`，路径一律 '/' 分隔、按名字排序（保证产物可复现）。"""
    files = []
    for root, _dirs, names in os.walk(srcdir):
        for name in names:
            path = os.path.join(root, name)
            rel = os.path.relpath(path, srcdir).replace(os.sep, "/")
            if only and not rel.startswith(tuple(only)):
                continue
            with open(path, "rb") as fp:
                files.append((rel, fp.read()))
    files.sort()
    if not files:
        raise SystemExit(f"{srcdir} 里没有可打包的文件")
    return files


def ensure_keys(args, files) -> dict:
    keys = cxdec_v2.load_keys(args.keys) if os.path.exists(args.keys) else {}
    missing = sorted({cxdec_v2.adler32(plain) for _n, plain in files} - set(keys))
    if not missing:
        return keys
    if not args.exe:
        raise SystemExit(f"密钥缓存缺 {len(missing)} 条 adlr（例 {[hex(h) for h in missing[:5]]}）；"
                         f"给 --exe <游戏exe> 现场补算")
    scheme = cxdec_v2.Scheme.from_json(args.profile)
    module = cxdec_v2.extract_embedded_module(args.exe)
    print(f"调插件补算 {len(missing)} 条密钥 ...", flush=True)
    keys.update(cxdec_v2.derive_keys(scheme, module, missing))
    cxdec_v2.save_keys(args.keys, keys)
    print(f"已写回 {args.keys}", flush=True)
    return keys


def verify_roundtrip(out_path: str, files, keys) -> int:
    """回读产物：解析 → 解密 → 与输入明文逐字节比对。"""
    import mmap

    fp = open(out_path, "rb")
    mm = mmap.mmap(fp.fileno(), 0, access=mmap.ACCESS_READ)
    try:
        entries = {e.name: e for e in cxdec_v2.entries(mm)}
        bad = []
        for name, plain in files:
            entry = entries.get(name)
            if entry is None:
                bad.append(f"{name}: 回读找不到条目")
                continue
            if entry.adlr.hash != cxdec_v2.adler32(plain):
                bad.append(f"{name}: 索引 adlr {entry.adlr.hash:#010x} 与明文不符")
                continue
            if not (entry.info.flags & 0x80000000):
                bad.append(f"{name}: 条目没有加密标记")
                continue
            got = cxdec_v2.decrypt(keys, entry.adlr.hash, cxdec_v2.read_entry(mm, entry))
            if got != plain:
                bad.append(f"{name}: 解密结果与输入不一致（{len(got)} vs {len(plain)} B）")
        extra = set(entries) - {n for n, _p in files}
        for name in sorted(extra):
            bad.append(f"{name}: 产物里多出来的条目")
        if bad:
            print(f"回读失败 {len(bad)} 条:")
            for line in bad[:10]:
                print("  ", line)
            return 1
        print(f"回读通过：{len(files)} 条逐字节一致")
        return 0
    finally:
        mm.close()
        fp.close()


def main(argv=None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("out", help="产物路径（*.xp3）")
    ap.add_argument("srcdir", help="待打包目录（相对路径即逻辑路径）")
    ap.add_argument("--exe", help="游戏 exe（密钥缓存缺条目时现场调插件补算）")
    ap.add_argument("--profile", default=PROFILE)
    ap.add_argument("--keys", default=KEYS)
    ap.add_argument("--only", nargs="+", help="只打包这些名字前缀")
    ap.add_argument("--md5-names", action="store_true", help="条目名用 md5（第 1 作形态，实验用）")
    ap.add_argument("--hnfn", action="store_true", help="附加每文件一条 hnfn（第 1 作形态，实验用）")
    args = ap.parse_args(argv)

    files = collect(args.srcdir, args.only)
    keys = ensure_keys(args, files)
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    size = xp3build.write_archive(args.out, files,
                                  cxdec_v2.KeyCrypt(keys),
                                  name_style="md5" if args.md5_names else "real",
                                  emit_hnfn=args.hnfn)
    print(f"写包 {args.out}: {len(files)} 条 / {size} B "
          f"(条目名 {'md5' if args.md5_names else '真名'}，hnfn {'有' if args.hnfn else '无'})")
    return verify_roundtrip(args.out, files, keys)


if __name__ == "__main__":
    sys.exit(main())
