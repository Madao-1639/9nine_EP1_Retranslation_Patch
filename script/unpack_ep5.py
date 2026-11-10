"""第 5 作（9-nine-NewEpisode）XP3 解包 —— M2 Cxdec V2 内容解密。

与 `script/unpack_xp3.py`（第 1–4 作，Cx 参数在 `resource/cx/profile_9nine.json`）并列：
本作的参数与插件内部地址在 `resource/cx/profile_9nine_ep5.json`，条目密钥缓存在
`resource/cx/keys_9nine_ep5.json`（1389 条 adlr，覆盖 `data.xp3` + `steam.xp3`）。

用法（从项目根执行）：

    # 校验：解密到内存 + 按扩展名自检，不落盘（推荐用小包/单条目）
    mamba run -n GalRev python script/unpack_ep5.py verify <xp3...> \\
        [--only scn/ bgimage/bg001a.png]

    # 提取（幂等：已存在且大小一致则跳过）
    mamba run -n GalRev python script/unpack_ep5.py extract <outdir> <xp3...> [--force]

    # 重算密钥（换了构建 / 出现索引外的 adlr）
    mamba run -n GalRev python script/unpack_ep5.py keys <游戏exe> <xp3...>

要点：

  * 解出来、改完之后要写回，用 `script/pack_ep5.py`（同一套参数与密钥缓存）。
  * 解密层的算式与 Cx 相同（`tool/cxdec_v2.py`），差别只在密钥怎么算；密钥缓存命中时
    整条流程是纯 Python，不需要游戏 exe。
  * 缓存没命中时：给 `--exe` 就现场调插件补算并写回缓存，否则报错并列出缺失的 adlr。
  * 文本类（`*.tjs`/`*.ks`/`*.txt`/`*.csv`/`*.ini`）写盘前按 `tool/krkr_text.py` 解扰成 UTF-8。
  * 判型：PNG = 签名 + 全 chunk CRC + IDAT 解压长度对 IHDR；PSB/TLG/OGG = 魔数；
    文本 = 解扰后 UTF-8 可解码且无 NUL。任何 BAD 都要当失败处理。
"""

from __future__ import annotations

import argparse
import collections
import mmap
import os
import sys
import zlib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tool import cxdec_v2, krkr_text, tjs2

PROFILE = "resource/cx/profile_9nine_ep5.json"
KEYS = "resource/cx/keys_9nine_ep5.json"

TEXT_EXT = (".tjs", ".ks", ".txt", ".csv", ".ini", ".stage", ".asd", ".func", ".sli")
PNG_SIG = bytes.fromhex("89504e470d0a1a0a")


def check_png(data: bytes) -> bool:
    """签名 + 全 chunk CRC + IDAT 完整 inflate；非隔行再核对原始尺寸。"""
    if data[:8] != PNG_SIG:
        return False
    p = 8
    idat = b""
    width = height = bit_depth = color = interlace = None
    while p + 12 <= len(data):
        ln = int.from_bytes(data[p:p + 4], "big")
        typ = data[p + 4:p + 8]
        body = data[p + 8:p + 8 + ln]
        crc = int.from_bytes(data[p + 8 + ln:p + 12 + ln], "big")
        if zlib.crc32(typ + body) & 0xFFFFFFFF != crc:
            return False
        if typ == b"IHDR":
            width = int.from_bytes(body[0:4], "big")
            height = int.from_bytes(body[4:8], "big")
            bit_depth, color, interlace = body[8], body[9], body[12]
        elif typ == b"IDAT":
            idat += body
        elif typ == b"IEND":
            inflater = zlib.decompressobj()
            try:
                raw = inflater.decompress(idat) + inflater.flush()
            except zlib.error:
                return False
            if not inflater.eof:
                return False
            if interlace:                      # Adam7 的原始长度不是简单乘积
                return bool(raw)
            channels = {0: 1, 2: 3, 4: 2, 6: 4}[color]
            row_bytes = (width * channels * bit_depth + 7) // 8
            return len(raw) == (row_bytes + 1) * height
        p += 12 + ln
    return False


def text_ok(data: bytes) -> bool:
    """TVP 加扰文本先解扰；其余按 UTF-8（允许尾部 NUL 填充）。"""
    if data[:2] == b"\xfe\xfe":
        try:
            krkr_text.decode_bytes(data)
            return True
        except Exception:
            return False
    body = data.rstrip(b"\0")
    for enc in ("utf-8", "cp932"):      # 引擎的 .txt/.sli 常见 Shift-JIS
        try:
            body.decode(enc)
            return True
        except UnicodeDecodeError:
            continue
    return False


def validate(name: str, data: bytes) -> str:
    """按扩展名判型。判据要能真正排除「解出来是乱码」，不能只看非空。"""
    ext = os.path.splitext(name)[1].lower()
    if ext == ".png":
        return "png ok" if check_png(data) else "png BAD"
    if ext in (".scn", ".pimg"):
        return "psb ok" if data[:4] == b"PSB\0" else "psb BAD"
    if ext == ".ogg":
        return "ogg ok" if data[:4] == b"OggS" else "ogg BAD"
    if ext == ".tlg":
        return "tlg ok" if data[:3] == b"TLG" else "tlg BAD"
    if ext in (".ttf", ".otf"):
        return "font ok" if data[:4] in (b"\x00\x01\x00\x00", b"OTTO", b"true", b"ttcf") else "font BAD"
    if ext == ".amv":
        return "amv ok" if data[:4] == b"AJPM" else "amv BAD"
    if ext == ".tjs":
        if data[:8] == tjs2.TJS_SIG:
            try:
                tjs2.load(data)
                return "tjs2 ok"
            except Exception:
                return "tjs2 BAD"
        return "text ok" if text_ok(data) else "text BAD"
    if ext in TEXT_EXT:
        return "text ok" if text_ok(data) else "text BAD"
    return "other"


def dest_path(outdir: str, name: str) -> str:
    # 官方有个超长文件名的「protected archive」警告 txt，Windows 下存不下
    leaf = name if len(name) < 150 else "_longname_" + os.path.splitext(name)[1].lower()
    return os.path.join(outdir, leaf.replace("/", os.sep))


def open_archives(archives):
    out = []
    for arch in archives:
        fp = open(arch, "rb")
        out.append((arch, fp, mmap.mmap(fp.fileno(), 0, access=mmap.ACCESS_READ)))
    return out


def collect_hashes(archives, only=None) -> list[int]:
    seen = []
    for arch, _fp, mm in archives:
        for entry in cxdec_v2.entries(mm):
            if only and not entry.name.startswith(tuple(only)):
                continue
            if entry.adlr.hash not in seen:
                seen.append(entry.adlr.hash)
    return seen


def ensure_keys(args, archives) -> dict:
    keys = cxdec_v2.load_keys(args.keys) if os.path.exists(args.keys) else {}
    missing = [h for h in collect_hashes(archives, args.only) if h not in keys]
    if not missing:
        return keys
    if not args.exe:
        raise SystemExit(f"密钥缓存缺 {len(missing)} 条 adlr（例 {[hex(h) for h in missing[:5]]}）；"
                         f"给 --exe <游戏exe> 现场补算")
    scheme = cxdec_v2.Scheme.from_json(args.profile)
    module = cxdec_v2.extract_embedded_module(args.exe)
    print(f"调插件补算 {len(missing)} 条密钥 ...", flush=True)
    keys.update(cxdec_v2.derive_keys(scheme, module, missing))
    if args.write_keys:
        cxdec_v2.save_keys(args.keys, keys)
        print(f"已写回 {args.keys}", flush=True)
    return keys


def run(args, write: bool) -> int:
    archives = open_archives(args.archives)
    try:
        keys = ensure_keys(args, archives)
        stats = collections.Counter()
        bad = []
        extracted = 0
        for arch, _fp, mm in archives:
            for entry in cxdec_v2.entries(mm):
                if args.only and not entry.name.startswith(tuple(args.only)):
                    continue
                plain = cxdec_v2.read_entry(mm, entry)
                if entry.info.flags & 0x80000000:
                    plain = cxdec_v2.decrypt(keys, entry.adlr.hash, plain)
                kind = validate(entry.name, plain)
                stats[kind] += 1
                if kind.endswith("BAD"):
                    bad.append(f"{os.path.basename(arch)}:{entry.name}")
                if write:
                    dest = dest_path(args.outdir, entry.name)
                    os.makedirs(os.path.dirname(dest) or args.outdir, exist_ok=True)
                    if not args.force and os.path.exists(dest) and os.path.getsize(dest) == len(plain):
                        continue
                    data = plain
                    if entry.name.lower().endswith(TEXT_EXT) and plain[:2] == b"\xfe\xfe":
                        data = krkr_text.encode_bytes(krkr_text.decode_bytes(plain)[1])
                    with open(dest, "wb") as f:
                        f.write(data)
                    extracted += 1
        total = sum(stats.values())
        print(("提取" if write else "校验") + f" {total} 条"
              + (f"，写盘 {extracted} 个文件 → {args.outdir}" if write else "（不落盘）"))
        print("判型:", dict(sorted(stats.items())))
        if bad:
            print(f"BAD {len(bad)} 条:", bad[:5])
            return 1
        return 0
    finally:
        for _arch, fp, mm in archives:
            mm.close()
            fp.close()


def cmd_verify(args) -> int:
    return run(args, write=False)


def cmd_extract(args) -> int:
    return run(args, write=True)


def cmd_keys(args) -> int:
    archives = open_archives(args.archives)
    try:
        hashes = collect_hashes(archives)
        keys = cxdec_v2.load_keys(args.keys) if os.path.exists(args.keys) else {}
        todo = [h for h in hashes if h not in keys]
        if todo:
            scheme = cxdec_v2.Scheme.from_json(args.profile)
            module = cxdec_v2.extract_embedded_module(args.exe)
            print(f"调插件求 {len(todo)} 条密钥 ...", flush=True)
            keys.update(cxdec_v2.derive_keys(scheme, module, todo))
        cxdec_v2.save_keys(args.keys, keys)
        print(f"密钥 {len(keys)} 条 → {args.keys}")
        return 0
    finally:
        for _arch, fp, mm in archives:
            mm.close()
            fp.close()


def main(argv=None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    def common(p):
        p.add_argument("--profile", default=PROFILE)
        p.add_argument("--keys", default=KEYS)
        p.add_argument("--only", nargs="+", help="只处理这些名字前缀")
        p.add_argument("--exe", help="游戏 exe（密钥缓存缺条目时现场调插件补算）")

    p = sub.add_parser("verify", help="解密到内存并自检，不落盘")
    p.add_argument("archives", nargs="+")
    common(p)
    p.add_argument("--no-write-keys", dest="write_keys", action="store_false",
                   help="补算出的密钥不写回缓存")
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("extract", help="解密并写到 outdir")
    p.add_argument("outdir")
    p.add_argument("archives", nargs="+")
    p.add_argument("--force", action="store_true")
    common(p)
    p.add_argument("--no-write-keys", dest="write_keys", action="store_false",
                   help="补算出的密钥不写回缓存")
    p.set_defaults(func=cmd_extract)

    p = sub.add_parser("keys", help="重算并更新密钥缓存")
    p.add_argument("exe")
    p.add_argument("archives", nargs="+")
    common(p)
    p.set_defaults(func=cmd_keys)

    args = ap.parse_args(argv)
    if getattr(args, "write_keys", None) is None:
        args.write_keys = True
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
