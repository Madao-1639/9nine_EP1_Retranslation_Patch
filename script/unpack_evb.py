"""Enigma Virtual Box 包列举 / 提取（民汉补丁的 `*.exe` 与 `*.pck`）。

用法（从项目根执行）：

    # 列目录（不落盘）
    mamba run -n GalRev python script/unpack_evb.py list <pkg...>

    # 提取（幂等：已存在且大小一致则跳过）
    mamba run -n GalRev python script/unpack_evb.py extract <pkg> <outdir> [--png] [--force]

    # 只提某个目录（例：只看 UI 贴图）
    mamba run -n GalRev python script/unpack_evb.py extract <pkg> <outdir> --only Project/conf

`--png` 时把 `*.tlg` 解成 PNG（TLG5 / TLG6 / `TLG0.0\\0sds` 外壳都支持，走 `tool/tlg.py`），
其余文件原样复制。非图片的 `.tjs`/`.txt`/`.ks` 是 **UTF-16LE 明文**，不在这里转码——需要
文本来比对时按 UTF-16LE 读。

格式细节见 `tool/evb.py` 的模块 docstring 与 `doc/file-formats.md` §6。
"""

from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tool import evb


def cmd_list(args) -> int:
    for pkg in args.pkgs:
        data = open(pkg, "rb").read()
        magic = evb.find_magic(data)
        if magic < 0:
            print(f"===== {os.path.basename(pkg)}：没有 EVB 文件系统，跳过")
            continue
        nodes = evb.parse(data)[0]
        print(f"===== {os.path.basename(pkg)}  size={len(data)}  magic={magic:#x}")
        nfile = ndir = 0
        for kind, path, node in evb.tree(nodes):
            if kind == "M":
                print(f"  M 顶层 {node.objects_count} 项")
            elif kind == "D":
                shown = path + "/" if path else "(虚拟根) %DEFAULT FOLDER%"
                print(f"  D {shown:<44} children={node.objects_count}")
                ndir += 1
            else:
                print(f"  F {path:<44} stored={node.stored_size:>9} "
                      f"orig={node.original_size:>9} off={node.offset:#x}")
                nfile += 1
        print(f"  —— {ndir} 个目录，{nfile} 个文件")
    return 0


def cmd_extract(args) -> int:
    data = open(args.pkg, "rb").read()
    if evb.find_magic(data) < 0:
        raise SystemExit(f"{args.pkg}: 没有 EVB 文件系统")
    only = tuple(args.only) if args.only else None

    os.makedirs(args.out, exist_ok=True)
    done = skipped = 0
    total = 0
    for path, payload, note in evb.iter_files(args.pkg, png=args.png, only=only):
        dst = os.path.join(args.out, path.replace("/", os.sep))
        os.makedirs(os.path.dirname(dst) or args.out, exist_ok=True)
        # 幂等比的是**产物**字节数（--png 时 PNG 与 TLG 大小不同）
        if not args.force and os.path.exists(dst) and os.path.getsize(dst) == len(payload):
            skipped += 1
            continue
        with open(dst, "wb") as fp:
            fp.write(payload)
        total += len(payload)
        done += 1
        if args.verbose:
            print(f"{path:<46} {len(payload):>9}B {note}")

    print(f"{os.path.basename(args.pkg)}: 写出 {done} 个，跳过 {skipped} 个，"
          f"共 {total / 1e6:.1f} MB -> {args.out}")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_list = sub.add_parser("list", help="列目录，不落盘")
    p_list.add_argument("pkgs", nargs="+")
    p_list.set_defaults(func=cmd_list)

    p_x = sub.add_parser("extract", help="提取到目录")
    p_x.add_argument("pkg")
    p_x.add_argument("out")
    p_x.add_argument("--png", action="store_true", help="把 *.tlg 解成 PNG")
    p_x.add_argument("--force", action="store_true", help="覆盖已有文件")
    p_x.add_argument("--only", nargs="+", default=None,
                     help="只提这些路径前缀（例：Project/conf）")
    p_x.add_argument("-v", "--verbose", action="store_true")
    p_x.set_defaults(func=cmd_extract)

    args = ap.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
