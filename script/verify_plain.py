"""`tool/mdf.plain_variants()` 的回归测试：单元用例 + 官方数据 oracle。

用途：`plain` / `plain2` 两个槽的语义（读音版 / 基字版）是从官方 scn 反推出来的，
规则改动必须重跑本脚本，命中数不是 4839/4839 就说明改坏了。

用法（从项目根执行）：

    mamba run -n GalRev python script/verify_plain.py

判据：
  1. 单元用例全过（含 ruby、控制码、`\\n`、颜色标记）；
  2. 官方 17 个 scn 的 **全部 4839 个 arity-4 语言块**逐值吻合。

退出码 0 = 全过。
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tool import mdf

NL = mdf.NEWLINE

# (正文, 期望 plain(读音版), 期望 plain2(基字版))
CASES = [
    ("abc", "abc", "abc"),
    ("a" + NL + "b", "ab", "ab"),
    # ruby：`[よみ,N]` + 后随 N+1 个基字
    ("俺の『[しろみつがわ,3]白巳津川』が" + NL + "スポンサー",
     "俺の『しろみつがわ』がスポンサー", "俺の『白巳津川』がスポンサー"),
    # 控制码与 ruby 混排
    ("学校%p-1;%fＭＳ ゴシック;――%p;%fuser;[はくせん,1]白泉学園" + NL + "の教師",
     "学校――はくせん学園の教師", "学校――白泉学園の教師"),
    # 颜色标记
    ("「#FF0000;赤#;」", "「赤」", "「赤」"),
]


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    bad = 0
    for text, want_read, want_base in CASES:
        got = mdf.plain_variants(text)
        if got == (want_read, want_base):
            print(f"OK   {got!r}")
        else:
            bad += 1
            print(f"FAIL {got!r}")
            print(f"     期望 {(want_read, want_base)!r}")
    print(f"\n单元用例：{len(CASES) - bad}/{len(CASES)} 通过")

    scn_dir = "resource/official_scn/scn"
    if not os.path.isdir(scn_dir):
        print(f"跳过 oracle：找不到 {scn_dir}")
        return 0 if bad == 0 else 1

    ok = miss = 0
    for fn in sorted(os.listdir(scn_dir)):
        if not fn.endswith(".scn"):
            continue
        script = mdf.MdfScript(open(os.path.join(scn_dir, fn), "rb").read(), fn)
        for msg in script.iter_messages():
            for blk in msg.blocks:
                if len(blk.plains) != 2 or blk.text is None:
                    continue
                got = mdf.plain_variants(blk.text)
                want = (blk.plains[0][0], blk.plains[1][0])
                if got == want:
                    ok += 1
                else:
                    miss += 1
                    if miss <= 3:
                        print(f"\nMISMATCH {fn} scene{msg.scene} row{msg.row} {blk.lang}")
                        print(f"  got  {got!r}")
                        print(f"  want {want!r}")
    print(f"官方 oracle：命中 {ok} / 不符 {miss}（判据 4839/0）")
    return 0 if bad == 0 and miss == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
