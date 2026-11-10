"""写「与官方同构」的补丁归档：Cx 变体头 + Cx 加密内容 + 每文件一条 `hnfn` + zlib 索引。

本作引擎只认这套形态（见 `doc/file-formats.md` §1 / §3.5、`doc/engine-mechanics.md` §3.1）：

    header  : XP3 签名 11 B | u64 伪索引偏移 0x17 | u32 1 | u32 0x80 | 5 B 填充 | u64 真索引偏移
    内容区  : 从 0x28 开始，逐条 zlib.compress(Cx.crypt(adler32(明文), 明文), 9)
    索引    : 先「每个文件一条 hnfn」（名字原文，UTF-16LE），再逐条 File（info 名 = md5(UTF-16LE 逻辑路径)）
              索引整体 zlib 压缩

`hnfn` 必须每文件一条：写成一条大 `hnfn` 时引擎只认得出第一条条目的名字，子域别名/裸名
都只能命中第一个文件（实测差异根因，见 `doc/engine-mechanics.md` §3.1）。

用途：容器写法只有这一份实现，打包脚本只负责决定「装哪些文件」（`script/build_patch.py`
写 `patch3.xp3` 的 17 个四块 scn + UI 语料；`script/pack_ep5.py` 写第 5 作的包）。新增补丁包时直接复用它，不要另抄一份。

索引形态按官方包对齐：第 1 作是 `md5` 条目名 + 每文件一条 `hnfn`（默认值），第 5 作是真名 + 无 `hnfn`
（`name_style="real"`、`emit_hnfn=False`）。
"""

from __future__ import annotations

import ctypes
import hashlib
import io
import struct
import zlib

from . import xp3

PROT = xp3.TVP_XP3_FILE_PROTECTED


def md5_name(path: str) -> str:
    """索引里的条目名 = md5(UTF-16LE 逻辑路径)。"""
    return hashlib.md5(path.encode("utf-16-le")).hexdigest()


def write_archive(path: str, files: list[tuple[str, bytes]], crypt,
                  name_style: str = "md5", emit_hnfn: bool = True) -> int:
    """把 `[(逻辑路径, 明文)]` 写成 Cx 加密的补丁归档，返回文件大小。

    `crypt` 只要实现 `crypt(adler32, 明文) -> 密文`：`tool.cx.CxCrypt`（第 1–4 作）、
    `tool.cxdec_v2.KeyCrypt`（第 5 作）都满足；加解密同一算式，同一个对象读写通用。

    `name_style` / `emit_hnfn` 决定索引形态，两作官方包不一样：

    | 作 | `info` 里的条目名 | `hnfn` |
    |---|---|---|
    | 第 1 作（本作，`data.xp3` + 我们的 `patch3.xp3`） | `md5(UTF-16LE 路径)` | **每文件一条**（裸名/子域靠它命中） |
    | 第 5 作（9-nine-NewEpisode 官方包） | **真名**（`scn/e01a.txt.scn`） | 无 |

    `name_style` 取 `"md5"` / `"real"`；默认值与第 1 作一致，改默认会破坏既有补丁包。
    """
    out = io.BytesIO()
    out.write(xp3.XP3_SIG)
    out.write(struct.pack("<q", 0x17))
    out.write(struct.pack("<I", 1))
    out.write(struct.pack("<I", 0x80))
    out.write(bytes(5))
    idx_pos = out.tell()
    out.write(struct.pack("<q", 0))

    placed = []
    for name, plain in files:
        adlr = zlib.adler32(plain) & 0xFFFFFFFF
        packed = zlib.compress(crypt.crypt(adlr, plain), 9)
        off = out.tell()
        out.write(packed)
        placed.append((name, plain, adlr, packed, off))

    index = io.BytesIO()
    if emit_hnfn:
        for name, _plain, adlr, _packed, _off in placed:
            hn = struct.pack("<Ih", adlr, len(name)) + name.encode("utf-16-le")
            index.write(b"hnfn" + struct.pack("<q", len(hn)) + hn)

    for name, plain, adlr, packed, off in placed:
        nh = md5_name(name) if name_style == "md5" else name
        nbytes = nh.encode("utf-16-le") + bytes(2)
        info = xp3.Xp3Info_t()
        info.flags = PROT
        info.fsize, info.zsize, info.namelen = len(plain), len(packed), len(nh)
        segm = xp3.Xp3Segm_t()
        segm.flags = xp3.TVP_XP3_SEGM_ENCODE_ZLIB
        segm.offset, segm.fsize, segm.zsize = off, len(plain), len(packed)
        adlr_b = xp3.Xp3Adlr_t()
        adlr_b.hash = adlr
        chunks = (b"time" + struct.pack("<q", 8) + bytes(8)
                  + b"adlr" + struct.pack("<q", 4) + bytes(adlr_b)
                  + b"segm" + struct.pack("<q", ctypes.sizeof(xp3.Xp3Segm_t)) + bytes(segm)
                  + b"info" + struct.pack("<q", ctypes.sizeof(xp3.Xp3Info_t) + len(nbytes))
                  + bytes(info) + nbytes)
        index.write(b"File" + struct.pack("<q", len(chunks)) + chunks)

    idx_off = out.tell()
    out.seek(idx_off)
    packed_index = zlib.compress(index.getvalue(), 6)
    out.write(bytes([1]))
    out.write(struct.pack("<QQ", len(packed_index), index.getvalue().__len__()))
    out.write(packed_index)
    out.seek(idx_pos)
    out.write(struct.pack("<q", idx_off))
    blob = out.getvalue()
    with open(path, "wb") as fp:
        fp.write(blob)
    return len(blob)


def read_entries(path: str):
    """回读补丁归档：返回 `(fp, mmap, {逻辑名 -> entry})`，调用方负责 close。

    名字用 `hnfn` 里的原文重建（File 里是 md5），这样校验时能直接对上「逻辑路径」。
    """
    import mmap

    fp = open(path, "rb")
    mm = mmap.mmap(fp.fileno(), 0, access=mmap.ACCESS_READ)
    entries = {e.name: e for e in xp3.parse_xp3(mm, show_log=False) if e.name}
    return fp, mm, entries


def hnfn_names(path: str) -> dict[int, str]:
    """索引里 `hnfn` 登记的「adlr 哈希 -> 逻辑名」映射（用于审计条目名是否每文件一条）。"""
    import mmap

    data = open(path, "rb").read(0x28)
    with open(path, "rb") as fp:
        mm = mmap.mmap(fp.fileno(), 0, access=mmap.ACCESS_READ)
        try:
            idx_off = struct.unpack_from("<Q", data, 0x20)[0]
            zsize = struct.unpack_from("<Q", mm, idx_off + 1)[0]
            index = zlib.decompress(mm[idx_off + 17: idx_off + 17 + zsize])
        finally:
            mm.close()
    out = {}
    pos = 0
    while pos + 12 <= len(index):
        tag = bytes(index[pos:pos + 4])
        size = struct.unpack_from("<q", index, pos + 4)[0]
        body = pos + 12
        if tag == b"hnfn":
            inner, end = body, body + size
            while inner + 6 <= end:
                adlr = struct.unpack_from("<I", index, inner)[0]
                nl = struct.unpack_from("<h", index, inner + 4)[0]
                if nl <= 0 or inner + 6 + 2 * nl > end:
                    break
                out[adlr] = bytes(index[inner + 6: inner + 6 + 2 * nl]).decode("utf-16-le")
                inner += 6 + 2 * nl
        pos = body + size
    return out
