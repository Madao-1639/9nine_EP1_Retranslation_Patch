"""Enigma Virtual Box（EVB）虚拟文件系统读取。

**这不是 krkr 引擎能力**，是第三方打包器（Enigma Virtual Box）的容器格式：它把一堆
文件塞进宿主 PE 的 `.enigma1` 段尾部（或者单独存成外部 `.pck`），并在进程里挂成
虚拟盘。本项目遇到的是民汉补丁（第 4/5 作）：`nine_*_chs.exe` 与 `chsdata.pck`。

格式来源：`GalRevserse/evbunpack`（mos9527, v0.2.6）的 `pe_external_tree` 实现；本文件
是纯标准库重写，不依赖 evbunpack，也不依赖 `aplib`（理由见文末「分块压缩」）。

## 布局（PE-external 变体）

```
偏移 0           EVB_PACK_HEADER   4s("EVB\\0") + 60s
+0x40            EVB_NODE_MAIN     u32 size | 8s | u32 objects_count
之后逐节点：
  EVB_HEADER_NODE   u32 size | 8s | u32 objects_count
  EVB_NODE_NAMED    u16 名（UTF-16LE，双 0 结尾）| u8 type
  type == 2（文件） EVB_NODE_OPTIONAL_FILE
                    2s | u32 original_size | 4s | 8s×3（三个 FILETIME）| 15s | u32 stored_size
  type == 3（目录） 25 字节（时间等）
```

文件内容区起点 = `魔数 + 0x40 + 16 + main.size - 12`，命名顺序**即**文件系统树的
前序遍历顺序；文件按 `stored_size` 依次紧排。目录 `%DEFAULT FOLDER%` 表示「虚拟根」。

**两种载体**（本项目的两个作各命中一种）：

| 载体 | 魔数位置 | 例 |
|---|---|---|
| exe 内嵌 | `PE` 的 `.enigma1` 段内 | `nine_new_chs.exe`（`EVB\\0` 在 `0x435cce`） |
| 外部包 | 文件偏移 0 | `chsdata.pck`、`update.pck` |

**节点里的 `offset` 是相对文件开头的绝对偏移**（因为 `parse()` 是在整份文件上从魔数开始的，
内容区起点已含魔数），`read()` 直接用，不再加偏移。这一点踩过坑：早期版本把 offset 当
相对魔数又加了一次，外部包（魔数为 0）看不出差别，exe 内嵌时会读到错位置。

## 分块压缩：只报错，不解压

`stored_size != original_size` 的条目是 EVB 的「分块压缩」模式（每块 aPLib，块长表
8 字节头 + 每 3 个 u32 取一个长度）。**本项目接触过的全部 4 个真实包（第 4/5 作 663 个
条目）与 evbunpack 自带的 11 个测试包，压缩条目数均为 0**，因此没有真实样本可验证
aPLib 解码器。按「报错优先」原则这里不实现，遇到就抛 `EvbError`：

> TODO(evb): 需要时可移植 aPLib（evbunpack-rs 的纯 Rust 实现可作参照），并用真实压缩
> 包验证后启用。

宁可报错，也不放一个没跑通过的分块解压器——解错了会静默产出坏文件。

## 用法

```python
from tool import evb
nodes = evb.open_package(pkg_path)
for kind, path, node in evb.tree(nodes):
    if kind == "F":
        blob = evb.read(pkg_path, node)     # 该文件明文
evb.extract(pkg_path, outdir, png=True)     # 落盘（*.tlg 解成 PNG）
```
"""

from __future__ import annotations

import os
import struct

EVB_MAGIC = b"EVB\x00"

NODE_TYPE_MAIN = 0
NODE_TYPE_FILE = 2
NODE_TYPE_FOLDER = 3

DEFAULT_FOLDER = "%DEFAULT FOLDER%"

_PACK_HEADER_SIZE = 64       # EVB_PACK_HEADER：4s + 60s
_NODE_HEADER_SIZE = 16       # EVB_HEADER_NODE / EVB_NODE_MAIN：u32 + 8s + u32
_FILE_OPT_SIZE = 53          # EVB_NODE_OPTIONAL_FILE
_FOLDER_OPT_SIZE = 25        # 目录节点附带的 25 字节


class EvbError(Exception):
    pass


class Node:
    """文件系统树的一个节点。`offset` 是**相对文件开头**的内容偏移（main 节点为 0）。"""

    __slots__ = ("kind", "name", "objects_count", "offset", "stored_size", "original_size")

    def __init__(self, kind: str, name: str = "", objects_count: int = 0,
                 offset: int = 0, stored_size: int = 0, original_size: int = 0):
        self.kind = kind                  # "M" 主节点 / "D" 目录 / "F" 文件
        self.name = name
        self.objects_count = objects_count
        self.offset = offset
        self.stored_size = stored_size
        self.original_size = original_size

    def __repr__(self) -> str:
        if self.kind == "F":
            return f"<File {self.name!r} off={self.offset:#x} {self.stored_size}B>"
        return f"<{self.kind} {self.name!r} children={self.objects_count}>"


# ------------------------------------------------------------------ 魔数定位
def find_magic(data: bytes) -> int:
    """-> `EVB\\0` 的文件偏移；找不到返回 -1。"""
    return data.find(EVB_MAGIC)


# ---------------------------------------------------------------- 节点解析
def _read_cstr16(data: bytes, pos: int) -> tuple[str, int]:
    """读一个双 0 结尾的 UTF-16LE 字符串，返回 (str, 新位置)。"""
    start = pos
    n = len(data)
    while pos + 1 < n:
        if data[pos] == 0 and data[pos + 1] == 0:
            raw = data[start:pos]
            return raw.decode("utf-16-le", "replace"), pos + 2
        pos += 2
    raise EvbError(f"文件名在 {start:#x} 处没有终结符")


def parse(data: bytes, magic: int | None = None) -> tuple[list[Node], int]:
    """解析节点表。-> (nodes, magic)。`nodes[0]` 是主节点，之后是前序遍历的节点序列。"""
    if magic is None:
        magic = find_magic(data)
    if magic < 0:
        raise EvbError("找不到 EVB\\0 魔数（不是 Enigma Virtual Box 包）")

    pos = magic
    if data[pos:pos + 4] != EVB_MAGIC:
        raise EvbError(f"魔数校验失败：偏移 {magic:#x} 处应为 EVB\0，实为 {data[pos:pos+4]!r}")
    pos += _PACK_HEADER_SIZE

    if pos + _NODE_HEADER_SIZE > len(data):
        raise EvbError(f"主节点越界：偏移 {pos:#x} 起需 {_NODE_HEADER_SIZE} 字节，文件仅 {len(data)}")
    main_size, _pad, main_count = struct.unpack_from("<I8sI", data, pos)
    pos += _NODE_HEADER_SIZE
    nodes = [Node("M", objects_count=main_count)]
    # 文件内容区起点：主节点结束后 main.size - 12 字节处
    content = pos + main_size - 12
    # 怪癖（照抄 evbunpack `pe_external_tree`）：主节点之后要**回退 1 字节**才是第一个
    # 头节点的起点。这不是笔误——不回退会把下一个 u32 读成 0，整棵树只解出主节点。
    pos -= 1

    max_count = 0
    seen = 0
    while True:
        if pos + _NODE_HEADER_SIZE > len(data):
            break
        try:
            _size, _pad2, count = struct.unpack_from("<I8sI", data, pos)
        except struct.error:
            break
        pos += _NODE_HEADER_SIZE
        try:
            name, pos = _read_cstr16(data, pos)
        except EvbError:
            break
        if pos >= len(data):
            break
        ntype = data[pos]
        pos += 1

        if ntype == NODE_TYPE_FILE:
            if pos + _FILE_OPT_SIZE > len(data):
                break
            original = struct.unpack_from("<I", data, pos + 2)[0]
            stored = struct.unpack_from("<I", data, pos + _FILE_OPT_SIZE - 4)[0]
            pos += _FILE_OPT_SIZE
            nodes.append(Node("F", name, 0, content, stored, original))
            content += stored
            seen += 1
        elif ntype == NODE_TYPE_FOLDER:
            pos += _FOLDER_OPT_SIZE
            # `%DEFAULT FOLDER%` = 虚拟根，折叠成空名（路径就不会以它开头）
            nodes.append(Node("D", "" if name == DEFAULT_FOLDER else name, count))
            max_count += count
            seen += 1
        else:
            break
        if max_count and seen > max_count:
            break

    return nodes, magic


def open_package(pkg_path: str) -> list[Node]:
    """读包并返回节点表（`Node.offset` 是可直接 seek 的文件绝对偏移）。"""
    data = _read(pkg_path)
    nodes, _magic = parse(data)
    return nodes


def tree(nodes: list[Node]) -> list[tuple[str, str, Node]]:
    """前序节点表 -> `[(kind, path, node)]`，path 是完整的包内路径。

    `%DEFAULT FOLDER%` 折叠成空（即虚拟根），所以路径不会以它开头。
    """
    out: list[tuple[str, str, Node]] = [("M", "", nodes[0])]
    pos = 1

    def walk(prefix: str, count: int) -> None:
        nonlocal pos
        for _ in range(count):
            if pos >= len(nodes):
                return
            n = nodes[pos]
            pos += 1
            path = f"{prefix}/{n.name}" if prefix else n.name
            if n.kind == "D":
                out.append(("D", path, n))
                walk(path, n.objects_count)
            else:
                out.append(("F", path, n))

    walk("", nodes[0].objects_count)
    return out


# ------------------------------------------------------------------ 取内容
def _read(pkg_path: str) -> bytes:
    with open(pkg_path, "rb") as fp:
        return fp.read()


def read(pkg_path: str, node: Node) -> bytes:
    """取一个文件节点的明文内容。压缩条目会抛 `EvbError`（见模块 docstring）。

    `Node.offset` 已是文件绝对偏移（`parse()` 在整份文件上从魔数开始算），直接 seek。
    """
    if node.kind != "F":
        raise EvbError(f"不是文件节点：{node!r}")
    if node.stored_size != node.original_size:
        raise EvbError(
            f"{node.name}（偏移 {node.offset:#x}）：该包用了 EVB 分块压缩"
            f"（stored {node.stored_size} != original {node.original_size}），"
            f"本库未实现 aPLib 解码（见 tool/evb.py 文末）")
    with open(pkg_path, "rb") as fp:
        fp.seek(node.offset)
        blob = fp.read(node.stored_size)
    if len(blob) != node.stored_size:
        raise EvbError(f"{node.name}（偏移 {node.offset:#x}）：读到 {len(blob)} 字节，期望 {node.stored_size}（文件被截断？）")
    return blob


# -------------------------------------------------------------------- 落盘
def iter_files(pkg_path: str, *, png: bool = False,
               only: tuple[str, ...] | None = None):
    """解包生成器：`(path, payload, note)`，**不落盘**。

    `png=True` 时 `*.tlg` 解成 PNG（用 `tool.tlg`，TLG5/6 与 `TLG0.0\0sds` 外壳都支持），
    `note` 是 "TLG6 703x374" 这类描述；否则 `payload` 是原字节、`note` 为空。
    落盘与幂等判断交给调用方（`extract()` 或脚本）。
    """
    nodes, _magic = parse(_read(pkg_path))
    for kind, path, node in tree(nodes):
        if kind != "F":
            continue
        if only and not path.startswith(only):
            continue
        blob = read(pkg_path, node)
        if png and node.name.lower().endswith(".tlg"):
            from tool import pngio, tlg
            img = tlg.decode(blob)
            yield (path[:-4] + ".png", pngio.write(img.width, img.height, img.rgba),
                   f"{img.kind} {img.width}x{img.height}")
        else:
            yield (path, blob, "")


def extract(pkg_path: str, out_dir: str, *, png: bool = False,
            force: bool = False, only: tuple[str, ...] | None = None) -> int:
    """把整个包解到 `out_dir`（保持包内路径）。返回写出的文件数。

    幂等：已存在且**产物字节数一致**的文件跳过（`force=True` 强制重写）。
    注意比的是写入后的文件大小，不是包里那份（`png=True` 时两者不同）。
    """
    os.makedirs(out_dir, exist_ok=True)
    written = 0
    for path, payload, _note in iter_files(pkg_path, png=png, only=only):
        dst = os.path.join(out_dir, path.replace("/", os.sep))
        os.makedirs(os.path.dirname(dst) or out_dir, exist_ok=True)
        if not force and os.path.exists(dst) and os.path.getsize(dst) == len(payload):
            continue
        with open(dst, "wb") as fp:
            fp.write(payload)
        written += 1
    return written
