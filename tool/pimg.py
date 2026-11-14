"""`.pimg` 位图容器：**统一入口**，按内部 PSB 版本自动分派。

同一件工作（取/换某个 chunk 里的 TLG）在两个 PSB 版本上的做法不同，但调用方**不该关心**：

```python
from tool import pimg
f = pimg.open_pimg(data)          # v2 / v3 都行，返回同样的接口
blob = f.resource_bytes(3)
out  = f.replace_resources({3: new_tlg})
```

| 版本 | 实现 | 特点 |
|---|---|---|
| v2 | 本文件的 `PimgV2` | 头部 7 个 u32、无 checksum、chunk 数据在文件尾部；实测 chunk 紧密排列 |
| v3 | 委派 `tool/psb.PsbFile` | 9 个 u32 + `0x28` checksum、chunk 起点 4 字节对齐 |

要读 v3 的**对象图与字符串**（比如按图层名找 chunk），直接用 `tool/psb.py`；本模块只保证
「两个版本都能用同一套 chunk 读写」。

## v2 布局（本文件实现的部分）

```
0x00  "PSB\0"     0x04 u16 version(=2)    0x06 u16 header_encrypt(=0)
0x08  u32 × 7      [0] 恒 0（names 紧跟头部，无需偏移）
                   [1] offset_names         [2] offset_strings     [3] offset_strings_data
                   [4] offset_chunk_offsets [5] offset_chunk_lengths [6] offset_chunk_data
之后   names / strings / 对象图 / chunk 表 / chunk 数据
```

与 v3 的差别（本模块只依赖后两条）：

* **没有 `header_length`**，头部就是 `0x08 + 7*4 = 0x24` 字节；
* **对象图在 chunk 数据之前**，chunk 数据在整个文件尾部（其后只剩十几字节尾巴）；
* 三个 chunk 偏移在 `0x08` 起的第 5/6/7 个 u32 里（v3 是 `0x18`/`0x1C`/`0x20`）；
* 没有 checksum 字段（v3 在 `0x28` 有 adler32），所以重排后不用重算校验。

## v2 的三条写回规则（与 v3 不同，必须按原文件量）

1. **chunk 之间是否对齐要看原文件**：同一批素材实测**紧密排列（gap = 0）**，与 v3 官方包的
   4 字节对齐不同。判据是「同内容替换后与原文件逐字节一致」。
2. **两个阵列在新表比原表长时就让它长**：chunk 变大后 offsets 阵列的元素宽度可能从 2 字节
   升到 3 字节（实测 50096 → 76781 B 的 chunk 就触发了），此时头部 `[5]`/`[6]` 跟着推。
   引擎按宽度读，不要求阵列宽度固定、也不要求 chunk 起点对齐。
3. 表区先尽量保持原长（照抄原填充）可以让「同内容替换」逐字节往返；装不下时才变长。

判据：`resource_bytes` 全量取出 + `replace_resources({})` 与「逐 chunk 原样替换」都必须与
原文件逐字节一致（本作 20 张 v2 `_sc.pimg` 实测 20/20）。
"""

from __future__ import annotations

import io
import struct

PSB_SIG = b"PSB\x00"

NUMBER_N8 = 0x0C
ARRAY_N1 = 0x0D
ARRAY_N8 = 0x14

# v2 头部：sig(4) + version(2) + encrypt(2) + 7*u32
V2_HEADER_SIZE = 0x08 + 7 * 4


class PimgError(Exception):
    pass


def _read_le(br: io.BytesIO, n: int) -> int:
    b = br.read(n)
    if len(b) != n:
        raise PimgError(f"读到 EOF（要 {n} 字节）")
    return int.from_bytes(b, "little")


def _read_array_style(br: io.BytesIO) -> tuple[list[int], int, int]:
    """-> (values, count_width, entry_width)。"""
    t = br.read(1)
    if not t:
        raise PimgError("数组类型字节读到 EOF")
    t = t[0]
    if not (ARRAY_N1 <= t <= ARRAY_N8):
        raise PimgError(f"不是数组类型字节：0x{t:02x}")
    count_width = t - ARRAY_N1 + 1
    count = _read_le(br, count_width)
    et = br.read(1)
    if not et:
        raise PimgError("数组元素类型字节读到 EOF")
    entry_width = et[0] - NUMBER_N8
    if entry_width == 0 and count == 0:
        return [], count_width, 0
    if not (1 <= entry_width <= 8):
        raise PimgError(f"元素宽度非法 {entry_width}")
    buf = br.read(entry_width * count)
    if len(buf) != entry_width * count:
        raise PimgError("数组体读到 EOF")
    return ([int.from_bytes(buf[i * entry_width:(i + 1) * entry_width], "little")
             for i in range(count)], count_width, entry_width)


def _pack_array_styled(values: list[int], count_width: int | None = None,
                       entry_width: int | None = None) -> bytes:
    """按原字段宽度编码（宽度不够时自动加宽）。"""
    need_entry = 1
    for v in values:
        for w in range(1, 9):
            if v < (1 << (8 * w)):
                need_entry = max(need_entry, w)
                break
    if entry_width is not None:
        need_entry = max(need_entry, entry_width)
    need_count = 1
    for w in range(1, 9):
        if len(values) < (1 << (8 * w)):
            need_count = w
            break
    if count_width is not None:
        need_count = max(need_count, count_width)
    out = bytearray([ARRAY_N1 + need_count - 1])
    out += len(values).to_bytes(need_count, "little")
    out.append(NUMBER_N8 + need_entry)
    for v in values:
        out += v.to_bytes(need_entry, "little")
    return bytes(out)


class PimgV2:
    """PSB v2 位图容器。只解析头部 + 两个 chunk 阵列，对象图不碰。"""

    def __init__(self, data: bytes):
        self.raw = data
        if data[:4] != PSB_SIG:
            raise PimgError(f"不是 PSB：{data[:4]!r}")
        self.version = struct.unpack_from("<H", data, 4)[0]
        self.header_encrypt = struct.unpack_from("<H", data, 6)[0]
        if self.header_encrypt:
            raise PimgError("v2 头部加密未支持")
        if self.version != 2:
            raise PimgError(f"不是 PSB v2（version={self.version}）；v3 请用 tool/psb.py")
        (self._names, self.offset_names, self.offset_strings, self.offset_strings_data,
         self.offset_chunk_offsets, self.offset_chunk_lengths, self.offset_chunk_data) \
            = struct.unpack_from("<7I", data, 8)

        br = io.BytesIO(data)
        br.seek(self.offset_chunk_offsets)
        self.chunk_offsets, self._off_cw, self._off_ew = _read_array_style(br)
        br.seek(self.offset_chunk_lengths)
        self.chunk_lengths, self._len_cw, self._len_ew = _read_array_style(br)
        if len(self.chunk_offsets) != len(self.chunk_lengths):
            raise PimgError(
                f"两个 chunk 阵列长度不一致 {len(self.chunk_offsets)} vs {len(self.chunk_lengths)}")
        # 原打包器的 chunk 间对齐粒度：本作 20 张 v2 实测 `gaps` 全 0（紧密排列，不补），
        # 所以默认 1 就够；保留成构造参数，遇到 4 字节对齐的包也能照抄。
        self._align = 1
        for i in range(len(self.chunk_offsets) - 1):
            gap = self.chunk_offsets[i + 1] - (self.chunk_offsets[i] + self.chunk_lengths[i])
            if gap:
                self._align = max(self._align, _infer_align(
                    self.chunk_offsets[i + 1]))
                break

    # ------------------------------------------------------------- 读
    def __len__(self) -> int:
        return len(self.chunk_offsets)

    @property
    def original_bytes(self) -> bytes:
        """`replace_resources({})` 会返回的那个字节串（与 `psb.PsbFile` 同名）。"""
        return self.raw

    def resource_bytes(self, index: int) -> bytes:
        start = self.offset_chunk_data + self.chunk_offsets[index]
        return self.raw[start: start + self.chunk_lengths[index]]

    # ------------------------------------------------------------- 写
    def replace_resources(self, mapping: dict[int, bytes]) -> bytes:
        """替换若干 chunk（长度可变），重排两个阵列与尾部数据；对象图一字不动。

        `mapping` 为空时直接返回原字节（零改动往返）。
        """
        if not mapping:
            return self.raw

        blob = bytearray()
        offsets: list[int] = []
        lengths: list[int] = []
        n = len(self.chunk_offsets)
        for i in range(n):
            data = mapping.get(i)
            if data is None:
                data = self.resource_bytes(i)
            offsets.append(len(blob))
            lengths.append(len(data))
            blob += data
            if i != n - 1 and self._align > 1:  # 照抄原包的 chunk 间对齐粒度
                blob += bytes(-len(blob) % self._align)

        offs_blob = _pack_array_styled(offsets, self._off_cw, self._off_ew)
        lens_blob = _pack_array_styled(lengths, self._len_cw, self._len_ew)
        # 表区尽量保持原长（照抄原填充），这样「同内容替换」能逐字节往返；
        # 若新表变长（chunk 变大 ⇒ offsets 阵列要加宽），就让它长，头部两个偏移跟着推。
        orig_tables = self.offset_chunk_data - self.offset_chunk_offsets
        pad = orig_tables - (len(offs_blob) + len(lens_blob))
        lens_blob += bytes(max(0, pad))

        offset_chunk_lengths = self.offset_chunk_offsets + len(offs_blob)
        offset_chunk_data = offset_chunk_lengths + len(lens_blob)

        # 原 chunk 数据区之后可能还有不属于任何 chunk 的尾巴，原样带过
        orig_end = self.offset_chunk_data + max(
            (o + l for o, l in zip(self.chunk_offsets, self.chunk_lengths)), default=0)
        trailing = self.raw[orig_end:]

        head = bytearray(self.raw[:V2_HEADER_SIZE])
        struct.pack_into("<I", head, 0x08 + 4 * 5, offset_chunk_lengths)
        struct.pack_into("<I", head, 0x08 + 4 * 6, offset_chunk_data)
        prefix = self.raw[V2_HEADER_SIZE: self.offset_chunk_offsets]
        return (bytes(head) + prefix + offs_blob + lens_blob + bytes(blob) + trailing)



def _infer_align(offset: int) -> int:
    """从一个 chunk 起点反推对齐粒度（2 的幂，最大 16）。"""
    for a in (16, 8, 4, 2):
        if offset % a == 0:
            return a
    return 2


# --------------------------------------------------------------- 统一入口
def version_of(data: bytes) -> int:
    """-> 2 或 3（不是 PSB 就抛 `PimgError`）。"""
    if data[:4] != PSB_SIG:
        raise PimgError(f"不是 PSB：{data[:4]!r}")
    return struct.unpack_from("<H", data, 4)[0]


def open_pimg(data: bytes):
    """按内部 PSB 版本分派，返回**同一套接口**的容器对象。

    统一接口：`version` / `len()` / `original_bytes` / `resource_bytes(i)` /
    `replace_resources(mapping)`。`original_bytes` 是「零改动重建」应当逐字节相等的那个串。
    """
    version = version_of(data)
    if version == 2:
        return PimgV2(data)
    if version == 3:
        from tool import psb
        return psb.PsbFile(data)
    raise PimgError(f"不支持的 PSB version={version}")


def load(path: str):
    """`open_pimg(open(path,'rb').read())` 的便捷写法。"""
    with open(path, "rb") as fp:
        return open_pimg(fp.read())
