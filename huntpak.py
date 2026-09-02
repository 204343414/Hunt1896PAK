#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
huntpak.py — 远程按需读取 Hunt: Showdown (1896) 加密 pak 的工具。

原理移植自 StrangerWay/cmodel (src/pak_reader.cpp, MIT 无声明, 仅作学习):
  - pak = ZIP/ZIP64, 文件目录(CDR)整体 AES-CTR 加密
  - 密钥包放在 ZIP 注释里: CryExtHdr + CryEncHdr, 16 个 128bit 块密钥 + CDR IV
    各自经 RSA-OAEP(SHA256) 用"私钥加密"包裹, 客户端用内嵌公钥拆
  - 每个条目: LFH 区和数据区分别用 (blockKeys[kidx], BuildIV(e)) 独立 AES-CTR(小端计数器)
    kidx = (~(crc32>>2)) & 0xF

支持的数据来源: 本地文件 / 支持 Range 的 HTTP URL(你那边开 huntserve.py 后接 cf 隧道)。
子命令:
  paks   <tunnel_base_url>                列出目录页里所有 .pak 及大小
  list   <pak_url_or_path> [--json OUT]   解密并列出全部条目
  pull   <pak_url_or_path> PATTERN... [-o DIR]  按通配符提取条目(仅拉所需字节)
  selftest                                构造合成加密 pak 做端到端自检
"""
import argparse
import fnmatch
import io
import json
import os
import re
import struct
import sys
import urllib.parse
import urllib.request
import zlib

from Crypto.Hash import SHA256          # pycryptodome
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
import zstandard as zstd

# 来自 cmodel/src/pak_reader.h 的 Hunt: Showdown 5.11 客户端公钥
HUNT_RSA_PUB_DER = bytes([
    0x30, 0x81, 0x89, 0x02, 0x81, 0x81, 0x00,
    0xAF, 0xFD, 0x71, 0xCA, 0x74, 0x1C, 0x1A, 0xA5,
    0x89, 0x5B, 0xEC, 0xF5, 0x96, 0xE8, 0x73, 0x2D,
    0x29, 0x04, 0x53, 0xD2, 0x75, 0xCF, 0x6F, 0xF0,
    0xBB, 0x21, 0x43, 0x24, 0xEB, 0xAB, 0x7E, 0xED,
    0xD7, 0xF3, 0x9D, 0xEE, 0xBC, 0x27, 0x08, 0xD8,
    0x8B, 0x6D, 0x53, 0x6A, 0x58, 0xDA, 0x56, 0x83,
    0x13, 0x7F, 0xAF, 0xEC, 0x47, 0x8E, 0x41, 0xE6,
    0xF8, 0xB0, 0x88, 0x2E, 0x5E, 0xBA, 0x23, 0x6B,
    0x9D, 0x2A, 0x15, 0x0E, 0xE5, 0x13, 0xAE, 0x56,
    0x2C, 0xE5, 0x6B, 0x6A, 0xAF, 0x98, 0x2C, 0x27,
    0xA8, 0xC3, 0x17, 0x28, 0x1A, 0xFA, 0x0F, 0x84,
    0xF5, 0x46, 0xEC, 0xB8, 0x25, 0xCC, 0xF2, 0x21,
    0x75, 0x19, 0xC8, 0x4E, 0xD0, 0xCE, 0xAB, 0x17,
    0x9E, 0xE5, 0xCC, 0xDA, 0xB0, 0xCB, 0x40, 0xA9,
    0x5D, 0x54, 0x42, 0x12, 0x0F, 0x25, 0xA6, 0x1E,
    0x7D, 0xA7, 0x9D, 0x30, 0xC7, 0xD7, 0xD8, 0xA7,
    0x02, 0x03, 0x01, 0x00, 0x01
])

# ── ZIP/ZIP64 结构 ────────────────────────────────────────────────────────────
EOCD      = '<I4H2IH'          # 22
EOCD64    = '<IQHHII4Q'        # 56
EOCD64LOC = '<IIQI'            # 20
CDR_ENT   = '<I6H3I5H2I'       # 46
LFH       = '<I5H3I2H'         # 30
SIG_EOCD, SIG_EOCD64, SIG_EOCD64LOC = 0x06054b50, 0x06064b50, 0x07064b50
SIG_CDR, SIG_LFH = 0x02014b50, 0x04034b50


# ── 加密原语 ─────────────────────────────────────────────────────────────────
def mgf1_sha256(seed: bytes, length: int) -> bytes:
    out, i = b'', 0
    while len(out) < length:
        out += SHA256.new(seed + struct.pack('>I', i)).digest()
        i += 1
    return out[:length]


def oaep_sha256_decode(em: bytes) -> bytes:
    """k=128, hLen=32 的 OAEP 解码(无标签)。"""
    if len(em) != 128 or em[0] != 0:
        raise ValueError('bad EM')
    masked_seed, masked_db = em[1:33], em[33:]
    seed = bytes(a ^ b for a, b in zip(masked_seed, mgf1_sha256(masked_db, 32)))
    db = bytes(a ^ b for a, b in zip(masked_db, mgf1_sha256(seed, 128 - 33)))
    if db[:32] != SHA256.new(b'').digest():
        raise ValueError('OAEP hash mismatch')
    sep = db.find(b'\x01', 32)
    if sep < 0:
        raise ValueError('OAEP sep not found')
    return db[sep + 1:]


def aes_ctr_le(key16: bytes, iv16: bytes, data: bytes) -> bytes:
    """AES-128-CTR, 计数器按 128bit 小端整数自增
    (与 libtomcrypt CTR_COUNTER_LITTLE_ENDIAN 语义一致)。
    pycryptodome 无 little_endian 参数, 用 ECB 造密钥流手动异或。"""
    if not data:
        return data
    ctr = int.from_bytes(iv16, 'little')
    nblocks = (len(data) + 15) // 16
    ecb = AES.new(key16, AES.MODE_ECB)
    cb = bytearray()
    mask = (1 << 128) - 1
    c = ctr
    for _ in range(nblocks):
        cb += c.to_bytes(16, 'little')
        c = (c + 1) & mask
    stream = ecb.encrypt(bytes(cb))
    return bytes(a ^ b for a, b in zip(data, stream))


def build_iv(csize: int, usize: int, crc: int) -> bytes:
    cs, us = csize & 0xFFFFFFFF, usize & 0xFFFFFFFF
    v = [us ^ ((cs << 12) & 0xFFFFFFFF),
         0 if cs else 1,
         crc ^ ((cs << 12) & 0xFFFFFFFF),
         (0 if us else 1) ^ cs]
    return struct.pack('<4I', *[x & 0xFFFFFFFF for x in v])


def key_index(crc: int) -> int:
    return (~(crc >> 2)) & 0xF


# ── 数据源抽象(本地/HTTP Range) ───────────────────────────────────────────────
class LocalBlob:
    def __init__(self, path):
        self.path = path
        self.size = os.path.getsize(path)
    def read_at(self, off, n):
        with open(self.path, 'rb') as f:
            f.seek(off)
            return f.read(n)


class HTTPBlob:
    def __init__(self, url, timeout=180):
        p = urllib.parse.urlsplit(url)          # URL 里含空格/中文时转义
        self.url = urllib.parse.urlunsplit((p.scheme, p.netloc,
                                            urllib.parse.quote(p.path), '', ''))
        self.timeout = timeout
        req = urllib.request.Request(self.url, method='HEAD')
        with urllib.request.urlopen(req, timeout=timeout) as r:
            self.size = int(r.headers['Content-Length'])
            self.range_ok = (r.headers.get('Accept-Ranges', '') == 'bytes')
        if not self.range_ok:
            raise RuntimeError('服务器不支持 Range(换 huntserve.py)')
    def read_at(self, off, n):
        req = urllib.request.Request(self.url, headers={
            'Range': f'bytes={off}-{off + n - 1}'})
        with urllib.request.urlopen(req, timeout=self.timeout) as r:
            if r.status != 206:
                raise RuntimeError(f'Range 请求被拒(HTTP {r.status})')
            return r.read()


def open_blob(src):
    if src.startswith('http://') or src.startswith('https://'):
        return HTTPBlob(src)
    return LocalBlob(src)


# ── pak 解析 ─────────────────────────────────────────────────────────────────
class PakError(RuntimeError):
    pass


class PakEntry:
    __slots__ = ('path', 'crc32', 'comp_size', 'uncomp_size', 'local_off',
                 'method')


class PakReader:
    def __init__(self, blob: object, pubkey_der: bytes = HUNT_RSA_PUB_DER):
        self.blob = blob
        self.pubkey = RSA.import_key(pubkey_der)
        self.encrypted = False
        self.block_keys = [b'\x00' * 16] * 16
        self.cdr_iv = b'\x00' * 16
        self.entries = []
        self._open()

    def _rsa_unwrap(self, blob128: bytes) -> bytes:
        em_int = pow(int.from_bytes(blob128, 'big'), self.pubkey.e, self.pubkey.n)
        em = em_int.to_bytes(self.pubkey.size_in_bytes(), 'big')
        return oaep_sha256_decode(em)

    def _open(self):
        size = self.blob.size
        tail_len = min(size, 65535 + 22)
        tail = self.blob.read_at(size - tail_len, tail_len)

        # 1. 从尾向前找 EOCD, 校验 comment 恰好到文件尾
        eocd_pos = -1
        for i in range(tail_len - 22, -1, -1):
            sig, = struct.unpack_from('<I', tail, i)
            if sig != SIG_EOCD:
                continue
            comment_len, = struct.unpack_from('<H', tail, i + 20)
            if i + 22 + comment_len == tail_len:
                eocd_pos = i
                break
        if eocd_pos < 0:
            raise PakError('EOCD 未找到')
        (_s, _disk, _cdrdisk, num_disk, num_total,
         cdr_size, cdr_off, comment_len) = struct.unpack_from(EOCD, tail, eocd_pos)

        # 2. ZIP64
        if 0xFFFFFFFF in (cdr_size, cdr_off) or 0xFFFF in (num_total, num_disk):
            loc_abs = (size - tail_len) + eocd_pos - 20
            loc = self.blob.read_at(loc_abs, 20)
            sig, _d, z64_off, _t = struct.unpack(EOCD64LOC, loc)
            if sig != SIG_EOCD64LOC:
                raise PakError('ZIP64 locator 未找到')
            z64 = self.blob.read_at(z64_off, 56)
            sig, _rs, _vm, _vn, _d1, _d2, _n1, _n2, cdr_size, cdr_off = \
                struct.unpack(EOCD64, z64)
            if sig != SIG_EOCD64:
                raise PakError('ZIP64 EOCD 未找到')

        if cdr_off >= size or cdr_size == 0 or cdr_size > size - cdr_off:
            raise PakError('CDR 越界')

        # 3. 注释区加密头
        comment = bytes(tail[eocd_pos + 22: eocd_pos + 22 + comment_len])
        if len(comment) >= 8:
            ext_size, enc, sign = struct.unpack_from('<IHH', comment, 0)
            if enc >= 3:
                self.encrypted = True
                pos = ext_size
                if sign:
                    sig_sz, = struct.unpack_from('<I', comment, pos)
                    pos += sig_sz
                (eh_size,) = struct.unpack_from('<I', comment, pos)
                enc_base = pos
                extra = eh_size - 2180 if eh_size > 2180 else 0
                p_iv = enc_base + 4 + extra
                p_keys = p_iv + 128
                if p_keys + 16 * 128 > len(comment):
                    raise PakError('加密头越界')
                self.cdr_iv = self._rsa_unwrap(comment[p_iv:p_iv + 128])
                assert len(self.cdr_iv) == 16
                self.block_keys = []
                for i in range(16):
                    k = self._rsa_unwrap(comment[p_keys + i * 128:
                                                 p_keys + i * 128 + 128])
                    assert len(k) == 16
                    self.block_keys.append(k)

        # 4. 读+解 CDR
        cdr = self.blob.read_at(cdr_off, cdr_size)
        if self.encrypted:
            cdr = aes_ctr_le(self.block_keys[0], self.cdr_iv, cdr)
            if struct.unpack_from('<I', cdr, 0)[0] != SIG_CDR:
                raise PakError('CDR 解密失败')

        # 5. 条目表
        self.entries = []
        pos = 0
        while pos + 46 <= len(cdr):
            (sig, _vm, _vn, _fl, method, _mt, _md, crc, csize, usize,
             fnlen, exlen, cmtlen, _ds, _ia, _ea, lhdr_off) = \
                struct.unpack_from(CDR_ENT, cdr, pos)
            if sig != SIG_CDR:
                break
            pos += 46
            if pos + fnlen > len(cdr):
                break
            fn = cdr[pos:pos + fnlen].decode('utf-8', 'replace')
            pos += fnlen
            if pos + exlen + cmtlen > len(cdr):
                break
            extra = cdr[pos:pos + exlen]
            pos += exlen + cmtlen
            if not fn or fn.endswith('/'):
                continue
            if 0xFFFFFFFF in (csize, usize, lhdr_off):
                i = 0
                while i + 4 <= len(extra):
                    tag, esz = struct.unpack_from('<HH', extra, i)
                    i += 4
                    if i + esz > len(extra):
                        break
                    if tag == 0x0001:
                        p = i
                        if usize == 0xFFFFFFFF:
                            usize, = struct.unpack_from('<Q', extra, p); p += 8
                        if csize == 0xFFFFFFFF:
                            csize, = struct.unpack_from('<Q', extra, p); p += 8
                        if lhdr_off == 0xFFFFFFFF:
                            lhdr_off, = struct.unpack_from('<Q', extra, p)
                        break
                    i += esz
            e = PakEntry()
            e.path, e.crc32, e.method = fn, crc, method
            e.comp_size, e.uncomp_size, e.local_off = csize, usize, lhdr_off
            self.entries.append(e)

    def read_entry(self, e: PakEntry) -> bytes:
        size = self.blob.size
        if e.local_off + 30 > size:
            raise PakError(f'local offset 越界: {e.path}')
        iv = build_iv(e.comp_size, e.uncomp_size, e.crc32)
        ki = key_index(e.crc32)
        data_start = 0
        if self.encrypted:
            n = min(30 + 256 + 64, size - e.local_off)
            buf = aes_ctr_le(self.block_keys[ki], iv,
                             self.blob.read_at(e.local_off, n))
            if len(buf) >= 30 and struct.unpack_from('<I', buf, 0)[0] == SIG_LFH:
                _s, _vn, _fl, _me, _mt, _md, _c, _cs, _us, fnl, exl = \
                    struct.unpack(LFH, buf[:30])
                data_start = 30 + fnl + exl
        else:
            buf = self.blob.read_at(e.local_off, 30)
            if struct.unpack_from('<I', buf, 0)[0] == SIG_LFH:
                _s, _vn, _fl, _me, _mt, _md, _c, _cs, _us, fnl, exl = \
                    struct.unpack(LFH, buf)
                data_start = 30 + fnl + exl
        if data_start == 0:
            raise PakError(f'LFH 解析失败: {e.path}')
        data_off = e.local_off + data_start
        if data_off + e.comp_size > size:
            raise PakError(f'数据越界: {e.path}')
        comp = self.blob.read_at(data_off, e.comp_size)
        if self.encrypted:
            comp = aes_ctr_le(self.block_keys[ki], iv, comp)

        if e.method in (0, 13, 94):
            return comp
        if e.method in (8, 14):
            try:
                return zlib.decompress(comp)
            except zlib.error:
                return zlib.decompress(comp, -15)
        if e.method == 93:  # 多帧 zstd
            dctx = zstd.ZstdDecompressor()
            with dctx.stream_reader(io.BytesIO(comp),
                                    read_across_frames=True) as rd:
                return rd.read()
        return comp


def human(n: int) -> str:
    for u in ('B', 'KB', 'MB', 'GB', 'TB'):
        if n < 1024 or u == 'TB':
            return f'{n:.1f}{u}' if u != 'B' else f'{n}B'
        n /= 1024
    return f'{n:.1f}TB'


# ── 子命令 ───────────────────────────────────────────────────────────────────
def _fetch_listing(url):
    with urllib.request.urlopen(url, timeout=60) as r:
        html = r.read().decode('utf-8', 'replace')
    return re.findall(r'href="([^"]+)"', html)


def cmd_paks(args):
    """递归爬目录页收集 .pak(深度<=4), HEAD 取大小, 按大小降序打印。"""
    base = args.url.rstrip('/') + '/'
    found = {}   # url -> size
    def crawl(dir_url, depth):
        if depth > 4:
            return
        try:
            hrefs = _fetch_listing(dir_url)
        except Exception as ex:
            print(f'# 无法读取 {dir_url}: {ex}', file=sys.stderr)
            return
        for href in hrefs:
            if href.startswith(('..', '/', '?')):
                continue
            full = urllib.parse.urljoin(dir_url, href)
            if href.endswith('/'):
                crawl(full, depth + 1)
            elif href.lower().endswith('.pak'):
                found[full] = -1
    crawl(base, 0)
    print(f'# 发现 {len(found)} 个 pak, 获取大小中…', file=sys.stderr)
    for url in found:
        try:
            req = urllib.request.Request(url, method='HEAD')
            with urllib.request.urlopen(req, timeout=60) as r:
                found[url] = int(r.headers.get('Content-Length', 0))
        except Exception:
            found[url] = 0
    for url, sz in sorted(found.items(), key=lambda kv: -kv[1]):
        rel = urllib.parse.urlsplit(url).path
        print(f'{human(sz):>10}  {urllib.parse.unquote(rel)}')
    if args.json:
        with open(args.json, 'w') as f:
            json.dump([{'url': u, 'size': s} for u, s in found.items()],
                      f, indent=1)


def cmd_list(args):
    pak = PakReader(open_blob(args.src))
    enc = '加密' if pak.encrypted else '明文'
    print(f'# entries={len(pak.entries)}  [{enc}]', file=sys.stderr)
    rows = []
    for e in pak.entries:
        rows.append({'path': e.path, 'method': e.method,
                     'comp': e.comp_size, 'uncomp': e.uncomp_size,
                     'offset': e.local_off, 'crc32': f'{e.crc32:08x}'})
        if not args.json:
            print(f'{human(e.uncomp_size):>10}  m{e.method:<3}  {e.path}')
    print(f'# 共 {len(rows)} 个文件', file=sys.stderr)
    if args.json:
        with open(args.json, 'w') as f:
            json.dump(rows, f, ensure_ascii=False, indent=1)
        print(f'# 索引已存 {args.json}', file=sys.stderr)


def cmd_pull(args):
    pak = PakReader(open_blob(args.src))
    pats = [p.lower() for p in args.patterns]
    hits = [e for e in pak.entries
            if any(fnmatch.fnmatch(e.path.lower(), p) or p in e.path.lower()
                   for p in pats)]
    print(f'# 匹配 {len(hits)}/{len(pak.entries)}', file=sys.stderr)
    os.makedirs(args.out, exist_ok=True)
    ok = 0
    for e in hits:
        try:
            data = pak.read_entry(e)
            dst = os.path.join(args.out, e.path.replace('/', os.sep))
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            with open(dst, 'wb') as f:
                f.write(data)
            print(f'  OK {human(len(data)):>10}  {e.path}')
            ok += 1
        except Exception as ex:
            print(f'  FAIL {e.path}: {ex}', file=sys.stderr)
    print(f'# 成功 {ok}/{len(hits)}', file=sys.stderr)


# ── 自检: 造一个"Hunt 同款"加密 pak 跑全流程 ────────────────────────────────
def _oaep_encode(msg: bytes) -> bytes:
    l_hash = SHA256.new(b'').digest()
    seed = os.urandom(32)
    db = l_hash + b'\x00' * (128 - 2 * 32 - 2 - len(msg)) + b'\x01' + msg
    masked_db = bytes(a ^ b for a, b in zip(db, mgf1_sha256(seed, 95)))
    masked_seed = bytes(a ^ b for a, b in zip(seed, mgf1_sha256(masked_db, 32)))
    return b'\x00' + masked_seed + masked_db


def _build_fake_pak(files, zip64: bool):
    key = RSA.generate(1024)
    block_keys = [os.urandom(16) for _ in range(16)]
    cdr_iv = os.urandom(16)

    def wrap(b):  # 私钥加密(RSA 反向)+OAEP, 对齐 cmodel 的解包方向
        em = int.from_bytes(_oaep_encode(b), 'big')
        return pow(em, key.d, key.n).to_bytes(128, 'big')

    out = io.BytesIO()
    cd = []
    for path, data, method in files:
        if method == 93:
            c1 = zstd.ZstdCompressor().compress(data[:len(data) // 2])
            c2 = zstd.ZstdCompressor().compress(data[len(data) // 2:])
            comp = c1 + c2          # 双帧, 测 read_across_frames
        elif method in (8, 14):
            comp = zlib.compress(data)
        else:
            comp = data
        crc = zlib.crc32(data)
        iv = build_iv(len(comp), len(data), crc)
        ki = key_index(crc)
        lfh = struct.pack(LFH, SIG_LFH, 20, 0, method, 0, 0, crc,
                          len(comp), len(data), len(path), 0) + path.encode()
        lfh_enc = aes_ctr_le(block_keys[ki], iv, lfh)
        comp_enc = aes_ctr_le(block_keys[ki], iv, comp)
        off = out.tell()
        out.write(lfh_enc + comp_enc)
        cd.append((path, method, crc, len(comp), len(data), off))

    cdr = io.BytesIO()
    for path, method, crc, cs, us, off in cd:
        if zip64:
            extra = struct.pack('<HHQQQ', 0x0001, 24, us, cs, off)
            ent = struct.pack(CDR_ENT, SIG_CDR, 45, 45, 0, method, 0, 0,
                              crc, 0xFFFFFFFF, 0xFFFFFFFF,
                              len(path), len(extra), 0, 0, 0, 0, 0xFFFFFFFF)
            cdr.write(ent + path.encode() + extra)
        else:
            ent = struct.pack(CDR_ENT, SIG_CDR, 45, 20, 0, method, 0, 0,
                              crc, cs, us, len(path), 0, 0, 0, 0, 0, off)
            cdr.write(ent + path.encode())
    cdr_plain = cdr.getvalue()
    cdr_off = out.tell()
    out.write(aes_ctr_le(block_keys[0], cdr_iv, cdr_plain))

    comment = struct.pack('<IHH', 8, 3, 0) + struct.pack('<I', 2180) \
        + wrap(cdr_iv) + b''.join(wrap(k) for k in block_keys)

    if zip64:
        z64_off = out.tell()
        out.write(struct.pack(EOCD64, SIG_EOCD64, 44, 45, 45, 0, 0,
                              len(cd), len(cd), len(cdr_plain), cdr_off))
        out.write(struct.pack(EOCD64LOC, SIG_EOCD64LOC, 0, z64_off, 1))
        out.write(struct.pack(EOCD, SIG_EOCD, 0, 0, 0xFFFF, 0xFFFF,
                              0xFFFFFFFF, 0xFFFFFFFF, len(comment)))
    else:
        out.write(struct.pack(EOCD, SIG_EOCD, 0, 0, len(cd), len(cd),
                              len(cdr_plain), cdr_off, len(comment)))
    out.write(comment)
    return out.getvalue(), key.publickey().export_key('DER')


def cmd_selftest(_args):
    import random
    random.seed(1896)
    files = [
        ('objects/characters/butcher.chr', os.urandom(7000), 93),
        ('objects/weapons/winfield.cga', os.urandom(150000), 93),
        ('textures/ui.dds', os.urandom(3000), 94),
        ('scripts/ent/ai.xml', ('<x>' + '猎杀' * 500 + '</x>').encode(), 8),
        ('readme.txt', b'hello hunt', 94),
    ]
    for zip64 in (False, True):
        blob, pub_der = _build_fake_pak(files, zip64)
        class MemBlob:
            size = len(blob)
            def read_at(self, off, n):
                return blob[off:off + n]
        pak = PakReader(MemBlob(), pubkey_der=pub_der)
        assert pak.encrypted, '应识别为加密'
        names = [e.path for e in pak.entries]
        assert names == [f[0] for f in files], f'清单不符: {names}'
        for e, (path, data, _m) in zip(pak.entries, files):
            got = pak.read_entry(e)
            assert got == data, f'{path} 内容不符 ({len(got)} vs {len(data)})'
        print(f'  [{"ZIP64" if zip64 else "ZIP  "}模式] '
              f'{len(files)} 个条目全部还原成功 ✓')
    print('selftest 全绿 ✅')


def main():
    ap = argparse.ArgumentParser(description='Hunt: Showdown 加密 pak 远程读取器')
    sub = ap.add_subparsers(dest='cmd', required=True)
    p = sub.add_parser('paks');  p.add_argument('url')
    p.add_argument('--json', metavar='OUT.json'); p.set_defaults(fn=cmd_paks)
    p = sub.add_parser('list');  p.add_argument('src')
    p.add_argument('--json', metavar='OUT.json'); p.set_defaults(fn=cmd_list)
    p = sub.add_parser('pull');  p.add_argument('src')
    p.add_argument('patterns', nargs='+')
    p.add_argument('-o', '--out', default='hunt_out'); p.set_defaults(fn=cmd_pull)
    p = sub.add_parser('selftest'); p.set_defaults(fn=cmd_selftest)
    args = ap.parse_args()
    args.fn(args)


if __name__ == '__main__':
    main()
