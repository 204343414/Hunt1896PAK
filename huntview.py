#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
huntview.py — 猎杀对决(Hunt: Showdown / 1896) 本地资产浏览器
一键启动后浏览器打开 http://127.0.0.1:8796 即可。
只读: 绝不写入/修改游戏目录。

用法:
    python3 huntview.py [游戏目录] [端口]
依赖: pycryptodome, zstandard  (可选 numpy 加速解密)
    Debian 13:  sudo apt install python3-pycryptodome python3-zstandard
测试模式(远程):  环境变量 HUNT_BASE=https://xxx.trycloudflare.com 可替代游戏目录
"""
import gzip
import http.server
import io
import json
import os
import re
import socketserver
import struct
import sys
import time
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import huntpak            # noqa: E402
import huntcgf            # noqa: E402

CACHE_FILE = os.path.join(HERE, 'huntview_index.cache')

# ════════════════════════ 资产索引 ════════════════════════

def collect_paks(root):
    """本地目录 → [abs paths]; http(s) → 爬目录页 → [urls]
    环境变量 HUNT_PAK_FILTER(正则)可只装部分包(调试用)"""
    out = []
    if root.startswith(('http://', 'https://')):
        base = root.rstrip('/') + '/'
        def crawl(u, d):
            if d > 4:
                return
            try:
                with urllib.request.urlopen(u, timeout=60) as r:
                    html = r.read().decode('utf-8', 'replace')
            except Exception as e:
                print(f'  无法读取 {u}: {e}', file=sys.stderr)
                return
            for href in re.findall(r'href="([^"]+)"', html):
                if href.startswith(('..', '/', '?')):
                    continue
                full = urllib.parse.urljoin(u, href)
                if href.endswith('/'):
                    crawl(full, d + 1)
                elif href.lower().endswith('.pak'):
                    out.append(full)
        crawl(base, 0)
    else:
        for dp, _dn, fns in os.walk(root):
            for fn in fns:
                if fn.lower().endswith('.pak'):
                    out.append(os.path.join(dp, fn))
    out = sorted(out)
    flt = os.environ.get('HUNT_PAK_FILTER')
    if flt:
        rx = re.compile(flt)
        out = [u for u in out if rx.search(u)]
    # 默认跳过对浏览资产没用的包(设 HUNT_SKIP='' 可全量)
    skip = os.environ.get(
        'HUNT_SKIP',
        r'svogi|localization|shadercache|shadersbin|/shaders\.pak|'
        r'gameshaders|fastload|intromovies|cryasset')
    if skip:
        rxs = re.compile(skip, re.I)
        out = [u for u in out if not rxs.search(u)]
    return out


class AssetIndex:
    """全 pak 条目的合并索引: files_map[path_lower] = (pak_url, [crc,cs,us,off,method,path])"""

    def __init__(self, root, log=print):
        self.root = root
        self.pak_keys = {}      # pak_source -> (block_keys, cdr_iv) 运行期惰性拆
        self.pak_blobs = {}
        self.files = {}         # path.lower() -> (pak_src, crc, cs, us, off, method, path)
        self.tree = {}          # dir -> (set(dirs), [ (name, path, size) ])
        self._build(log)

    # ---------- 索引建立/缓存 ----------
    def _build(self, log):
        cache = self._load_cache()
        sources = collect_paks(self.root)
        t0 = time.time()
        n_new = 0
        for src in sources:
            key = src
            blob_size = (os.path.getsize(src) if not src.startswith('http')
                         else self._head_size(src))
            hit = cache.get(key)
            if hit and hit.get('size') == blob_size:
                rows = hit['entries']
            else:
                log(f'  索引: {os.path.basename(urllib.parse.unquote(src))} '
                    f'({huntpak.human(blob_size)})…')
                try:
                    pak = huntpak.PakReader(self._blob(src))
                except Exception as e:
                    log(f'    ⚠ 无法读取: {e}')
                    continue
                rows = [[e.path, e.crc32, e.comp_size, e.uncomp_size,
                         e.local_off, e.method] for e in pak.entries]
                cache[key] = {'size': blob_size, 'entries': rows}
                self.pak_keys[key] = (pak.block_keys if pak.encrypted else None,
                                      pak.cdr_iv)
                self._save_keys(cache)
                n_new += 1
            for path, crc, cs, us, off, meth in rows:
                low = path.lower()
                if low not in self.files:
                    self.files[low] = (key, crc, cs, us, off, meth, path)
        self._save_cache(cache)
        self._build_tree()
        log(f'索引完成: {len(self.files):,} 个文件 / {len(sources)} 个 pak '
            f'(新增解析 {n_new}, 耗时 {time.time()-t0:.0f}s)')

    def _load_cache(self):
        try:
            raw = open(CACHE_FILE, 'rb').read()
            return json.loads(gzip.decompress(raw).decode('utf-8'))
        except Exception:
            return {}
        return {}

    def _save_cache(self, cache):
        try:
            tmp = CACHE_FILE + '.tmp'
            with open(tmp, 'wb') as f:
                f.write(gzip.compress(json.dumps(
                    cache, separators=(',', ':')).encode('utf-8'), 6))
            os.replace(tmp, CACHE_FILE)
        except Exception as e:
            print(f'缓存写入失败(不致命): {e}', file=sys.stderr)

    def _save_keys(self, cache):
        # 顺带边建边存, 防止中途被打断
        self._save_cache(cache)

    def _head_size(self, url):
        req = urllib.request.Request(url, method='HEAD')
        with urllib.request.urlopen(req, timeout=60) as r:
            return int(r.headers['Content-Length'])

    def _build_tree(self):
        tree = {'': (set(), [])}
        for low, (_k, _c, _cs, us, _o, _m, path) in self.files.items():
            parts = path.split('/')
            for i in range(len(parts) - 1):
                d = '/'.join(parts[:i + 1])
                parent = '/'.join(parts[:i])
                tree.setdefault(d, (set(), []))
                tree.setdefault(parent, (set(), []))[0].add(parts[i])
            d = '/'.join(parts[:-1])
            tree.setdefault(d, (set(), []))[1].append((parts[-1], path, us))
        self.tree = tree

    # ---------- 读取 ----------
    def _blob(self, src):
        if src not in self.pak_blobs:
            self.pak_blobs[src] = (huntpak.HTTPBlob(src, timeout=180)
                                   if src.startswith('http')
                                   else huntpak.LocalBlob(src))
        return self.pak_blobs[src]

    def _pak_lite(self, src):
        """只在内存里拿到密钥, 不重扫 CDR(若无缓存密钥则完整开一次)"""
        if src not in self.pak_keys:
            pak = huntpak.PakReader(self._blob(src))
            self.pak_keys[src] = (pak.block_keys if pak.encrypted else None,
                                  pak.cdr_iv)
        return self.pak_keys[src]

    def read(self, path):
        low = path.lower()
        if low not in self.files:
            raise FileNotFoundError(path)
        src, crc, cs, us, off, meth, real = self.files[low]
        block_keys, cdr_iv = self._pak_lite(src)
        e = huntpak.PakEntry()
        e.path, e.crc32, e.comp_size = real, crc, cs
        e.uncomp_size, e.local_off, e.method = us, off, meth
        fake = object.__new__(huntpak.PakReader)
        fake.blob = self._blob(src)
        fake.encrypted = block_keys is not None
        fake.block_keys = block_keys or [b'\x00' * 16] * 16
        fake.cdr_iv = cdr_iv
        return fake.read_entry(e)

    def ls(self, d):
        d = d.strip('/')
        dirs, files = self.tree.get(d, (set(), []))
        return {'dirs': sorted(dirs), 'files': [
            {'name': n, 'path': p, 'size': s} for n, p, s in sorted(files)]}

    def search(self, q, limit=300):
        q = q.lower()
        hits, rest = [], []
        for low, (_k, _c, _cs, us, _o, _m, path) in self.files.items():
            if q in low:
                # cdf 装配单优先(整模入口), 其次可预览几何, 杂件殿后
                (hits if low.endswith('.cdf') else rest).append({'path': path, 'size': us})
        return (hits + rest)[:limit]


# ════════════════════════ 模型/动画/材质/贴图解析 ════════════════════════
import xml.etree.ElementTree as ET
import subprocess as _sp

PREVIEW_EXT = ('.chr', '.skin', '.skinm', '.cgf', '.cgfm', '.cga', '.cdf')
GEO_MATE = {'.skin': 'm', '.cgf': 'm', '.cga': 'm'}


def _normp(p):
    return p.replace('\\', '/').lstrip('./').lower()


def parse_cdf_attach(idx, path):
    """cdf → chr(骨架/本体) + 全部几何附件(skin/cgf…, 含骨骼挂点).
    CA_SKIN=皮肤部件; CA_BONE 等带 Binding=骨骼挂的静态件(武器枪管/枪托)."""
    xml = idx.read(path).decode('utf-8', 'replace')
    mdl = re.search(r'<Model[^>]*File="([^"]+)"(?:[^>]*Material="([^"]*)")?', xml)
    chr_p = _normp(mdl.group(1)) if mdl else None
    mtl = _normp(mdl.group(2)) if mdl and mdl.group(2) else None
    skins = []
    for m in re.finditer(r'<Attachment\s+([^>]+)/?>', xml):
        attr = dict(re.findall(r'(\w+)="([^"]*)"', m.group(1)))
        bd = attr.get('Binding')
        if not bd:
            continue
        sp = _normp(bd)
        if not sp.endswith(('.skin', '.cgf', '.cga', '.chr')):
            continue
        if sp not in idx.files:
            continue
        def _vec(v, n, dflt):
            try:
                vals = [float(x) for x in (v or '').split(',')]
                return vals if len(vals) == n else dflt
            except ValueError:
                return dflt
        skins.append({'name': attr.get('AName') or os.path.basename(sp),
                      'path': sp,
                      'mtl': _normp(attr['Material']) if attr.get('Material') else None,
                      'bone': attr.get('BoneName') or '',
                      'rot': _vec(attr.get('Rotation'), 4, [1, 0, 0, 0]),
                      'pos': _vec(attr.get('Position'), 3, [0, 0, 0])})
    if not skins:  # meathead/spider 类: 空 attachment → 扫同目录+attachments子目录
        d = os.path.dirname(_normp(path))
        stem = os.path.splitext(os.path.basename(path))[0].lower()
        dirs = {d}
        att = d + '/attachments'
        if att in idx.tree:
            for sub in idx.tree[att][0]:
                dirs.add(att + '/' + sub)
        badv = re.compile(r'_lod\d|_sim|_fp\.|_cull|_dsmb|_dsm|_dmg|_old|christmas'
                          r'|halloween|easter|santa|valentine|lunar|anniversary'
                          r'|liveevent|_event|_dev|_test|dummy|_v\d|_npc|shadow')
        for low, ent in sorted(idx.files.items(), key=lambda kv: kv[0]):
            if (os.path.dirname(low) in dirs and low.endswith('.skin')
                    and os.path.basename(low).startswith(stem)
                    and not badv.search(low)):
                skins.append({'name': os.path.basename(ent[6]), 'path': low,
                              'mtl': None, 'bone': '',
                              'rot': [1, 0, 0, 0], 'pos': [0, 0, 0]})
    return {'chr': chr_p, 'mtl': mtl, 'skins': skins}


def _qpos_to_col16(quat, pos):
    """quat xyzw + pos → 列优先 4x4(OpenGL 惯例)."""
    x, y, z, w = quat
    xx, yy, zz = x * x, y * y, z * z
    xy, xz, yz, wx, wy, wz = x * y, x * z, y * z, w * x, w * y, w * z
    return [                                  # 列优先展开
        1 - 2 * (yy + zz), 2 * (xy + wz), 2 * (xz - wy), 0,
        2 * (xy - wz), 1 - 2 * (xx + zz), 2 * (yz + wx), 0,
        2 * (xz + wy), 2 * (yz - wx), 1 - 2 * (xx + yy), 0,
        pos[0], pos[1], pos[2], 1]


def _b2w_to_col16(b12):
    """b2w 3x4 行优先 → 列优先 4x4."""
    return [b12[0], b12[4], b12[8], 0,
            b12[1], b12[5], b12[9], 0,
            b12[2], b12[6], b12[10], 0,
            b12[3], b12[7], b12[11], 1]


def _mul_col16(a, b):
    """col-major 4x4 相乘: a*b. 逐元素"""
    out = [0.0] * 16
    for c in range(4):
        for r in range(4):
            out[c * 4 + r] = sum(a[k * 4 + r] * b[c * 4 + k] for k in range(4))
    return out


def parse_mtl(idx, mtl_path):
    """CryXmlB 文本 mtl → 子材质 [{name,diffuse,bump,spec}]; .tif→同stem.dds"""
    mtl_path = _normp(mtl_path)
    if mtl_path not in idx.files:
        return None
    try:
        root = ET.fromstring(idx.read(mtl_path))
    except Exception:
        return None
    mdir = os.path.dirname(mtl_path)

    def dds(ref):
        ref = _normp(ref)
        p = os.path.normpath(os.path.join(mdir, ref)).replace('\\', '/')
        for cand in (re.sub(r'\.tif$', '.dds', p), p,
                     re.sub(r'\.tif$', '.dds', ref)):
            if cand in idx.files:
                return cand
        return re.sub(r'\.tif$', '.dds', p)

    subs = []
    sm = root.find('SubMaterials')
    els = list(sm) if sm is not None else [root]
    for el in els:
        texs = {}
        for t in el.iter('Texture'):
            mp, fl = (t.get('Map') or '').lower(), t.get('File')
            if mp and fl:
                texs[mp] = dds(fl)
        subs.append({'name': el.get('Name') or 'mat',
                     'diffuse': texs.get('diffuse'),
                     'bump': texs.get('bumpmap'),
                     'spec': texs.get('specular')})
    return subs


def guess_mtl(idx, base_hint, *fallbacks):
    """spider_body.skin → 同目录逐级截尾猜 spider_body.mtl / spider.mtl"""
    for fb in fallbacks:
        if fb and _normp(fb) in idx.files:
            return _normp(fb)
    stem = os.path.splitext(_normp(base_hint))[0]
    parts = os.path.basename(stem).split('_')
    d = os.path.dirname(stem)
    for dd in (d, os.path.dirname(d)):      # 附件目录找不到 → 父级目录
        for k in range(len(parts), 0, -1):
            c = f"{dd}/{'_'.join(parts[:k])}.mtl"
            if c in idx.files:
                return c
    # 猎人配色: xxx.skin → xxx_v01.mtl(或多个 vNN 取最小)
    cand_noext = stem.split('/')[-1]
    hits = sorted(p for (low, (_k, _c, _cs, _us, _o, _m, p)) in idx.files.items()
                  if low.startswith(d + '/' + cand_noext + '_v')
                  and low.endswith('.mtl'))
    if hits:
        return hits[0]
    # attachments/butcher/x.skin → 角色根/butcher.mtl (屠夫家族映射)
    seg = d.split('/')
    if 'attachments' in seg:
        i = seg.index('attachments')
        if i + 1 < len(seg):
            c = '/'.join(seg[:i]) + '/' + seg[i + 1] + '.mtl'
            if c in idx.files:
                return c
    return None


import hashlib
HUNTDD = os.path.join(HERE, 'huntdd')
TEX_TMP = '/tmp/huntview_tex'


def tex_rgba(idx, dds_path):
    """CryEngine 分裂 DDS → [w u32][h u32] + RGBA8 原始像素(128 字节内头会被去掉)
    stub(148/128B 头) + 最大序号 .dds.N 像素分片 = mip0 微缩图。"""
    low = _normp(dds_path)
    key = hashlib.md5(low.encode()).hexdigest()[:16]
    out = os.path.join(TEX_TMP, key + '.raw')
    if not os.path.exists(out):
        os.makedirs(TEX_TMP, exist_ok=True)
        stub = idx.read(low)
        if len(stub) < 132 or stub[:4] != b'DDS ':
            raise RuntimeError('不是 DDS')
        hdr = 148 if stub[84:88] == b'DX10' else 128
        data = stub
        if len(stub) < hdr + 2048:                    # 头 stub → 找像素分片
            # 分片预算: 预览 ≤1024²。BB=每 4x4 块字节数(BC1/BC4=8 其余16 未压缩≈0)
            bb = 8
            if stub[84:88] == b'DX10':
                dxgi = int.from_bytes(stub[128:132], 'little')
                bb = 8 if dxgi in (70, 71, 72, 79, 80, 81) else (16 if 73 <= dxgi <= 99 else 0)
            elif stub[84:88] not in (b'DXT1', b'ATI1', b'BC4U'):
                bb = 16
            budget = 1024 * 1024 // 16 * bb           # 1024² ≈ 0.5MB(BC1)/1MB(BC3)
            piece, fallback = None, None
            for n in range(15, 0, -1):
                cand = f'{low}.{n}'
                if cand not in idx.files:
                    continue
                ent = idx.files[cand]
                if fallback is None:
                    fallback = cand
                if ent[3] <= budget:                  # ent[3]=解压后大小
                    piece = idx.read(cand)
                    break
            if piece is None:
                if fallback is None:
                    raise RuntimeError('分裂 DDS 找不到像素分片(贴图 pak 未挂载?)')
                piece = idx.read(fallback)            # 全超预算 → 最小那片
            data = stub[:hdr] + piece
        tmp_d = out + '.dds'
        with open(tmp_d, 'wb') as f:
            f.write(data)
        r = _sp.run([HUNTDD, tmp_d, out], capture_output=True, timeout=120)
        try:
            os.remove(tmp_d)
        except OSError:
            pass
        if r.returncode != 0 or not os.path.exists(out):
            raise RuntimeError('huntdd: ' + r.stderr.decode('utf-8', 'replace')[:200])
    with open(out, 'rb') as f:
        return f.read()


def model_payload(idx: AssetIndex, path: str):
    low = path.lower()
    ext = '.' + low.rsplit('.', 1)[-1]
    errors, models, bones, mats = [], [], [], []

    def attach_mtl(pth, hard=None, cdf_mtl=None):
        mtl_p = None
        if hard and _normp(hard) in idx.files:
            mtl_p = _normp(hard)
        if not mtl_p:
            mtl_p = guess_mtl(idx, pth)
        if not mtl_p and cdf_mtl and _normp(cdf_mtl) in idx.files:
            mtl_p = _normp(cdf_mtl)
        return parse_mtl(idx, mtl_p) if mtl_p else None

    def mat_idx(subs, matId):
        if not subs:
            return -1
        k = matId if 0 <= matId < len(subs) else 0
        s = subs[k]
        for i, m in enumerate(mats):
            if m['name'] == s['name'] and m.get('diffuse') == s.get('diffuse'):
                return i
        mats.append(s)
        return len(mats) - 1

    def add_file(pth, prefer_bones, subs=None, tag='', xform=None):
        try:
            parsed = huntcgf.parse_cgf(idx.read(pth))
        except Exception as e:
            errors.append(f'{pth}: {e}')
            return
        for m in parsed['meshes']:
            total = len(m['indices']) * 3
            parts = [{'first': s['firstIndex'], 'count': s['numIndices'],
                      'mat': mat_idx(subs, s['matId'])}
                     for s in m['subsets']]
            covered = sum(p['count'] for p in parts)
            if not parts:
                parts = [{'first': 0, 'count': total, 'mat': mat_idx(subs, 0)}]
            elif covered < total:                     # spider_body: 尾部悬空段
                parts.append({'first': covered,
                              'count': total - covered,
                              'mat': parts[0]['mat']})
            t = m['transform']
            if xform is not None:
                t = _mul_col16(xform, t)
            models.append({
                'name': tag or m['name'] or os.path.basename(pth),
                'mat': huntcgf.mat_name(parsed, m['matChunkId']),
                'transform': t,
                'pos': [c for v in m['positions'] for c in v],
                'nrm': [c for v in m['normals'] for c in v],
                'tan': [c for v in m.get('tangents') or [] for c in v],
                'uv': [c for v in m['uvs'] for c in v],
                'idx': [i for tri in m['indices'] for i in tri],
                'parts': parts})
        if len(parsed['skeleton']) > len(bones):
            bones[:] = parsed['skeleton']
        errors.extend(parsed['errors'])

    if ext == '.cdf':                    # ▶ 整模型装配: 骨架 + 全部皮肤部件
        try:
            cdf = parse_cdf_attach(idx, path)
        except Exception as e:
            errors.append(f'cdf 解析失败: {e}')
            cdf = None
        if cdf:
            if cdf['chr'] and cdf['chr'] in idx.files:
                add_file(cdf['chr'], True)
            bone_xf = {b['name']: _b2w_to_col16(b['b2w']) for b in bones}
            for sk in cdf['skins']:
                subs = attach_mtl(sk['path'], sk['mtl'], cdf['mtl'])
                xf = None
                if sk.get('bone') and sk['bone'] in bone_xf:
                    xf = _mul_col16(bone_xf[sk['bone']],
                                    _qpos_to_col16(sk['rot'], sk['pos']))
                add_file(sk['path'], False, subs, sk['name'], xf)
                for mate in (sk['path'][:-4] + 'm', sk['path'] + 'm'):
                    if mate in idx.files and mate != sk['path']:
                        add_file(mate, False, subs, sk['name'], xf)
                        break
            return {'title': path, 'models': models, 'errors': errors[:8],
                    'materials': mats, 'cdf': True,
                    'bones': [{'name': b['name'], 'parentOff': b['offsetParent'],
                               'b2w': b['b2w']} for b in bones]}

    subs = attach_mtl(path)             # 单文件点击: 顺带猜材质
    add_file(path, True, subs)
    stems = os.path.splitext(low)[0]
    for cand in (stems + ext + 'm', low + 'm'):
        if cand in idx.files and cand != low:
            add_file(cand, False, subs)
            break
    return {'title': path, 'models': models, 'errors': errors[:8],
            'materials': mats,
            'bones': [{'name': b['name'], 'parentOff': b['offsetParent'],
                       'b2w': b['b2w']} for b in bones]}




def outfit_payload(idx: AssetIndex, gender='male', setno='001'):
    """猎人换装拼装: 同编号跨部位, 每槽一件, 洗脸规则滤掉装饰杂物.
    setno='list' → 只返回可用编号清单."""
    g = 'hunter_female' if gender.startswith('f') else 'hunter_male'
    tag = 'hfus' if gender.startswith('f') else 'hmus'
    base = f'characters/{g}'
    assets = f'{base}/us/assets'
    chr_p = f'{base}/hf_skel.chr' if gender.startswith('f') else f'{base}/hm_skel.chr'
    if chr_p not in idx.files:                      # 女猎人公用男骨架
        chr_p = 'characters/hunter_male/hm_skel.chr'

    # 槽位 → {编号: 目录}
    slots = {}
    for slot_path in idx.tree:
        if not slot_path.startswith(assets + '/'):
            continue
        parts = slot_path[len(assets) + 1:].split('/')
        if len(parts) != 2:
            continue
        mnum = re.search(r'_(\d{3})$', parts[1])
        if mnum:
            slots.setdefault(parts[0], {}).setdefault(mnum.group(1), []).append(parts[1])

    if setno == 'list':
        alln = sorted({n for s in slots.values() for n in s})
        return {'found': True, 'numbers': alln}

    # 选装规则: 每槽取“名字最少修饰词”的同编号目录
    deco = re.compile(r'beard|eyepatch|glasses|hair_|zombie|lgnd|legendary|dead'
                      r'|atlas|layout|skull|trinket|rope|backpack|bedroll|canteen'
                      r'|pouch|cigarette|christmas|indigenous|victor|vinson|otis'
                      r'|pale|posti|senator|strongman|chef|highrank|_merged|_var')
    badf = re.compile(r'_lod\d|_fp|_fix|_sim|_dsmb|_dmg')
    chosen = []
    for slot in ('face', 'torso', 'legs', 'armor', 'hat'):
        probes = [setno] if slot != 'face' else [
            f'{int(setno) + i:03d}' for i in range(5)]      # 脸允许缺号向后借
        chosen_dirs = None
        for use_n in probes:
            if use_n not in slots.get(slot, {}):
                continue
            cds = [d for d in slots[slot][use_n] if not deco.search(d)]
            if slot == 'face':
                cds = [d for d in cds if f'_face_{use_n}' in d]
            if cds:
                chosen_dirs = cds
                break
        if not chosen_dirs:
            continue
        if slot in ('hat',):                       # 帽槽同编号多目录→只取最短一件
            chosen_dirs = [sorted(chosen_dirs, key=len)[0]]
        for dname in sorted(chosen_dirs, key=len):     # armor 槽目录全收(甲+双护腕)
            slot_path = assets + '/' + slot + '/' + dname
            files = idx.tree.get(slot_path, (None, []))[1]
            skins = [(n.lower(), p) for n, p, _s in files
                     if n.lower().endswith('.skin') and not badf.search(n.lower())]
            if not skins:
                badf2 = re.compile(r'_lod\d|_fp|_fix|_sim|_dsmb|_dmg')
                skins = [(n.lower(), p) for n, p, _s in files
                         if n.lower().endswith('.skin') and not badf2.search(n.lower())]
            if not skins:
                continue
            skins.sort(key=lambda cp: (len(cp[0]), cp[0]))
            picked = [skins[0]]
            st0 = skins[0][0]
            for pairo in skins[1:]:                # _l/_r 对(护腕)双手都装
                if (re.sub(r'_[lr]\.skin$', '', pairo[0])
                        == re.sub(r'_[lr]\.skin$', '', st0)
                        and pairo[0] != st0):
                    picked.append(pairo)
            for pn, pp in picked:
                chosen.append({'name': slot + ':' + os.path.splitext(pn)[0],
                               'path': pp, 'mtl': None})
    return _assemble_from_attach(
        idx, {'chr': chr_p, 'mtl': None, 'skins': chosen},
        f'{g} 猎人 · 套装 {setno}')


def _assemble_from_attach(idx, cdf, title, default_mtl_d=None):
    """通用装配内核: chr + 附件列表 → payload(outfit 复用)."""
    errors, models, bones, mats = [], [], [], []

    def attach_mtl(pth, hard=None, cdf_mtl=None):
        mtl_p = None
        if hard and _normp(hard) in idx.files:
            mtl_p = _normp(hard)
        if not mtl_p:
            mtl_p = guess_mtl(idx, pth)
        if not mtl_p and cdf_mtl and _normp(cdf_mtl) in idx.files:
            mtl_p = _normp(cdf_mtl)
        return parse_mtl(idx, mtl_p) if mtl_p else None

    def mat_idx(subs, matId):
        if not subs:
            return -1
        k = matId if 0 <= matId < len(subs) else 0
        s = subs[k]
        for i, m in enumerate(mats):
            if m['name'] == s['name'] and m.get('diffuse') == s.get('diffuse'):
                return i
        mats.append(s)
        return len(mats) - 1

    def add_file(pth, prefer_bones, subs=None, tag='', xform=None):
        try:
            parsed = huntcgf.parse_cgf(idx.read(pth))
        except Exception as e:
            errors.append(f'{pth}: {e}')
            return
        for m in parsed['meshes']:
            total = len(m['indices']) * 3
            parts = [{'first': s['firstIndex'], 'count': s['numIndices'],
                      'mat': mat_idx(subs, s['matId'])}
                     for s in m['subsets']]
            covered = sum(p['count'] for p in parts)
            if not parts:
                parts = [{'first': 0, 'count': total, 'mat': mat_idx(subs, 0)}]
            elif covered < total:
                parts.append({'first': covered, 'count': total - covered,
                              'mat': parts[0]['mat']})
            t = m['transform']
            if xform is not None:
                t = _mul_col16(xform, t)
            models.append({
                'name': tag or m['name'] or os.path.basename(pth),
                'mat': huntcgf.mat_name(parsed, m['matChunkId']),
                'transform': t,
                'pos': [c for v in m['positions'] for c in v],
                'nrm': [c for v in m['normals'] for c in v],
                'tan': [c for v in m.get('tangents') or [] for c in v],
                'uv': [c for v in m['uvs'] for c in v],
                'idx': [i for tri in m['indices'] for i in tri],
                'parts': parts})
        if len(parsed['skeleton']) > len(bones):
            bones[:] = parsed['skeleton']
        errors.extend(parsed['errors'])

    if cdf['chr'] and cdf['chr'] in idx.files:
        add_file(cdf['chr'], True)
    bone_xf = {b['name']: _b2w_to_col16(b['b2w']) for b in bones}
    for sk in cdf['skins']:
        subs = attach_mtl(sk['path'], sk.get('mtl'), cdf.get('mtl'))
        xf = None
        if sk.get('bone') and sk['bone'] in bone_xf:
            xf = _mul_col16(bone_xf[sk['bone']],
                            _qpos_to_col16(sk.get('rot', [1, 0, 0, 0]),
                                           sk.get('pos', [0, 0, 0])))
        add_file(sk['path'], False, subs, sk['name'], xf)
        for mate in (sk['path'][:-4] + 'm', sk['path'] + 'm'):
            if mate in idx.files and mate != sk['path']:
                add_file(mate, False, subs, sk['name'], xf)
                break
    return {'title': title, 'models': models, 'errors': errors[:8],
            'materials': mats, 'cdf': True,
            'bones': [{'name': b['name'], 'parentOff': b['offsetParent'],
                       'b2w': b['b2w']} for b in bones]}

def anims_payload(idx: AssetIndex, path: str):
    """找与该资产关联的动画清单(chrparams 的 AnimationList)"""
    low = path.lower()
    stem = os.path.splitext(low)[0]
    dirn = os.path.dirname(low)
    chr_path = None
    if low.endswith('.chr'):
        chr_path = low
    else:
        cands = []
        if low.endswith('.cdf'):
            try:
                xml = idx.read(idx.files[low][6]).decode('utf-8', 'replace')
                mdl = re.search(r'<Model[^>]*File="([^"]+)"', xml)
                if mdl:
                    chr_path = mdl.group(1).lower()
            except Exception:
                pass
        if not chr_path:
            base = os.path.basename(stem)
            # 逐级截掉尾部下划线段: spider_body → spider_body.cdf / spider.cdf
            parts = base.split('_')
            for k in range(len(parts), 0, -1):
                c = f"{dirn}/{'_'.join(parts[:k])}.cdf"
                if c in idx.files:
                    try:
                        xml = idx.read(idx.files[c][6]).decode('utf-8', 'replace')
                        mdl = re.search(r'<Model[^>]*File="([^"]+)"', xml)
                        if mdl and mdl.group(1).lower() in idx.files:
                            chr_path = mdl.group(1).lower()
                            break
                    except Exception:
                        continue
    if not chr_path:
        return {'found': False, 'anims': []}
    params = os.path.splitext(chr_path)[0] + '.chrparams'
    if params not in idx.files:
        return {'found': False, 'chr': chr_path, 'anims': []}
    xml = idx.read(idx.files[params][6]).decode('utf-8', 'replace')
    anims, folders = [], []
    for m in re.finditer(r'<Animation\s+name="([^"]*)"\s+path="([^"]*)"', xml):
        name, db = m.group(1), m.group(2)
        if name.startswith(('$', '#', '*')):
            # 通配符(*/​*.caf 等) → 列出该角色 animations/ 目录下的实际文件
            anim_dir = os.path.dirname(params) + '/animations/'
            seen = set(f['path'] for f in folders)
            for low, (_k, _c, _cs, us, _o, _m, pth) in idx.files.items():
                if low.startswith(anim_dir) and pth not in seen:
                    folders.append({'path': pth, 'size': us})
                    seen.add(pth)
            continue
        anims.append({'name': name, 'dba': db.split('#')[0]})
    folders.sort(key=lambda f: f['path'])
    clips = []                                   # .animevents 里的 bspace 动画名
    try:
        cd = os.path.dirname(params)
        base = cd.split('/')[-1]                 # spider_skel 或目录名
        ev_dir = os.path.dirname(cd) if cd.endswith('_skel') else cd
        for cand in (f'{ev_dir}/{os.path.basename(ev_dir)}.animevents',
                     f'{cd}/{base}.animevents'):
            if cand in idx.files:
                ev = idx.read(cand).decode('utf-8', 'replace')
                for nm in re.findall(r'<animation name="([^"]+)"', ev):
                    if nm not in clips:
                        clips.append(nm)
                break
    except Exception:
        pass
    return {'found': True, 'chr': chr_path, 'chrparams': params,
            'anims': anims, 'clips': clips[:600], 'files': folders[:400]}

# ════════════════════════ 音频转码 (wem → ogg) ════════════════════════
import hashlib
import shutil
import subprocess

WW2OGG = os.path.join(HERE, 'ww2ogg')
REVORB = os.path.join(HERE, 'revorb')
AUDIO_TMP = '/tmp/huntview_audio'


def _wem_codec(data):
    i = data.find(b'fmt ')
    if i < 0 or i + 10 > len(data):
        return 0, 'unknown'
    codec = struct.unpack_from('<H', data, i + 8)[0]
    names = {0xFFFF: 'vorbis', 0x0166: 'xWMA', 0x3040: 'opus', 0x3041: 'opus',
             1: 'pcm', 2: 'adpcm'}
    return codec, names.get(codec, 'codec-0x%04x' % codec)


def audio_convert(idx: AssetIndex, path: str) -> bytes:
    if not path.lower().endswith('.wem'):
        raise RuntimeError('只有 .wem 支持在线播放(.bnk 是容器)')
    data = idx.read(path)
    codec, cname = _wem_codec(data)
    os.makedirs(AUDIO_TMP, exist_ok=True)
    key = hashlib.md5(str(len(data)).encode() + data[:2048]).hexdigest()[:16]
    ogg = os.path.join(AUDIO_TMP, key + '.ogg')

    def valid(p):
        try:
            with open(p, 'rb') as f:
                mag = f.read(4)
                return mag in (b'OggS', b'RIFF', b'fLaC') and os.path.getsize(p) > 64
        except OSError:
            return False

    if valid(ogg):
        with open(ogg, 'rb') as f:
            return f.read()

    wem = ogg + '.wem'
    with open(wem, 'wb') as f:
        f.write(data)
    errs = []
    try:
        os.chmod(WW2OGG, 0o755)
    except OSError:
        pass
    # 1) ww2ogg (旧 Vorbis)
    if os.path.exists(WW2OGG) and cname == 'vorbis':
        for flags in ([], ['--no-mod-packets'], ['--mod-packets'],
                      ['--inline-codebooks']):
            if os.path.exists(ogg):
                try:
                    os.remove(ogg)
                except OSError:
                    pass
            r = subprocess.run([WW2OGG, wem, '-o', ogg] + flags,
                               capture_output=True, timeout=180, cwd=HERE)
            if r.returncode == 0 and valid(ogg):
                os.remove(wem)
                with open(ogg, 'rb') as f:
                    return f.read()
            errs.append((r.stderr or r.stdout).decode('utf-8', 'replace')[:120])
    # 2) ffmpeg (Hunt 新包大量 Opus)
    ff = shutil.which('ffmpeg')
    if ff:
        for out, extra in ((ogg, ['-c:a', 'libvorbis', '-q:a', '4']),
                           (ogg + '.opus', ['-c:a', 'copy'])):
            r = subprocess.run(
                [ff, '-y', '-loglevel', 'error', '-i', wem] + extra + [out],
                capture_output=True, timeout=180)
            if r.returncode == 0 and os.path.exists(out) and os.path.getsize(out) > 64:
                try:
                    os.remove(wem)
                except OSError:
                    pass
                with open(out, 'rb') as f:
                    return f.read()
            errs.append('ffmpeg: ' + (r.stderr or b'').decode('utf-8', 'replace')[:120])
    # 3) vgmstream
    vg = shutil.which('vgmstream-cli') or shutil.which('vgmstream123')
    if vg and 'vgmstream-cli' in vg:
        r = subprocess.run([vg, '-o', ogg, wem], capture_output=True, timeout=180)
        if r.returncode == 0 and valid(ogg):
            os.remove(wem)
            with open(ogg, 'rb') as f:
                return f.read()
            errs.append('vgmstream: ' + (r.stderr or b'').decode('utf-8', 'replace')[:120])
    try:
        os.remove(wem)
    except OSError:
        pass
    hint = ''
    if cname == 'opus' and not shutil.which('ffmpeg'):
        hint = ' 装 ffmpeg: sudo apt install ffmpeg'
    raise RuntimeError('音频转码失败(%s).%s %s' % (cname, hint, ' | '.join(errs)[:180]))

SPA = r"""<!DOCTYPE html>
<html lang="zh"><head><meta charset="utf-8"><title>猎杀对决 · 资产浏览器</title>
<style>
*{box-sizing:border-box}
body{margin:0;background:#141210;color:#d8cdb4;font-family:system-ui,'Microsoft YaHei',sans-serif;display:flex;height:100vh;overflow:hidden}
#side{width:330px;background:#1c1915;border-right:1px solid #3a332a;display:flex;flex-direction:column}
#side h1{font-size:15px;color:#c9a959;margin:12px 12px 6px}
#search{margin:0 10px 8px;padding:7px 10px;background:#262118;border:1px solid #554a37;color:#eee;border-radius:5px}
#tree{flex:1;overflow:auto;padding:0 6px;font-size:12px}
.dir>label{cursor:pointer;color:#a89b78;display:block;padding:3px 4px;border-radius:3px}
.dir>label:hover{background:#332d20}.dir>label::before{content:'▸ ';opacity:.6}.dir.open>label::before{content:'▾ '}
.kids{display:none;padding-left:14px}.dir.open>.kids{display:block}
.file{padding:2px 4px 2px 16px;cursor:pointer;color:#cfc5aa;border-radius:3px;white-space:nowrap}
.file:hover{background:#332d20;color:#ffe9a8}.file.sel{background:#4a3d23;color:#ffe9a8}
#searchhit{padding:2px 8px;cursor:pointer;color:#cfc5aa;font-size:12px}
#searchhit:hover{background:#332d20}
#quick{display:flex;flex-wrap:wrap;gap:4px;padding:0 10px 6px}
#quick .q{font-size:11px;padding:2px 7px;flex:0 0 auto}
#quick .q.on{background:#6b5a33;color:#ffe9a8}
#hint{font-size:10px;color:#8a7c5c;padding:0 12px 6px;line-height:1.5}
#main{flex:1;position:relative;background:#171410}
#cv{width:100%;height:100%;display:block}
#top{position:absolute;top:0;left:0;right:0;padding:8px 10px;background:#00000066;font-size:12px;display:flex;gap:8px;align-items:center;backdrop-filter:blur(3px)}
#top b{color:#c9a959}#top .grow{flex:1}
button{background:#3a332a;color:#d8cdb4;border:1px solid #554a37;border-radius:4px;padding:3px 9px;font-size:12px;cursor:pointer}
button.on{background:#6b5a33;color:#ffe9a8}
#msg{position:absolute;left:50%;top:45%;transform:translate(-50%,-50%);font-size:14px;color:#8a7c5c;pointer-events:none;text-align:center;line-height:2}
#anim{position:absolute;right:0;top:34px;bottom:0;width:265px;background:#1c1915d9;overflow-y:auto;font-size:12px;padding:8px;border-left:1px solid #3a332a}
#anim h2{font-size:13px;color:#c9a959;margin:4px 0}
#anim .a{padding:3px 6px;border-radius:3px}#anim .a:hover{background:#332d20}
#anim small{opacity:.5;word-break:break-all}
#player{position:absolute;left:0;right:0;bottom:0;background:#1c1915f0;border-top:1px solid #3a332a;padding:8px 12px;font-size:12px;display:none}
#player audio{width:100%;height:32px;margin-top:4px}
#shelf{display:none}
#shelftop{display:flex;gap:8px;align-items:center;padding:10px 14px;border-bottom:1px solid #3a332a;font-size:13px}
#shelfdir{background:#262118;border:1px solid #554a37;color:#eee;border-radius:4px;padding:5px 8px;width:300px;font-size:12px}
#shelfgrid{flex:1;overflow:auto;display:grid;grid-template-columns:repeat(auto-fill,minmax(176px,1fr));gap:10px;padding:12px}
.card{background:#1c1915;border:1px solid #3a332a;border-radius:6px;cursor:pointer;text-align:center;padding:8px 6px;font-size:11px;color:#cfc5aa;transition:border-color .15s}
.card:hover{border-color:#c9a959;color:#ffe9a8}
.card img{width:160px;height:160px;image-rendering:auto;border-radius:4px;background:#262118}
.card .nm{word-break:break-all;margin-top:4px;max-height:2.6em;overflow:hidden}
.card .wait{line-height:160px;color:#554a37}
#pname{color:#c9a959}
</style></head><body>
<div id="side">
 <h1>🕯️ 猎杀对决 · 资产浏览器</h1>
 <input id="search" placeholder="搜索文件(如 butcher / bomb / nitro)…">
 <div id="quick">
  <button class="q" id="qmale">👤 男猎人</button>
  <button class="q" id="qfemale">👩 女猎人</button>
  <select id="qset" style="background:#262118;color:#d8cdb4;border:1px solid #554a37;border-radius:4px;font-size:11px;padding:2px"><option>001</option></select>
  <button class="q" id="qweap">🔫 武器库</button>
  <button class="q" id="qmob">👹 怪物</button>
  <button class="q" id="qprop">📦 物件</button>
  <button class="q" id="qshelf">🧺 物品栏</button>
  <button class="q" id="qaud">🎵 音频</button>
  <button class="q" id="qaux">🗃️ 显示杂件</button>
 </div>
 <div id="hint">左键旋转·右键平移·滚轮缩放 · <b>Shift+点文件=叠加拼装</b></div>
 <div id="tree"></div>
</div>
<div id="main"><canvas id="cv"></canvas>
 <div id="top"><span class="grow"><b id="cur">未选择</b><span id="info"></span></span>
  <button id="bwire">线框</button><button id="bbone" class="on">骨架</button><button id="btex" class="on">贴图</button><button id="bnrm">法线</button><button id="bspec">高光</button><button id="bdbg">原法线</button>
  <button id="bshot" title="截图">📷</button><button id="breset">复位</button><button id="bglb" style="display:none">导出 glTF</button><button id="bdl" style="display:none">下载原始文件</button></div>
 <div id="msg">← 左边点开目录或搜索<br>角色模型在 characters/ · 武器在 characters/weapons/<br>静态物件在 objects/</div>
 <div id="anim" style="display:none"><h2>🎞️ 相关动画</h2><div id="anims"></div></div>
 <div id="player"><span id="pname"></span><br><audio id="ap" controls autoplay></audio></div>
<div id="shelf" style="display:none;position:absolute;inset:0;background:#171410f2;z-index:8;flex-direction:column">
 <div id="shelftop">
  <b style="color:#c9a959">🧺 物品栏</b>
  <input id="shelfdir" placeholder="目录(如 characters 或 characters/weapons)">
  <button id="bshelfgo">取货</button><span id="shelfinfo"></span>
  <span style="flex:1"></span>
  <button onclick="document.getElementById('shelf').style.display='none'">收起</button>
 </div>
 <div id="shelfgrid"></div>
</div>
<div id="texview" style="display:none;position:absolute;inset:40px;background:#12100cdd;border:1px solid #554a37;border-radius:6px;overflow:auto;padding:10px;z-index:9">
 <div style="display:flex;gap:8px;align-items:center;margin-bottom:6px"><b id="tvtitle" style="color:#c9a959"></b><span class="grow" style="flex:1"></span><button onclick="document.getElementById('texview').style.display='none'">关闭 (Esc)</button></div>
 <div id="tvbody" style="display:flex;flex-wrap:wrap;gap:10px"></div></div>
</div>
<script>
window.onerror=function(m,s,l){var e=document.getElementById('msg');if(e){e.style.display='';e.style.pointerEvents='auto';e.textContent='JS错误: '+m+' @'+l}};
const cv=document.getElementById('cv'),gl=cv.getContext('webgl',{antialias:true})||cv.getContext('experimental-webgl');
if(!gl){document.getElementById('msg').textContent='WebGL 不可用, 换 Chrome/Firefox(目录树仍应能显示)';}
function rs(){if(!gl)return;cv.width=cv.clientWidth;cv.height=cv.clientHeight;gl.viewport(0,0,cv.width,cv.height)}addEventListener('resize',rs);rs();
const VS=`attribute vec3 p;attribute vec3 n;attribute vec4 tan;attribute vec2 uv;uniform mat4 mvp;uniform mat4 mv;varying vec3 N;varying vec3 T;varying float Ts;varying vec2 UV;varying vec3 VP;
void main(){gl_Position=mvp*vec4(p,1.);VP=(mv*vec4(p,1.)).xyz;mat3 nm=mat3(mv);N=nm*n;T=nm*tan.xyz;Ts=tan.w;UV=uv;}`;
const FS=`#extension GL_OES_standard_derivatives:enable
precision mediump float;varying vec3 N;varying vec3 T;varying float Ts;varying vec2 UV;varying vec3 VP;
uniform vec3 col;uniform float useTex;uniform sampler2D tex;
uniform float useNrm;uniform sampler2D nrm;uniform float useSpec;uniform sampler2D spec;
uniform float dbgNrm;
void main(){
 if(dbgNrm>.5){gl_FragColor=vec4(texture2D(nrm,UV).rgb,1.);return;}
 vec3 NN=normalize(N);
 float gloss=.16;
 if(useNrm>.5){
  vec4 ns=texture2D(nrm,UV);
  vec3 nts;
  nts.xy=ns.rg*2.-1.;
  nts.y=-nts.y;
  nts.z=sqrt(max(.001,1.-dot(nts.xy,nts.xy)));
  if(ns.a<0.99)gloss=ns.a;
  vec3 TT=T;float tl=dot(TT,TT);
  if(tl>0.01){TT=normalize(TT);vec3 Btn=normalize(cross(NN,TT)*Ts);
   NN=normalize(TT*nts.x+Btn*nts.y+NN*nts.z);}}
 vec3 V=normalize(-VP);
 vec3 L1=normalize(vec3(.42,.72,.55)),L2=normalize(vec3(-.55,.15,-.6));
 vec3 base=col;
 if(useTex>.5){vec4 c=texture2D(tex,UV);if(c.a<.08)discard;base=c.rgb;}
 if(useSpec>.5){vec4 s=texture2D(spec,UV);gloss=s.a>0.02?s.a:s.r;}
 float dif=clamp(dot(NN,L1),0.,1.)*.62+clamp(dot(NN,L2),0.,1.)*.22+.20;
 float h=pow(clamp(dot(reflect(-L1,NN),V),0.,1.),mix(6.,36.,gloss))*gloss*.4;
 vec3 o=base*dif+vec3(h)+base*.03;
 gl_FragColor=vec4(o,1.);}`;
const DERIV=gl.getExtension('OES_standard_derivatives');
const LVS=`attribute vec3 p;uniform mat4 mvp;void main(){gl_Position=mvp*vec4(p,1.);gl_PointSize=7.;}`;
const LFS=`precision mediump float;void main(){gl_FragColor=vec4(1.,.35,.55,1.);}`;
function prog(v,f){const P=gl.createProgram();for(const[t,s]of[[gl.VERTEX_SHADER,v],[gl.FRAGMENT_SHADER,f]]){const sh=gl.createShader(t);gl.shaderSource(sh,s);gl.compileShader(sh);gl.attachShader(P,sh);}gl.linkProgram(P);return P;}
gl.getExtension('OES_element_index_uint');
const P=prog(VS,FS),LP=prog(LVS,LFS);gl.enable(gl.DEPTH_TEST);
let rot=[.6,.8],dist=6,pan=[0,0,0],drag=null;
cv.onmousedown=e=>{drag={x:e.clientX,y:e.clientY,b:e.button,rot:[...rot],pan:[...pan]};e.preventDefault()};
onmousemove=e=>{if(!drag)return;const dx=e.clientX-drag.x,dy=e.clientY-drag.y;
 if(drag.b===2){pan=[drag.pan[0]+dx*dist*.0016,drag.pan[1]-dy*dist*.0016,0]}
 else rot=[Math.max(-1.35,Math.min(1.35,drag.rot[0]+dy*.008)),drag.rot[1]+dx*.008]};
onmouseup=()=>drag=null;
cv.oncontextmenu=e=>e.preventDefault();
cv.onwheel=e=>{dist*=e.deltaY>0?1.12:.89;e.preventDefault()};
function mul(a,b){const r=new Float32Array(16);for(let i=0;i<4;i++)for(let j=0;j<4;j++)for(let k=0;k<4;k++)r[j*4+i]+=a[k*4+i]*b[j*4+k];return r}
function persp(f,a,n,fr){const t=1/Math.tan(f/2);return new Float32Array([t/a,0,0,0,0,t,0,0,0,0,(fr+n)/(n-fr),-1,0,0,2*fr*n/(n-fr),0])}
let models=[],boneBuf=null,bonePts=null,boneN=0,boneLn=0,showBones=true,wire=false,texOn=true,nrmOn=false,specOn=false,dbgNrm=false,span=1,ctr=[0,0,0];
const texCache={},rawCache={};
function fetchRaw(url){
 if(!rawCache[url])rawCache[url]=fetch(url).then(r=>{if(!r.ok)throw 0;return r.arrayBuffer()})
  .then(b=>{const dv=new DataView(b),w=dv.getUint32(0,true),h=dv.getUint32(4,true);
   if(w<1||h<1||w*h*4+8!==b.byteLength)throw 0;return b;});
 return rawCache[url];}
function uploadTex(g,b,nomip){
 const dv=new DataView(b),w=dv.getUint32(0,true),h=dv.getUint32(4,true);
 const t=g.createTexture();g.bindTexture(g.TEXTURE_2D,t);
 g.texImage2D(g.TEXTURE_2D,0,g.RGBA,w,h,0,g.RGBA,g.UNSIGNED_BYTE,new Uint8Array(b,8));
 g.texParameteri(g.TEXTURE_2D,g.TEXTURE_MAG_FILTER,g.LINEAR);
 g.texParameteri(g.TEXTURE_2D,g.TEXTURE_WRAP_S,g.CLAMP_TO_EDGE);
 g.texParameteri(g.TEXTURE_2D,g.TEXTURE_WRAP_T,g.CLAMP_TO_EDGE);
 if(nomip){g.texParameteri(g.TEXTURE_2D,g.TEXTURE_MIN_FILTER,g.LINEAR);}
 else {g.texParameteri(g.TEXTURE_2D,g.TEXTURE_MIN_FILTER,g.LINEAR_MIPMAP_LINEAR);g.generateMipmap(g.TEXTURE_2D);}
 return t;}
function loadTex(url,nomip){
 const k=url+(nomip?'|n':'');
 if(k in texCache)return texCache[k];
 const slot={tex:null};texCache[k]=slot;
 fetchRaw(url).then(b=>{slot.tex=uploadTex(gl,b,nomip)}).catch(()=>{});
 return slot;}
function loadModel(D, append){
 if(!append){
  for(const m of models){gl.deleteBuffer(m.pb);gl.deleteBuffer(m.ib);m.nb&&gl.deleteBuffer(m.nb);m.tb&&gl.deleteBuffer(m.tb);m.wb&&gl.deleteBuffer(m.wb);m.uvb&&gl.deleteBuffer(m.uvb);for(const P of m.parts||[])gl.deleteBuffer(P.ib)}
  models=[];boneN=0;}
 for(const M of D.models){if(!M.pos||!M.pos.length)continue;
  const pos=new Float32Array(M.pos),idx=new Uint32Array(M.idx),t=M.transform;
  let mn=[1e9,1e9,1e9],mx=[-1e9,-1e9,-1e9];
  for(let i=0;i<pos.length;i+=3){const x=pos[i],y=pos[i+1],z=pos[i+2];
   pos[i]=t[0]*x+t[4]*y+t[8]*z+t[12];pos[i+1]=t[1]*x+t[5]*y+t[9]*z+t[13];pos[i+2]=t[2]*x+t[6]*y+t[10]*z+t[14];
   for(let a=0;a<3;a++){const v=pos[i+a];if(v<mn[a])mn[a]=v;if(v>mx[a])mx[a]=v}}
  const pb=gl.createBuffer();gl.bindBuffer(gl.ARRAY_BUFFER,pb);gl.bufferData(gl.ARRAY_BUFFER,pos,gl.STATIC_DRAW);
  const ib=gl.createBuffer();gl.bindBuffer(gl.ELEMENT_ARRAY_BUFFER,ib);gl.bufferData(gl.ELEMENT_ARRAY_BUFFER,idx,gl.STATIC_DRAW);
  let nb=null;if(M.nrm&&M.nrm.length===M.pos.length){const nrm=new Float32Array(M.nrm);
  for(let i=0;i<nrm.length;i+=3){const x=nrm[i],y=nrm[i+1],z=nrm[i+2];
   nrm[i]=t[0]*x+t[4]*y+t[8]*z;nrm[i+1]=t[1]*x+t[5]*y+t[9]*z;nrm[i+2]=t[2]*x+t[6]*y+t[10]*z;}
  nb=gl.createBuffer();gl.bindBuffer(gl.ARRAY_BUFFER,nb);gl.bufferData(gl.ARRAY_BUFFER,nrm,gl.STATIC_DRAW)}
  let tb=null;if(M.tan&&M.tan.length===M.pos.length/3*4){const tan=new Float32Array(M.tan);
  for(let i=0;i<tan.length;i+=4){const x=tan[i],y=tan[i+1],z=tan[i+2];
   tan[i]=t[0]*x+t[4]*y+t[8]*z;tan[i+1]=t[1]*x+t[5]*y+t[9]*z;tan[i+2]=t[2]*x+t[6]*y+t[10]*z;}
  tb=gl.createBuffer();gl.bindBuffer(gl.ARRAY_BUFFER,tb);gl.bufferData(gl.ARRAY_BUFFER,tan,gl.STATIC_DRAW)}
  const w=new Uint32Array(idx.length*2);for(let f=0;f<idx.length/3;f++){w[f*6]=idx[f*3];w[f*6+1]=idx[f*3+1];w[f*6+2]=idx[f*3+1];w[f*6+3]=idx[f*3+2];w[f*6+4]=idx[f*3+2];w[f*6+5]=idx[f*3]}
  const wb=gl.createBuffer();gl.bindBuffer(gl.ELEMENT_ARRAY_BUFFER,wb);gl.bufferData(gl.ELEMENT_ARRAY_BUFFER,w,gl.STATIC_DRAW);
  let uvb=null;if(M.uv&&M.uv.length===M.pos.length/3*2){uvb=gl.createBuffer();gl.bindBuffer(gl.ARRAY_BUFFER,uvb);gl.bufferData(gl.ARRAY_BUFFER,new Float32Array(M.uv),gl.STATIC_DRAW)}
  let h=0;for(const c of M.mat)h=(h*31+c.charCodeAt(0))>>>0;
  const col=[.5+(h%89)/280,.48+((h>>7)%89)/300,.45+((h>>13)%89)/320];
  const parts=[];for(const P of(M.parts||[{first:0,count:idx.length,mat:-1}])){
   const pib=gl.createBuffer();gl.bindBuffer(gl.ELEMENT_ARRAY_BUFFER,pib);
   gl.bufferData(gl.ELEMENT_ARRAY_BUFFER,idx.subarray(P.first,P.first+P.count),gl.STATIC_DRAW);
   let slot=null,slotN=null,slotS=null;const mi=P.mat;
   if(mi>=0&&D.materials&&D.materials[mi]){const MM=D.materials[mi];
    if(MM.diffuse)slot=loadTex('/api/tex?path='+encodeURIComponent(MM.diffuse));
    if(MM.bump)slotN=loadTex('/api/tex?path='+encodeURIComponent(MM.bump));
    if(MM.spec)slotS=loadTex('/api/tex?path='+encodeURIComponent(MM.spec));}
   parts.push({ib:pib,n:P.count,tex:slot,nre:slotN,spe:slotS});}
  models.push({pb,ib,nb,tb,uvb,wb,n:idx.length,mn,mx,col,parts});}
 let allmn=[1e9,1e9,1e9],allmx=[-1e9,-1e9,-1e9];
 for(const m of models)for(let a=0;a<3;a++){allmn[a]=Math.min(allmn[a],m.mn[a]);allmx[a]=Math.max(allmx[a],m.mx[a])}
 if(models.length){ctr=[(allmn[0]+allmx[0])/2,(allmn[1]+allmx[1])/2,(allmn[2]+allmx[2])/2];
  span=Math.max(.05,...allmx.map((v,i)=>v-allmn[i]));dist=span*1.8;pan=[0,0,0];rot=[.6,.8]}
 if(D.bones&&D.bones.length){const L=[],Pts=[];
  for(let i=0;i<D.bones.length;i++){const b=D.bones[i],x=b.b2w[3],y=b.b2w[7],z=b.b2w[11];Pts.push(x,y,z);
   if(b.parentOff>0){const p=i-b.parentOff;
    if(p>=0&&p<D.bones.length){L.push(x,y,z,D.bones[p].b2w[3],D.bones[p].b2w[7],D.bones[p].b2w[11])}}}
  boneBuf=gl.createBuffer();gl.bindBuffer(gl.ARRAY_BUFFER,boneBuf);gl.bufferData(gl.ARRAY_BUFFER,new Float32Array(L.length?L:Pts),gl.STATIC_DRAW);
  bonePts=gl.createBuffer();gl.bindBuffer(gl.ARRAY_BUFFER,bonePts);gl.bufferData(gl.ARRAY_BUFFER,new Float32Array(Pts),gl.STATIC_DRAW);boneN=D.bones.length;boneLn=L.length/3;}
 document.getElementById('info').textContent=` — ${models.length} 网格, ${models.reduce((s,m)=>s+m.n/3,0).toLocaleString()} 面, ${boneN} 骨骼`;
}
function draw(){
 gl.clearColor(.078,.07,.062,1);gl.clear(gl.COLOR_BUFFER_BIT|gl.DEPTH_BUFFER_BIT);
 const pr=persp(.9,cv.width/cv.height,.005,Math.max(200,span*20));
 const eye=[ctr[0]+dist*Math.cos(rot[0])*Math.sin(rot[1]),ctr[1]+dist*Math.sin(rot[0]),ctr[2]+dist*Math.cos(rot[0])*Math.cos(rot[1])];
 const rt=[Math.cos(rot[1]),0,-Math.sin(rot[1])];
 eye[0]+=pan[0]*rt[0];eye[2]+=pan[0]*rt[2];eye[1]+=pan[1];
 const tg=[ctr[0]+pan[0]*rt[0],ctr[1]+pan[1],ctr[2]+pan[0]*rt[2]];
 let f=[tg[0]-eye[0],tg[1]-eye[1],tg[2]-eye[2]];const fl=Math.hypot(...f)||1;f=f.map(v=>v/fl);
 let r=[f[2],0,-f[0]];const rl=Math.hypot(...r);r=rl<1e-5?[1,0,0]:r.map(v=>v/rl);
 const u=[r[1]*f[2]-r[2]*f[1],r[2]*f[0]-r[0]*f[2],r[0]*f[1]-r[1]*f[0]];
 const vw=new Float32Array([r[0],u[0],-f[0],0,r[1],u[1],-f[1],0,r[2],u[2],-f[2],0,-(r[0]*eye[0]+r[1]*eye[1]+r[2]*eye[2]),-(u[0]*eye[0]+u[1]*eye[1]+u[2]*eye[2]),f[0]*eye[0]+f[1]*eye[1]+f[2]*eye[2],1]);
 const mvp=mul(pr,vw);
 gl.useProgram(P);
 const uM=gl.getUniformLocation(P,'mvp'),uV=gl.getUniformLocation(P,'mv'),uC=gl.getUniformLocation(P,'col'),
  uUT=gl.getUniformLocation(P,'useTex'),uTX=gl.getUniformLocation(P,'tex'),
  uUN=gl.getUniformLocation(P,'useNrm'),uNM=gl.getUniformLocation(P,'nrm'),
  uUS=gl.getUniformLocation(P,'useSpec'),uSP=gl.getUniformLocation(P,'spec'),
  uDG=gl.getUniformLocation(P,'dbgNrm');
 const aP=gl.getAttribLocation(P,'p'),aN=gl.getAttribLocation(P,'n'),aT=gl.getAttribLocation(P,'tan'),aUV=gl.getAttribLocation(P,'uv');
 gl.uniformMatrix4fv(uM,false,mvp);gl.uniformMatrix4fv(uV,false,vw);
 gl.uniform1i(uTX,0);gl.uniform1i(uNM,1);gl.uniform1i(uSP,2);if(uDG)gl.uniform1f(uDG,dbgNrm?1:0);
 for(const m of models){
  gl.bindBuffer(gl.ARRAY_BUFFER,m.pb);gl.enableVertexAttribArray(aP);gl.vertexAttribPointer(aP,3,gl.FLOAT,false,0,0);
  if(m.nb){gl.bindBuffer(gl.ARRAY_BUFFER,m.nb);gl.enableVertexAttribArray(aN);gl.vertexAttribPointer(aN,3,gl.FLOAT,false,0,0)}
  else gl.disableVertexAttribArray(aN),gl.vertexAttrib3f(aN,0,0,1);
  if(aT>=0){if(m.tb){gl.bindBuffer(gl.ARRAY_BUFFER,m.tb);gl.enableVertexAttribArray(aT);gl.vertexAttribPointer(aT,4,gl.FLOAT,false,0,0)}
   else gl.disableVertexAttribArray(aT),gl.vertexAttrib4f(aT,0,0,0,1);}
  gl.uniform3fv(uC,m.col);
  if(wire){gl.uniform1f(uUT,0);if(aUV>=0)gl.disableVertexAttribArray(aUV);
   gl.bindBuffer(gl.ELEMENT_ARRAY_BUFFER,m.wb);gl.drawElements(gl.LINES,m.n*2,gl.UNSIGNED_INT,0);continue}
  if(m.uvb&&aUV>=0){gl.bindBuffer(gl.ARRAY_BUFFER,m.uvb);gl.enableVertexAttribArray(aUV);gl.vertexAttribPointer(aUV,2,gl.FLOAT,false,0,0)}
  else if(aUV>=0){gl.disableVertexAttribArray(aUV);gl.vertexAttrib2f(aUV,0,0)}
  for(const P of m.parts){
   const t=P.tex&&P.tex.tex,tn=P.nre&&P.nre.tex,ts=P.spe&&P.spe.tex;
   if(t&&texOn){gl.activeTexture(gl.TEXTURE0);gl.bindTexture(gl.TEXTURE_2D,t);gl.uniform1f(uUT,1)}
   else gl.uniform1f(uUT,0);
   if(tn&&(nrmOn||dbgNrm)){gl.activeTexture(gl.TEXTURE1);gl.bindTexture(gl.TEXTURE_2D,tn);gl.uniform1f(uUN,nrmOn?1:0)}
   else gl.uniform1f(uUN,0);
   if(ts&&specOn){gl.activeTexture(gl.TEXTURE2);gl.bindTexture(gl.TEXTURE_2D,ts);gl.uniform1f(uUS,1)}
   else gl.uniform1f(uUS,0);
   gl.bindBuffer(gl.ELEMENT_ARRAY_BUFFER,P.ib);
   gl.drawElements(gl.TRIANGLES,P.n,gl.UNSIGNED_INT,0);}}
 if(showBones&&boneN){gl.disable(gl.DEPTH_TEST);gl.useProgram(LP);
  const lm=gl.getUniformLocation(LP,'mvp'),la=gl.getAttribLocation(LP,'p');gl.uniformMatrix4fv(lm,false,mvp);
  if(bonePts){gl.bindBuffer(gl.ARRAY_BUFFER,bonePts);gl.enableVertexAttribArray(la);gl.vertexAttribPointer(la,3,gl.FLOAT,false,0,0);gl.drawArrays(gl.POINTS,0,boneN);}
  if(boneBuf&&boneLn){gl.bindBuffer(gl.ARRAY_BUFFER,boneBuf);gl.enableVertexAttribArray(la);gl.vertexAttribPointer(la,3,gl.FLOAT,false,0,0);gl.drawArrays(gl.LINES,0,boneLn);}
  gl.enable(gl.DEPTH_TEST);}
 if(wantShot){wantShot=false;try{const a=document.createElement('a');
 a.href=cv.toDataURL('image/png');a.download=(curPath?curPath.replace(/[\\\/]/g,'_'):'shot')+'.png';a.click()}catch(e){}}
 requestAnimationFrame(draw);
}
let wantShot=false,curPath='';
if(gl)draw();
var _bs=document.getElementById('bshot');if(_bs)_bs.onclick=()=>{wantShot=true;};
// ── 目录树/搜索/加载 ──
const tree=document.getElementById('tree'),msg=document.getElementById('msg');
const PREV=/\.(chr|skin|skinm|cgf|cgfm|cga|cdf)$/i,AUD=/\.wem$/i,BNK=/\.bnk$/i,MTLV=/\.mtl$/i,DDV=/\.dds$/i;
function el(t,c,h){const d=document.createElement(t);if(c)d.className=c;d.innerHTML=h;return d}
async function jget(u){const r=await fetch(u);if(!r.ok)throw new Error(await r.text());return r.json()}
function mergeModel(path){return jget('/api/model?path='+encodeURIComponent(path))}
function icon(p){return PREV.test(p)?'🧊 ':AUD.test(p)?'🎵 ':BNK.test(p)?'📀 ':DDV.test(p)?'🖼️ ':MTLV.test(p)?'🎨 ':'📦 '}
function texCanvas(ab){const dv=new DataView(ab),w=dv.getUint32(0,true),h=dv.getUint32(4,true);
 const ca=document.createElement('canvas');ca.width=w;ca.height=h;
 const ctx=ca.getContext('2d');const im=ctx.createImageData(w,h);
 im.data.set(new Uint8ClampedArray(ab,8));ctx.putImageData(im,0,0);return ca}
function tvShow(title){document.getElementById('tvtitle').textContent=title;
 document.getElementById('tvbody').innerHTML='';document.getElementById('texview').style.display='';}
async function showMtl(path){tvShow('🎨 '+path.split('/').pop());
 const D=await jget('/api/mtlinfo?path='+encodeURIComponent(path));
 for(const s of D.subs){const card=el('div','',`<div style="color:#ffe9a8;font-size:12px;margin-bottom:4px">${s.name}</div>`);
  for(const k of ['diffuse','bump','spec']){if(!s[k])continue;
   const row=el('div','',`<small style="opacity:.6">${k}: ${s[k].split('/').pop()}</small><br>`);
   card.appendChild(row);
   fetch('/api/tex?path='+encodeURIComponent(s[k])).then(r=>{if(!r.ok)throw 0;return r.arrayBuffer()})
    .then(ab=>{const c=texCanvas(ab);c.style.cssText='max-width:190px;max-height:190px;image-rendering:pixelated;border:1px solid #333';card.appendChild(c)})
    .catch(()=>{card.appendChild(el('div','','<small style="color:#854">(贴图缺分片/解码失败)</small>'))});}
  document.getElementById('tvbody').appendChild(card);}}
async function showDds(path){tvShow('🖼️ '+path.split('/').pop());
 try{const r=await fetch('/api/tex?path='+encodeURIComponent(path));if(!r.ok)throw new Error(await r.text());
  const ca=texCanvas(await r.arrayBuffer());ca.style.cssText='max-width:100%;image-rendering:pixelated';
  document.getElementById('tvbody').appendChild(ca);}catch(e){document.getElementById('tvbody').innerHTML='<small style="color:#a66">'+e+'</small>'}}
addEventListener('keydown',e=>{
 if(e.target.tagName==='INPUT'||e.target.tagName==='SELECT')return;
 if(e.code==='Space'&&player.style.display!=='none'){e.preventDefault();ap.paused?ap.play():ap.pause();return}
 if(e.key==='Escape')document.getElementById('texview').style.display='none';
 if((e.key==='ArrowDown'||e.key==='ArrowUp')&&sibFiles.length){
  e.preventDefault();
  const d=e.key==='ArrowDown'?1:-1;
  sibIdx=(sibIdx+d+sibFiles.length)%sibFiles.length;
  const dir=document.getElementById('cur').textContent.split('/').slice(0,-1).join('/');
  openPath((dir?dir+'/':'')+sibFiles[sibIdx]);
 }});
let showAux=false;
const AUX=/(_lod\d+\.skin$|_lod\d+\.cgf$|\.skinm$|\.cgfm$|_fp\.skin$|_fp_|_fix\.skin$|_sim\.skin$|_dsmb|_dsm_|_dmg\.skin$|_shadow|\.v\d+\.mtl$|_ddna|_spec\.dds|_mask)/i;
function fileRow(f){
 if(!showAux&&AUX.test(f.path))return el('span','','');
 const row=el('div','file',icon(f.path)+f.name);
 row.title=f.path;
 row.onclick=e=>{e.stopPropagation();
 if(!e.shiftKey)document.querySelectorAll('.file.sel').forEach(x=>x.classList.remove('sel'));
 row.classList.add('sel');openPath(f.path,e.shiftKey)};
 return row}
const player=document.getElementById('player'),ap=document.getElementById('ap');
let sibFiles=[],sibIdx=-1;
async function openPath(path, append){
 curPath=path;document.getElementById('cur').textContent=path;
 if(!append){
  const dir=path.split('/').slice(0,-1).join('/');
  try{const L=await jget('/api/ls?dir='+encodeURIComponent(dir));
   sibFiles=L.files.filter(f=>PREV.test(f.path)).map(f=>f.name);
   sibIdx=sibFiles.indexOf(path.split('/').pop());}catch(e){sibFiles=[];sibIdx=-1}
 }
 msg.style.display='none';player.style.display='none';
 document.getElementById('bdl').style.display='';
 document.getElementById('bdl').onclick=()=>location.href='/api/raw?path='+encodeURIComponent(path);
 document.getElementById('bglb').style.display='';
 document.getElementById('bglb').onclick=()=>{msg.style.display='';msg.textContent='glTF 打包中(几何+骨骼+贴图)…';
  location.href='/api/glb?path='+encodeURIComponent(path);setTimeout(()=>{msg.style.display='none'},3000)};
 if(MTLV.test(path)){try{await showMtl(path)}catch(e){msg.style.display='';msg.textContent='材质读取失败: '+e}return}
 if(DDV.test(path)){showDds(path);return}
 if(AUD.test(path)){
  player.style.display='';
  document.getElementById('pname').textContent=path.split('/').pop()+'  转码中…';
  msg.style.display='';msg.textContent='音频转码中…';
  fetch('/api/audio?path='+encodeURIComponent(path)).then(async r=>{
   if(!r.ok){const t=await r.text();throw new Error(t.slice(0,240));}
   return r.blob();}).then(b=>{
   const u=URL.createObjectURL(b);ap.src=u;ap.play().catch(()=>{});
   document.getElementById('pname').textContent=path.split('/').pop();
   msg.style.display='none';
  }).catch(e=>{msg.style.display='';msg.style.pointerEvents='auto';
   msg.textContent='音频失败: '+e;document.getElementById('pname').textContent=path.split('/').pop()+' ✗';});
  return;
 }
 if(/\.dba$/i.test(path)){
  msg.style.display='';msg.textContent='扫描动画库…';
  try{const D=await jget('/api/dba?path='+encodeURIComponent(path));
   const pane=document.getElementById('anim'),box=document.getElementById('anims');
   pane.style.display='';
   box.innerHTML=`<small>${path}</small><h2>库内片段(${D.names.length})</h2>`
    +(D.names.length?D.names.map(n=>`<div class="a" data-p="${n}" title="${n}">🎬 ${n.split('/').pop()}</div>`).join(''):'<div class="a">(没扫到片段名, 关键帧解码还没做)</div>');
   box.onclick=e=>{const a=e.target.closest('.a');if(!a||!a.dataset.p)return;
    const s=document.getElementById('search');s.value=a.dataset.p.split('/').pop();s.dispatchEvent(new Event('input'));};
   msg.style.display='';msg.innerHTML='📼 <b>.dba 是动画打包库</b><br>右侧是扫到的片段名(点一下可搜索)<br><small>关键帧播放下一刀再做, 现在先能点名/听音</small>';
  }catch(e){msg.textContent='dba 读取失败: '+e}
  return;}
 if(BNK.test(path)){msg.style.display='';msg.innerHTML='📀 .bnk 是 Wwise 容器(内部可含多个 wem)<br>点左边搜 .wem 可直接听; 容器解包还没做';return}
 if(PREV.test(path)){
  msg.style.display='';msg.textContent='解析中…';
  try{const D=(append?await mergeModel(path):await jget('/api/model?path='+encodeURIComponent(path)));
   loadModel(D,append);msg.style.display=D.models.length?'none':'';
   if(!D.models.length)msg.innerHTML='⚫ <b>这个文件没有可显示的几何</b>(纯骨骼/描述/空壳)<br>'+(D.bones&&D.bones.length?'骨架已画出, 共 '+D.bones.length+' 根<br>':'')+'<small>'+(D.errors||[]).join('<br>')+'</small>';
  }catch(e){msg.textContent='解析失败: '+e}
 }
 try{const A=await jget('/api/anims?path='+encodeURIComponent(path));
  const pane=document.getElementById('anim'),box=document.getElementById('anims');
  if(A.found&&(A.anims.length||A.files.length||(A.clips&&A.clips.length))){pane.style.display='';
   box.innerHTML=`<small>骨架: ${A.chr||''}</small>`
    +(A.clips&&A.clips.length?`<h2>动作清单(${A.clips.length})</h2>`+A.clips.map(c=>{const nm=c.split('/').pop().replace(/\.(bspace|comb|caf)$/,'');return `<div class="a" data-p="${c}" title="${c}">🎬 ${nm}</div>`}).join(''):'')
    +(A.anims.length?'<h2>命名动画</h2>'+A.anims.map(a=>`<div class="a" data-p="${a.dba||a.name}" title="${a.dba||''}">▸ ${a.name}</div>`).join(''):'')
    +(A.files&&A.files.length?'<h2>动画库文件</h2>'+A.files.map(f=>`<div class="a" data-p="${f.path}" title="${f.path}">📼 ${f.path.split('/').pop()} <small>${(f.size/1024).toFixed(0)}KB</small></div>`).join(''):'');
   box.onclick=e=>{const a=e.target.closest('.a');if(!a)return;const p=a.dataset.p||'';
    if(/\.(dba|caf|wem)$/i.test(p))openPath(p);
    else {const s=document.getElementById('search');s.value=(p.split('/').pop()||p).replace(/\.(bspace|comb|caf)$/,'');s.dispatchEvent(new Event('input'));}};
  }else pane.style.display='none';}catch(e){}
}
function makeDir(path,name){
 const d=el('div','dir','<label>'+name+'</label>');const kids=el('div','kids');d.appendChild(kids);
 let loaded=false;
 d.querySelector('label').onclick=async()=>{
  d.classList.toggle('open');
  if(!loaded){loaded=true;kids.innerHTML='<div class="file">加载中…</div>';
   try{const L=await jget('/api/ls?dir='+encodeURIComponent(path));kids.innerHTML='';
   for(const sub of L.dirs)kids.appendChild(makeDir(path?path+'/'+sub:sub,sub));
   for(const f of L.files)kids.appendChild(fileRow(f));}catch(e){kids.innerHTML='<div class="file">加载失败: '+e+'</div>'}}};
 return d}
async function fillTree(){
 try{const L=await jget('/api/ls?dir=');tree.innerHTML='';
  for(const d of L.dirs)tree.appendChild(makeDir(d,d));
  for(const f of L.files)tree.appendChild(fileRow(f));
  if(!L.dirs.length&&!L.files.length){msg.style.display='';msg.textContent='索引根目录是空的';}
 }catch(e){msg.style.display='';msg.style.pointerEvents='auto';msg.textContent='目录树加载失败: '+e}}
fillTree();
let stimer=null;
document.getElementById('search').oninput=e=>{
 clearTimeout(stimer);const q=e.target.value.trim();
 if(q.length<2)return;
 stimer=setTimeout(async()=>{
  const H=await jget('/api/search?q='+encodeURIComponent(q));
  tree.innerHTML='';
  if(!H.length){tree.appendChild(el('div','file','(无结果)'))}
  for(const h of H){
   const name=h.path.split('/').pop();const row=el('div','file',icon(h.path)+`<b>${name}</b><br><small style="opacity:.5">${h.path}</small>`);
   row.style.whiteSpace='normal';row.onclick=()=>{document.querySelectorAll('.file.sel').forEach(x=>x.classList.remove('sel'));row.classList.add('sel');openPath(h.path)};tree.appendChild(row)}
  tree.dataset.search='1';
 },350);};
document.getElementById('search').addEventListener('keydown',e=>{if(e.key==='Escape'){e.target.value='';fillTree()}});
document.getElementById('bwire').onclick=e=>{wire=e.target.classList.toggle('on')};
document.getElementById('bbone').onclick=e=>{showBones=e.target.classList.toggle('on')};
document.getElementById('btex').onclick=e=>{texOn=e.target.classList.toggle('on')};
document.getElementById('bnrm').onclick=e=>{nrmOn=e.target.classList.toggle('on')};
document.getElementById('bspec').onclick=e=>{specOn=e.target.classList.toggle('on')};
document.getElementById('bdbg').onclick=e=>{dbgNrm=e.target.classList.toggle('on')};
document.getElementById('breset').onclick=()=>{rot=[.6,.8];dist=span*1.8;pan=[0,0,0]};
// ── 快捷入口 ──
document.getElementById('qaux').onclick=e=>{showAux=e.target.classList.toggle('on');fillTree()};
document.getElementById('qaud').onclick=()=>{const s=document.getElementById('search');s.value='.wem';s.dispatchEvent(new Event('input'));};
async function openDir(path){
 let dir=tree;const segs=path.split('/');
 for(let i=0;i<segs.length;i++){
  let target=null;
  for(const d of dir.children){const lab=d.querySelector&&d.querySelector('label');if(lab&&lab.textContent===segs[i]){target=d;break}}
  if(!target)return;const kids=target.querySelector('.kids');
  if(!target.classList.contains('open'))target.querySelector('label').onclick();
  await new Promise(r=>setTimeout(r,300));dir=kids;}
 if(dir)dir.scrollIntoView({block:'center'})}
document.getElementById('qweap').onclick=()=>openDir('characters/weapons');
document.getElementById('qmob').onclick=()=>openDir('characters');
document.getElementById('qprop').onclick=()=>openDir('objects');
document.getElementById('qshelf').onclick=()=>{
 const cur=document.getElementById('cur').textContent;
 const dir=(cur&&cur.includes('/'))?cur.split('/').slice(0,-1).join('/'):'characters';
 document.getElementById('shelfdir').value=dir;fillShelf(dir);};
let outfitG='male';
async function outfit(g){
 if(g)outfitG=g;
 const n=document.getElementById('qset').value;
 document.getElementById('cur').textContent=outfitG+' 猎人 · 套装'+n;msg.style.display='';msg.textContent='拼装中…';
 try{const D=await jget('/api/outfit?g='+outfitG+'&n='+n);
  loadModel(D,false);msg.style.display=D.models.length?'none':'';
  if(!D.models.length)msg.textContent='这套编号没装出来(可能不存在), 换 001 试试';
 }catch(e){msg.textContent='拼装失败: '+e}}

// ═══ 物品栏: 45° 定妆缩略图墙 ═══
const thumbCache={},SHELF_W=176;
let shGl=null,shProg=null,shCv=null;
function shelfCtx(){
 if(shGl)return shGl;
 shCv=document.createElement('canvas');shCv.width=192;shCv.height=192;
 shGl=shCv.getContext('webgl',{antialias:true,preserveDrawingBuffer:true});
 shGl.getExtension('OES_element_index_uint');shGl.getExtension('OES_standard_derivatives');
 const P=(()=>{const P=shGl.createProgram();
  for(const[t,s]of[[shGl.VERTEX_SHADER,VS],[shGl.FRAGMENT_SHADER,FS]]){const sh=shGl.createShader(t);shGl.shaderSource(sh,s);shGl.compileShader(sh);shGl.attachShader(P,sh);}
  shGl.linkProgram(P);return P;})();
 shProg=P;shGl.enable(shGl.DEPTH_TEST);
 return shGl;}
async function renderThumb(D,g){
 // 上传几何
 const gV=[],gI=[],subs=[];
 let mn=[1e9,1e9,1e9],mx=[-1e9,-1e9,-1e9];
 for(const M of D.models){if(!M.pos.length)continue;
  const base=gV.length/3,pos=M.pos,t=M.transform;
  for(let i=0;i<pos.length;i+=3){const x=pos[i],y=pos[i+1],z=pos[i+2];
   const X=t[0]*x+t[4]*y+t[8]*z+t[12],Y=t[1]*x+t[5]*y+t[9]*z+t[13],Z=t[2]*x+t[6]*y+t[10]*z+t[14];
   gV.push(X,Y,Z);
   if(X<mn[0])mn[0]=X;if(X>mx[0])mx[0]=X;if(Y<mn[1])mn[1]=Y;if(Y>mx[1])mx[1]=Y;if(Z<mn[2])mn[2]=Z;if(Z>mx[2])mx[2]=Z;}
  const idx=M.idx,mi=gI.length;
  for(const i of idx)gI.push(base+i);
  for(const pr of M.parts||[{first:0,count:idx.length,mat:-1}])subs.push({s:mi+pr.first,c:pr.count,mi:pr.mat});}
 if(!gV.length)return null;
 const ctr=[(mn[0]+mx[0])/2,(mn[1]+mx[1])/2,(mn[2]+mx[2])/2];
 const span=Math.max(.05,...mx.map((v,i)=>v-mn[i]));
 // 上传
 const pb=g.createBuffer();g.bindBuffer(g.ARRAY_BUFFER,pb);g.bufferData(g.ARRAY_BUFFER,new Float32Array(gV),g.STATIC_DRAW);
 const ib=g.createBuffer();g.bindBuffer(g.ELEMENT_ARRAY_BUFFER,ib);g.bufferData(g.ELEMENT_ARRAY_BUFFER,new Uint32Array(gI),g.STATIC_DRAW);
 // 贴图预备: 每 sub 先取 raw
 const prTex=await Promise.all(subs.map(async s=>{
  const M=D.materials&&s.mi>=0?D.materials[s.mi]:null;
  if(!M||!M.diffuse)return null;
  try{return uploadTex(g,await fetchRaw('/api/tex?path='+encodeURIComponent(M.diffuse)))}catch(e){return null}}));
 // 相机 45° 斜上
 const dist=span*1.65,rx=.72,ry=.8;
 const eye=[ctr[0]+dist*Math.cos(rx)*Math.sin(ry),ctr[1]+dist*Math.sin(rx),ctr[2]+dist*Math.cos(rx)*Math.cos(ry)];
 const pr=persp(.85,1,.005,Math.max(100,span*10));
 let f=[ctr[0]-eye[0],ctr[1]-eye[1],ctr[2]-eye[2]];const fl=Math.hypot(...f)||1;f=f.map(v=>v/fl);
 let r=[f[2],0,-f[0]];const rl=Math.hypot(...r);r=rl<1e-5?[1,0,0]:r.map(v=>v/rl);
 const u=[r[1]*f[2]-r[2]*f[1],r[2]*f[0]-r[0]*f[2],r[0]*f[1]-r[1]*f[0]];
 const vw=new Float32Array([r[0],u[0],-f[0],0,r[1],u[1],-f[1],0,r[2],u[2],-f[2],0,-(r[0]*eye[0]+r[1]*eye[1]+r[2]*eye[2]),-(u[0]*eye[0]+u[1]*eye[1]+u[2]*eye[2]),f[0]*eye[0]+f[1]*eye[1]+f[2]*eye[2],1]);
 const mvp=mul(pr,vw);
 g.clearColor(.10,.095,.083,1);g.clear(g.COLOR_BUFFER_BIT|g.DEPTH_BUFFER_BIT);
 g.useProgram(shProg);
 const uM=g.getUniformLocation(shProg,'mvp'),uV=g.getUniformLocation(shProg,'mv'),uC=g.getUniformLocation(shProg,'col'),
  uUT=g.getUniformLocation(shProg,'useTex'),uTX=g.getUniformLocation(shProg,'tex'),
  uUN=g.getUniformLocation(shProg,'useNrm'),uUS=g.getUniformLocation(shProg,'useSpec');
 const aP=g.getAttribLocation(shProg,'p'),aN=g.getAttribLocation(shProg,'n'),aUV=g.getAttribLocation(shProg,'uv');
 g.uniformMatrix4fv(uM,false,mvp);g.uniformMatrix4fv(uV,false,vw);
 g.disableVertexAttribArray(aN);g.vertexAttrib3f(aN,0,0,1);
 g.disableVertexAttribArray(aUV);g.vertexAttrib2f(aUV,0,0);
 g.uniform1f(uUN,0);g.uniform1f(uUS,0);
 g.bindBuffer(g.ARRAY_BUFFER,pb);g.enableVertexAttribArray(aP);g.vertexAttribPointer(aP,3,g.FLOAT,false,0,0);
 g.uniform3fv(uC,[.62,.58,.5]);
 for(let i=0;i<subs.length;i++){const s=subs[i],t=prTex[i];
  if(t){g.activeTexture(g.TEXTURE0);g.bindTexture(g.TEXTURE_2D,t);g.uniform1f(uUT,1)}
  else g.uniform1f(uUT,0);
  g.drawElements(g.TRIANGLES,s.c,g.UNSIGNED_INT,s.s*4);}
 // 读回
 const out=document.createElement('canvas');out.width=192;out.height=192;
 out.getContext('2d').drawImage(shCv,0,0);
 g.deleteBuffer(pb);g.deleteBuffer(ib);
 return out.toDataURL();}

async function collectItems(dir){
 const L=await jget('/api/ls?dir='+encodeURIComponent(dir));
 let own=L.files.filter(f=>PREV.test(f.path)&&!AUX.test(f.path));
 if(own.length)return own.slice(0,60);
 const res=[];
 for(const d of L.dirs.slice(0,30)){
  try{const S=await jget('/api/ls?dir='+encodeURIComponent((dir?dir+'/':'')+d));
   res.push(...S.files.filter(f=>PREV.test(f.path)&&!AUX.test(f.path)).slice(0,5));}catch(e){}}
 return res.slice(0,60);}

let shelfQ=false;
async function fillShelf(dir){
 document.getElementById('shelf').style.display='flex';
 const grid=document.getElementById('shelfgrid');
 grid.innerHTML='<div style="color:#8a7c5c;padding:20px">清点货物…</div>';
 let items;try{items=await collectItems(dir)}catch(e){grid.innerHTML='该目录拿不到: '+e;return}
 document.getElementById('shelfinfo').textContent=`${items.length} 件`;
 grid.innerHTML='';
 if(!items.length){grid.innerHTML='<div style="color:#8a7c5c;padding:20px">这目录和下一层都没有可预览文件, 换个目录</div>';return}
 const cards=[];
 for(const f of items){
  const c=el('div','card',`<div class="wait">⏳</div><div class="nm">${f.path.split('/').pop()}</div><small style="opacity:.5">${f.path.split('/').slice(0,-1).pop()}</small>`);
  c.title=f.path;c.onclick=()=>{document.getElementById('shelf').style.display='none';openPath(f.path)};
  grid.appendChild(c);cards.push([c,f]);}
 if(shelfQ)return;shelfQ=true;
 shelfCtx();
 const run=async()=>{
  while(cards.length){
   const [c,f]=cards.shift();
   if(f.path in thumbCache){c.querySelector('.wait').outerHTML=`<img src="${thumbCache[f.path]}">`;continue}
   try{const D=await jget('/api/model?path='+encodeURIComponent(f.path));
    if(D.models&&D.models.length){
     const url=await renderThumb(D,shGl);
     if(url){thumbCache[f.path]=url;c.querySelector('.wait').outerHTML=`<img src="${url}">`}
     else c.querySelector('.wait').textContent='—';}
    else c.querySelector('.wait').textContent='(空)';}
   catch(e){c.querySelector('.wait').textContent='✗';}
  }
  shelfQ=false;};
 run();}
document.getElementById('bshelfgo').onclick=()=>fillShelf(document.getElementById('shelfdir').value.trim());
document.getElementById('qmale').onclick=()=>outfit('male');
document.getElementById('qfemale').onclick=()=>outfit('female');
document.getElementById('qset').onchange=()=>outfit();
(async()=>{try{const L=await jget('/api/outfit?g=male&n=list');
 const sel=document.getElementById('qset');sel.innerHTML='';
 for(const n of L.numbers)sel.innerHTML+=`<option>${n}</option>`;}catch(e){}})();
</script></body></html>"""


# ════════════════════════ HTTP 服务 ════════════════════════

def dba_names(idx, path, limit=400):
    """从 dba/adb 里扫 ASCII 片段名(不做关键帧解码)."""
    try:
        data = idx.read(path)
    except Exception:
        return []
    out, i, n = [], 0, len(data)
    while i < n:
        if 45 <= data[i] < 127:      # '-' ../A
            j = i
            while j < n and 45 <= data[j] < 127:
                j += 1
            if j - i >= 8:
                s = data[i:j].decode('ascii', 'ignore').replace('\\', '/')
                sl = s.lower()
                if sl.endswith(('.caf', '.bspace', '.comb', '.anm')) or '/animations/' in sl:
                    out.append(s)
            i = j
        else:
            i += 1
    seen, uniq = set(), []
    for s in out:
        k = s.lower()
        if k not in seen:
            seen.add(k); uniq.append(s)
            if len(uniq) >= limit:
                break
    return uniq


IDX = None


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def _send(self, body, ctype='text/html; charset=utf-8', status=200,
              extra=None):
        if isinstance(body, str):
            body = body.encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(body)))
        if extra:
            for k, v in extra.items():
                self.send_header(k, v)
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_GET(self):
        u = urllib.parse.urlsplit(self.path)
        q = urllib.parse.parse_qs(u.query)
        path = q.get('path', [''])[0]
        try:
            if u.path == '/':
                return self._send(SPA, extra={'Cache-Control': 'no-cache'})
            if u.path in ('/api/ls', '/api/dir'):
                return self._json(IDX.ls(q.get('dir', q.get('path', ['']))[0]))
            if u.path == '/api/search':
                return self._json(IDX.search(q.get('q', [''])[0]))
            if u.path == '/api/model':
                return self._json(model_payload(IDX, path))
            if u.path == '/api/glb':
                import huntglb
                if path.lower().endswith('.cdf'):
                    assm = parse_cdf_attach(IDX, path)
                else:
                    assm = {'chr': None, 'mtl': None, 'skins': [
                        {'name': os.path.basename(path), 'path': path.lower(),
                         'mtl': None, 'bone': '', 'rot': [1, 0, 0, 0],
                         'pos': [0, 0, 0]}]}
                glb, glog = huntglb.export_glb(IDX, path, assm, tex_rgba)
                for line in glog:
                    print('  [glb]', line, file=sys.stderr)
                name = urllib.parse.quote(
                    os.path.splitext(os.path.basename(path))[0] + '.glb')
                return self._send(glb, 'model/gltf-binary', 200,
                                  {'Content-Disposition':
                                   f"attachment; filename*=UTF-8''{name}"})
            if u.path == '/api/mtlinfo':
                subs = parse_mtl(IDX, path) or []
                return self._json({'path': path, 'subs': subs})
            if u.path == '/api/outfit':
                return self._json(outfit_payload(
                    IDX, q.get('g', ['male'])[0], q.get('n', ['001'])[0]))
            if u.path == '/api/anims':
                return self._json(anims_payload(IDX, path))
            if u.path == '/api/tex':
                data = tex_rgba(IDX, path)
                return self._send(data, 'application/octet-stream', 200,
                                  {'Cache-Control': 'max-age=86400'})
            if u.path == '/api/audio':
                data = audio_convert(IDX, path)
                return self._send(data, 'audio/ogg', 200,
                                  {'Cache-Control': 'max-age=86400'})
            if u.path == '/api/raw':
                data = IDX.read(path)
                name = urllib.parse.quote(os.path.basename(path))
                return self._send(data, 'application/octet-stream', 200,
                                  {'Content-Disposition':
                                   f"attachment; filename*=UTF-8''{name}"})
            if u.path == '/api/dba':
                return self._json({'path': path, 'names': dba_names(IDX, path)})
            if u.path == '/api/stats':
                return self._json({'files': len(IDX.files),
                                   'paks': len(set(v[0] for v in IDX.files.values()))})
            return self._send('404', 'text/plain', 404)
        except FileNotFoundError:
            return self._send('文件不在索引里', 'text/plain; charset=utf-8', 404)
        except BrokenPipeError:
            pass
        except Exception as e:
            import traceback
            traceback.print_exc()
            return self._json({'error': str(e)}, 500)

    def _json(self, obj, status=200):
        self._send(json.dumps(obj, ensure_ascii=False, separators=(',', ':')),
                   'application/json; charset=utf-8', status)

    def log_message(self, fmt, *a):
        pass


def main():
    root = os.environ.get('HUNT_BASE')
    port = 8796
    args = sys.argv[1:]
    if root is None:
        if args:
            root = args.pop(0)
        else:
            cands = [
                os.path.expanduser('~/.var/app/com.valvesoftware.Steam/.local/'
                                   'share/Steam/steamapps/common/'
                                   'Hunt Showdown 1896'),
                os.path.expanduser('~/.steam/steam/steamapps/common/'
                                   'Hunt Showdown 1896'),
                os.path.expanduser('~/.local/share/Steam/steamapps/common/'
                                   'Hunt Showdown 1896'),
            ]
            root = next((c for c in cands if os.path.isdir(c)), None)
            if not root:
                sys.exit('找不到游戏目录, 请手动: python3 huntview.py "/游戏目录"')
    if args:
        port = int(args[0])
    print(f'游戏资源根: {root}')
    global IDX
    t0 = time.time()
    IDX = AssetIndex(root, log=lambda m: print(f'  [{time.time()-t0:5.1f}s] {m}'))
    bind = os.environ.get('HUNT_BIND', '127.0.0.1')
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    srv = socketserver.ThreadingTCPServer((bind, port), Handler)
    srv.daemon_threads = True
    print(f'\n✅ 就绪 — 浏览器打开:  http://127.0.0.1:{port}\n'
          f'   (Ctrl+C 停止; 只读模式, 不会碰游戏文件)')
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()
