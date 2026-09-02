#!/usr/bin/env python3
"""huntglb.py — CryEngine 资产品牌件 → glTF 2.0 Binary (.glb) 封装器
静态件原样带 local transform; 蒙皮件带 JOINTS_0/WEIGHTS_0 + skins。
贴图(diffuse/bump)RGBA → 内置 PNG。轴系: 根节点 ×X-90° (Z-up→Y-up)。"""
import json
import os
import struct
import zlib

import huntcgf


def png_rgba(w, h, rgba: bytes) -> bytes:
    raw = b''.join(b'\x00' + rgba[y * w * 4:(y + 1) * w * 4] for y in range(h))

    def chunk(t, d):
        return (struct.pack('>I', len(d)) + t + d
                + struct.pack('>I', zlib.crc32(t + d) & 0xffffffff))
    return (b'\x89PNG\r\n\x1a\n'
            + chunk(b'IHDR', struct.pack('>IIBBBBB', w, h, 8, 6, 0, 0, 0))
            + chunk(b'IDAT', zlib.compress(raw, 6))
            + chunk(b'IEND', b''))


def _m34_to_m4v(m12):          # 3x4 行优先 → 4x4 列优先
    return [m12[0], m12[4], m12[8], 0, m12[1], m12[5], m12[9], 0,
            m12[2], m12[6], m12[10], 0, m12[3], m12[7], m12[11], 1]


def _affine_inv_col16(m):      # 仿射 4x4(列主)逆: R⁻¹=Rᵀ, t'=-Rᵀt
    r = [[m[c * 4 + rr] for c in range(3)] for rr in range(3)]
    t = [m[12], m[13], m[14]]
    rt = [[r[c][rr] for c in range(3)] for rr in range(3)]  # transpose
    ti = [-(rt[i][0] * t[0] + rt[i][1] * t[1] + rt[i][2] * t[2]) for i in range(3)]
    return [rt[0][0], rt[0][1], rt[0][2], 0,
            rt[1][0], rt[1][1], rt[1][2], 0,
            rt[2][0], rt[2][1], rt[2][2], 0,
            ti[0], ti[1], ti[2], 1]


def _mul_col16(a, b):
    return [sum(a[k * 4 + r] * b[c * 4 + k] for k in range(4))
            for c in range(4) for r in range(4)]


class GlbBuilder:
    def __init__(self):
        self.bin = bytearray()
        self.views = []
        self.accs = []
        self.meshes = []
        self.nodes = []
        self.mats = []
        self.texs = []
        self.imgs = []
        self.skins = []

    def _pad(self):
        while len(self.bin) % 4:
            self.bin.append(0)

    def push(self, data: bytes, target, ctype, cnt, type_, minmax=None,
             norm=False):
        self._pad()
        off = len(self.bin)
        self.bin += data
        self.views.append({'buffer': 0, 'byteOffset': off,
                           'byteLength': len(data), 'target': target})
        acc = {'bufferView': len(self.views) - 1, 'byteOffset': 0,
               'componentType': ctype, 'count': cnt, 'type': type_}
        if norm:
            acc['normalized'] = True
        if minmax:
            acc['min'], acc['max'] = minmax
        self.accs.append(acc)
        return len(self.accs) - 1

    def push_f32(self, vals, type_='SCALAR', minmax=None, target=34962):
        return self.push(struct.pack('<%df' % len(vals), *vals), target,
                         5126, len(vals) // {'VEC3': 3, 'VEC2': 2, 'VEC4': 4,
                                             'MAT4': 16, 'SCALAR': 1}[type_],
                         type_, minmax)

    def push_u32_idx(self, vals):
        return self.push(struct.pack('<%dI' % len(vals), *vals), 34963,
                         5125, len(vals), 'SCALAR')

    def push_u16(self, vals, type_='VEC4', norm=False, target=34962):
        return self.push(struct.pack('<%dH' % len(vals), *vals), target,
                         5123, len(vals) // 4, type_, norm=norm)

    def push_u8(self, vals, type_='VEC4', norm=False, target=34962):
        return self.push(bytes(vals), target, 5121,
                         len(vals) // 4 if type_ == 'VEC4' else len(vals),
                         type_, norm=norm)


def export_glb(idx, path, assm, texfun):
    """assm: {'chr','mtl','skins':[...]} 装配描述(或单件), texfun=贴图→RGBA 字节
    返回 (glb_bytes, log_lines)"""
    log = []
    B = GlbBuilder()

    # ── 1. 收集(复用装配决策) ──
    errors = []
    models = []
    bones = []

    def add_file(pth, subs=None, tag='', xform=None):
        try:
            parsed = huntcgf.parse_cgf(idx.read(pth))
        except Exception as e:
            errors.append(f'{pth}: {e}')
            return
        for m in parsed['meshes']:
            models.append({'name': tag or m['name'] or os.path.basename(pth),
                           'transform': m['transform'], 'parsed_mesh': m,
                           'subs': subs, 'xform': xform})
        if len(parsed['skeleton']) > len(bones):
            bones[:] = parsed['skeleton']

    if assm.get('chr') and assm['chr'] in idx.files:
        add_file(assm['chr'])
    import huntview as hv  # 用它的材质/变换工具
    bone_xf = {b['name']: hv._b2w_to_col16(b['b2w']) for b in bones}
    for sk in assm.get('skins', []):
        subs = None
        mtl_p = hv.guess_mtl(idx, sk['path'])
        if mtl_p:
            subs = hv.parse_mtl(idx, mtl_p)
        xf = None
        if sk.get('bone') and sk['bone'] in bone_xf:
            xf = _mul_col16(bone_xf[sk['bone']],
                            hv._qpos_to_col16(sk.get('rot', [1, 0, 0, 0]),
                                              sk.get('pos', [0, 0, 0])))
        add_file(sk['path'], subs, sk['name'], xf)
        for mate in (sk['path'][:-4] + 'm', sk['path'] + 'm'):
            if mate in idx.files and mate != sk['path']:
                add_file(mate, subs, sk['name'], xf)
                break

    if not models:
        raise RuntimeError('无可导出几何. errors=' + '; '.join(errors[:3]))

    # ── 2. 根节点(Z-up→Y-up) + 骨骼节点树 ──
    root = 0
    B.nodes.append({'name': 'hunt_root',
                    'matrix': [1, 0, 0, 0, 0, 0, -1, 0, 0, 1, 0, 0,
                               0, 0, 0, 1]})
    joint_node = []
    if bones:
        w4 = [_m34_to_m4v(b['b2w']) for b in bones]
        for i, b in enumerate(bones):
            if b['offsetParent'] > 0:
                p = i - b['offsetParent']
                local = _mul_col16(_affine_inv_col16(w4[p]), w4[i])
            else:
                local = w4[i]
            B.nodes.append({'name': b['name'] or f'bone_{i}', 'matrix': local})
            joint_node.append(len(B.nodes) - 1)
        # parent 链
        for i, b in enumerate(bones):
            if b['offsetParent'] > 0:
                p = i - b['offsetParent']
                pn = joint_node[p]
                B.nodes[pn].setdefault('children', []).append(joint_node[i])
        B.nodes[root].setdefault('children', []).append(joint_node[0])
        # inverse bind matrices
        ibm = []
        for b in bones:
            ibm += _m34_to_m4v(b['w2b'])
        ibm_acc = B.push_f32(ibm, 'MAT4')
        B.skins.append({'joints': joint_node, 'inverseBindMatrices': ibm_acc,
                        'skeleton': joint_node[0]})

    # ── 3. 材质/贴图 ──
    mat_index = {}

    def mat_for(subs, matId):
        if not subs:
            return None
        k = matId if 0 <= matId < len(subs) else 0
        s = subs[k]
        key = s['name']
        import json as _j
        key = _j.dumps(s, sort_keys=True)
        if key in mat_index:
            return mat_index[key]
        mat = {'name': s['name'], 'pbrMetallicRoughness': {
            'metallicFactor': 0.0, 'roughnessFactor': 0.85}}
        for gname, skey in (('baseColorTexture', 'diffuse'),
                            ('normalTexture', 'bump')):
            dds = s.get(skey)
            if not dds:
                continue
            try:
                raw = texfun(idx, dds)
                w, h = struct.unpack_from('<2I', raw, 0)
                png = png_rgba(w, h, raw[8:])
                B._pad()
                off = len(B.bin)
                B.bin += png
                B.views.append({'buffer': 0, 'byteOffset': off,
                                'byteLength': len(png)})
                B.imgs.append({'mimeType': 'image/png',
                               'bufferView': len(B.views) - 1,
                               'name': os.path.basename(dds)})
                B.texs.append({'source': len(B.imgs) - 1, 'sampler': 0})
                if gname == 'baseColorTexture':
                    mat['pbrMetallicRoughness'][gname] = {
                        'index': len(B.texs) - 1}
                else:
                    mat[gname] = {'index': len(B.texs) - 1}
            except Exception as e:
                errors.append(f'贴图 {dds}: {e}')
        B.mats.append(mat)
        mat_index[key] = len(B.mats) - 1
        return mat_index[key]

    # ── 4. 网格 → primitives ──
    mesh_nodes = []
    for mi, md in enumerate(models):
        m = md['parsed_mesh']
        tot_idx = [i for tri in m['indices'] for i in tri]
        pos_flat = [c for v in m['positions'] for c in v]
        nrm_flat = [c for v in m['normals'] for c in v]
        uv_flat = [u for v in m['uvs'] for u in (v[0], 1.0 - v[1])]  # v 翻转
        pmin = [min(pos_flat[i::3]) for i in range(3)] if pos_flat else [0] * 3
        pmax = [max(pos_flat[i::3]) for i in range(3)] if pos_flat else [0] * 3
        a_pos = B.push_f32(pos_flat, 'VEC3', [pmin, pmax])
        a_nrm = B.push_f32(nrm_flat, 'VEC3') if len(nrm_flat) == len(pos_flat) else None
        a_uv = B.push_f32(uv_flat, 'VEC2') if len(uv_flat) == len(pos_flat) // 3 * 2 else None
        # 蒙皮
        skinned = bool(m['boneWeights']) and bool(B.skins)
        a_joint = a_wgt = None
        if skinned:
            jids, wgts = [], []
            for ids, ws in m['boneWeights']:
                ws = [w / 255.0 for w in ws] if max(ws) <= 255 else list(ws)
                s = sum(ws) or 1.0
                jids += list(ids)[:4]
                wgts += [w / s for w in ws[:4]]
            a_joint = B.push_u16(jids, 'VEC4')
            a_wgt = B.push_f32(wgts, 'VEC4')
        # primitives 按 subsets
        subs_use = m['subsets'] or [{'firstIndex': 0, 'numIndices': len(tot_idx),
                                     'matId': 0}]
        covered = sum(s['numIndices'] for s in subs_use)
        if covered < len(tot_idx):
            subs_use = subs_use + [{'firstIndex': covered,
                                    'numIndices': len(tot_idx) - covered,
                                    'matId': subs_use[0]['matId']}]
        prims = []
        for sd in subs_use:
            sl = tot_idx[sd['firstIndex']:sd['firstIndex'] + sd['numIndices']]
            ai = B.push_u32_idx(sl)
            atts = {'POSITION': a_pos}
            if a_nrm is not None:
                atts['NORMAL'] = a_nrm
            if a_uv is not None:
                atts['TEXCOORD_0'] = a_uv
            if a_joint is not None:
                atts['JOINTS_0'] = a_joint
                atts['WEIGHTS_0'] = a_wgt
            prm = {'attributes': atts, 'indices': ai}
            mm = mat_for(md['subs'], sd['matId'])
            if mm is not None:
                prm['material'] = mm
            prims.append(prm)
        B.meshes.append({'name': md['name'], 'primitives': prims})
        node = {'name': md['name'], 'mesh': len(B.meshes) - 1}
        if md['xform'] is not None:
            node['matrix'] = _mul_col16(md['xform'], _m34_to_m4v_box(md['transform']))
        elif md['transform'] != [1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1]:
            node['matrix'] = md['transform']
        if skinned:
            node['skin'] = 0
        B.nodes.append(node)
        mesh_nodes.append(len(B.nodes) - 1)
    for mn in mesh_nodes:
        B.nodes[root].setdefault('children', []).append(mn)

    # ── 5. 封装 GLB ──
    gltf = {
        'asset': {'version': '2.0', 'generator': 'huntview v1.3 glb'},
        'scene': 0,
        'scenes': [{'nodes': [root], 'name': os.path.basename(path)}],
        'nodes': B.nodes, 'meshes': B.meshes, 'skins': B.skins,
        'materials': B.mats, 'textures': B.texs, 'images': B.imgs,
        'samplers': [{'magFilter': 9729, 'minFilter': 9987,
                      'wrapS': 10497, 'wrapT': 10497}],
        'bufferViews': B.views, 'accessors': B.accs,
        'buffers': [{'byteLength': len(B.bin)}],
    }
    if not B.skins:
        gltf.pop('skins')
    js = json.dumps(gltf, separators=(',', ':')).encode()
    while len(js) % 4:
        js += b' '
    B._pad()
    glb = struct.pack('<II', 0x46546C67, 2)
    total = 12 + 8 + len(js) + 8 + len(B.bin)
    glb += struct.pack('<I', total)
    glb += struct.pack('<II', len(js), 0x4E4F534A) + js
    glb += struct.pack('<II', len(B.bin), 0x004E4942) + bytes(B.bin)
    log.append(f'{len(models)} mesh, {len(bones)} bone, {len(B.mats)} mat, '
               f'{len(B.bin)//1024}KB bin, errors={len(errors)}')
    log.extend(errors[:5])
    return glb, log


def _m34_to_m4v_box(t16):
    return t16 if len(t16) == 16 else t16
