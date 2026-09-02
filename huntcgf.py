#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
huntcgf.py — CryEngine 0x746 "CrChF" 分块格式解析器(Hunt: Showdown 1896 用)
移植自 StrangerWay/cmodel 的 cgf_parser.cpp。
子命令:
  diag     FILE                打印 chunk 表诊断
  stats    FILE                网格/骨骼/材质统计
  obj      FILE [-o out]       导出 OBJ(含子集/材质组, 应用节点变换)
  jsonview FILE [-o out]       导出给浏览器查看器的 JSON(几何+子集+材质名)
"""
import argparse
import json
import math
import os
import struct
import sys

CT_MESH, CT_NODE, CT_MTL_NAME = 0x1000, 0x100B, 0x1014
CT_DATASTREAM, CT_MESH_SUBSETS = 0x1016, 0x1017
CT_BONES, CT_INT_FACES, CT_INT_SKIN_VERTS = 0x2000, 0x2004, 0x2005
SS_POS, SS_NRM, SS_UV, SS_IDX, SS_BONE, SS_QTAN = 0, 1, 2, 5, 9, 12


def parse_chunks(data: bytes):
    """返回 [{type, ver, id, data(bytes slice)}]"""
    if len(data) < 16:
        raise ValueError('文件太小')
    if data[:4] != b'CrCh':
        raise ValueError(f'未知签名 {data[:8]!r} (仅实现了 0x746/CrChF;0x744/745 后补)')
    _sig, ver, ncount, toff = struct.unpack_from('<4sIII', data, 0)
    if ver != 0x746:
        raise ValueError(f'chunk 表版本 0x{ver:x}')
    chunks = []
    for i in range(ncount):
        t, v, cid, sz, off = struct.unpack_from('<HHIII', data, toff + i * 16)
        if off + sz > len(data):
            continue
        chunks.append({'type': t, 'ver': v & 0x7FFF, 'id': cid,
                       'data': data[off:off + sz], 'size': sz})
    return chunks


def get_stream(by_id, chunk_id):
    """→ (count, element_size, payload bytes) 或 None"""
    if chunk_id <= 0 or chunk_id not in by_id:
        return None
    cd = by_id[chunk_id]['data']
    if len(cd) < 24:
        return None
    _fl, _st, cnt, esz, _sc, _r1, _r2 = struct.unpack_from('<3i2H2i', cd, 0)
    if cnt <= 0 or esz <= 0 or cnt > 4000000 or esz > 256:
        return None
    payload = cd[24:24 + cnt * esz]
    if len(payload) < cnt * esz:
        return None
    return cnt, esz, payload


def read_subsets(by_id, chunk_id):
    out = []
    if chunk_id <= 0 or chunk_id not in by_id:
        return out
    cd = by_id[chunk_id]['data']
    if len(cd) < 16:
        return out
    n_flags, cnt, _r1, _r2 = struct.unpack_from('<4i', cd, 0)
    if cnt <= 0 or cnt > 4096:
        return out
    stride = 36 + (4 if n_flags & 0x04 else 0)
    if 16 + cnt * stride > len(cd):
        return out
    for s in range(cnt):
        fi, ni, fv, nv, mid = struct.unpack_from('<5i', cd, 16 + s * stride)
        out.append({'firstIndex': fi, 'numIndices': ni, 'firstVert': fv,
                    'numVerts': nv, 'matId': mid})
    return out


def qtangent_normal(q):
    x = max(-1, min(1, q[0] / 32767.0))
    y = max(-1, min(1, q[1] / 32767.0))
    z = max(-1, min(1, q[2] / 32767.0))
    w = max(-1, min(1, q[3] / 32767.0))
    return (2 * (x * z + w * y), 2 * (y * z - w * x), w * w - x * x - y * y + z * z)


def parse_cgf(data: bytes):
    chunks = parse_chunks(data)
    by_id = {c['id']: c for c in chunks}
    out = {'meshes': [], 'skeleton': [], 'materials': [], 'errors': []}

    # 骨骼
    for c in chunks:
        if c['type'] != CT_BONES or c['size'] <= 32:
            continue
        bd = c['data'][32:]
        nb = min(len(bd) // 584, 100000)
        for b in range(nb):
            ent = bd[b * 584:(b + 1) * 584]
            ctrl, = struct.unpack_from('<I', ent, 0)
            w2b = struct.unpack_from('<12f', ent, 216)
            b2w = struct.unpack_from('<12f', ent, 264)
            name = ent[312:568].split(b'\x00', 1)[0].decode('ascii', 'replace')
            limb, off_par, n_child, off_child = struct.unpack_from('<2iI i', ent, 568)
            out['skeleton'].append({
                'name': name, 'controllerId': ctrl, 'offsetParent': off_par,
                'numChildren': n_child, 'offsetChildren': off_child,
                'b2w': list(b2w), 'w2b': list(w2b)})
        break

    # 材质名
    for c in chunks:
        if c['type'] != CT_MTL_NAME or c['size'] < 140:
            continue
        _f1, _f2 = struct.unpack_from('<2i', c['data'], 0)
        name = c['data'][8:136].split(b'\x00', 1)[0].decode('ascii', 'replace')
        if len(c['data']) >= 144:
            _phys, nsub = struct.unpack_from('<2i', c['data'], 136)
        else:                       # dog_msh.skin 存在 143B 奇葩 chunk
            nsub = -1
        out['materials'].append({'chunkId': c['id'], 'name': name, 'numSubMats': nsub})

    # 渲染网格(DataStream 路径)
    for c in chunks:
        if c['type'] != CT_MESH or c['ver'] not in (0x800, 0x801):
            continue
        if c['size'] < 264:
            continue
        vals = struct.unpack_from('<27i', c['data'], 0)
        (n_flags, _nf2, n_verts, n_indices, _nsub, subsets_id, _vanim) = vals[:7]
        stream_ids = vals[7:23]
        if n_flags & 1 or n_verts <= 0 or n_verts > 2000000 or n_indices <= 0:
            continue

        mesh = {'name': '', 'chunkId': c['id'], 'matChunkId': -1,
                'transform': [1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1],
                'positions': [], 'normals': [], 'uvs': [], 'indices': [],
                'subsets': [], 'boneWeights': []}

        st = get_stream(by_id, stream_ids[SS_POS])
        if st and st[0] == n_verts and st[1] >= 12:
            cnt, esz, p = st
            mesh['positions'] = [struct.unpack_from('<3f', p, v * esz)
                                 for v in range(cnt)]
        elif st and st[0] == n_verts and st[1] == 8:
            # Hunt 流式网格: 半精度 3×f16 + 2B 填充
            cnt, esz, p = st
            mesh['positions'] = [struct.unpack_from('<3e2x', p, v * 8)
                                 for v in range(cnt)]
        st = get_stream(by_id, stream_ids[SS_NRM])
        if st and st[0] == n_verts and st[1] >= 12:
            cnt, esz, p = st
            mesh['normals'] = [struct.unpack_from('<3f', p, v * esz)
                               for v in range(cnt)]
        if not mesh['normals']:
            st = get_stream(by_id, stream_ids[SS_QTAN])
            if st and st[0] == n_verts and st[1] == 8:
                cnt, esz, p = st
                mesh['normals'] = [qtangent_normal(
                    struct.unpack_from('<4h', p, v * 8)) for v in range(cnt)]
        st = get_stream(by_id, stream_ids[SS_UV])
        if st and st[0] == n_verts and st[1] >= 8:
            cnt, esz, p = st
            mesh['uvs'] = [struct.unpack_from('<2f', p, v * esz)
                           for v in range(cnt)]
        st = get_stream(by_id, stream_ids[SS_IDX])
        if st and st[0] == n_indices:
            cnt, esz, p = st
            if esz == 2:
                mesh['indices'] = [struct.unpack_from('<3H', p, f * 6)
                                   for f in range(n_indices // 3)]
            elif esz == 4:
                mesh['indices'] = [struct.unpack_from('<3I', p, f * 12)
                                   for f in range(n_indices // 3)]
        st = get_stream(by_id, stream_ids[SS_BONE])
        if st and st[0] in (n_verts, 2 * n_verts) and st[1] in (8, 12):
            cnt, esz, p = st
            if esz == 12:
                mesh['boneWeights'] = [
                    (struct.unpack_from('<4H', p, v * 12),
                     struct.unpack_from('<4B', p, v * 12 + 8))
                    for v in range(n_verts)]
            else:
                mesh['boneWeights'] = [
                    (struct.unpack_from('<4B', p, v * 8),
                     struct.unpack_from('<4B', p, v * 8 + 4))
                    for v in range(n_verts)]
        mesh['subsets'] = read_subsets(by_id, subsets_id)

        if mesh['positions'] and mesh['indices']:
            out['meshes'].append(mesh)
        elif mesh['positions']:
            out['errors'].append(
                f"mesh id={c['id']} 有 {len(mesh['positions'])} 顶点但缺索引流")

    # 兼容路径: 编译皮肤(老式)
    if not out['meshes']:
        vdata = fdata = None
        for c in chunks:
            if c['type'] == CT_INT_SKIN_VERTS and c['size'] > 32:
                vdata = c['data'][32:]
            if c['type'] == CT_INT_FACES and c['size'] > 0:
                fdata = c['data']
        if vdata and fdata:
            nV, nF = len(vdata) // 64, len(fdata) // 6
            if 0 < nV <= 2000000 and 0 < nF <= 2000000:
                mesh = {'name': 'compiled_skin', 'chunkId': -1, 'matChunkId': -1,
                        'transform': [1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1],
                        'positions': [], 'normals': [], 'uvs': [], 'indices': [],
                        'subsets': [], 'boneWeights': []}
                for v in range(nV):
                    px, py, pz = struct.unpack_from('<3f', vdata, v * 64 + 12)
                    mesh['positions'].append((px, py, pz))
                    ids = struct.unpack_from('<4H', vdata, v * 64 + 36)
                    wts = struct.unpack_from('<4f', vdata, v * 64 + 44)
                    mesh['boneWeights'].append(
                        (ids, tuple(min(255, max(0, int(w * 255 + .5)))
                                    for w in wts)))
                mesh['indices'] = [struct.unpack_from('<3H', fdata, f * 6)
                                   for f in range(nF)]
                out['meshes'].append(mesh)

    # 节点名/变换
    mesh_by_id = {m['chunkId']: m for m in out['meshes']}
    for c in chunks:
        if c['type'] != CT_NODE or c['size'] < 204:
            continue
        name = c['data'][:64].split(b'\x00', 1)[0].decode('ascii', 'replace')
        obj_id, _pid, _nc, mat_id = struct.unpack_from('<4i', c['data'], 64)
        tm = struct.unpack_from('<16f', c['data'], 84)   # tm[4][4] 行主序
        m = mesh_by_id.get(obj_id)
        if m is None:
            continue
        m['name'] = name
        m['matChunkId'] = mat_id
        m['transform'] = [tm[r * 4 + cc] for cc in range(4) for r in range(4)]  # 列主序
    out['valid'] = bool(out['meshes'] or out['skeleton'])
    return out


def xform(t, v):
    x, y, z = v
    # t 为列主序 16 元
    return (t[0] * x + t[4] * y + t[8] * z + t[12],
            t[1] * x + t[5] * y + t[9] * z + t[13],
            t[2] * x + t[6] * y + t[10] * z + t[14])


def mat_name(parsed, chunk_id):
    for m in parsed['materials']:
        if m['chunkId'] == chunk_id:
            return m['name']
    return f'mat_{chunk_id}'


def cmd_diag(args):
    data = open(args.file, 'rb').read()
    chunks = parse_chunks(data)
    names = {0x1000: 'Mesh', 0x100B: 'Node', 0x1014: 'MtlName',
             0x1016: 'DataStream', 0x1017: 'MeshSubsets',
             0x2000: 'CompiledBones', 0x2004: 'IntFaces', 0x2005: 'IntSkinVerts'}
    print(f'{args.file}: {len(data)}B, chunks={len(chunks)}')
    for c in chunks:
        nm = names.get(c['type'], '')
        extra = ''
        if c['type'] == CT_MESH and c['size'] >= 264:
            v = struct.unpack_from('<27i', c['data'], 0)
            extra = f' nV={v[2]} nI={v[3]}' + (' EMPTY' if v[0] & 1 else '')
        if c['type'] == CT_DATASTREAM and c['size'] >= 24:
            _a, typ, cnt, esz, _s = struct.unpack_from('<3i2H', c['data'], 0)
            extra = f' dsType={typ} cnt={cnt} esz={esz}'
        print(f"  [id={c['id']:>4} type=0x{c['type']:04x} ver=0x{c['ver']:03x} "
              f"sz={c['size']:>8} {nm}{extra}]")


def cmd_stats(args):
    data = open(args.file, 'rb').read()
    p = parse_cgf(data)
    print(f'网格: {len(p["meshes"])}  骨骼: {len(p["skeleton"])}  材质: {len(p["materials"])}')
    for m in p['meshes']:
        print(f'  ▸ {m["name"] or "(未命名)"} verts={len(m["positions"])} '
              f'faces={len(m["indices"])} subsets={len(m["subsets"])} '
              f'mtl={mat_name(p, m["matChunkId"])} bones={"✓" if m["boneWeights"] else "—"}')
    if p['skeleton']:
        print('  骨骼样例:', ', '.join(b['name'] for b in p['skeleton'][:8]), '…')
    for e in p['errors']:
        print('  ⚠', e)


def cmd_obj(args):
    data = open(args.file, 'rb').read()
    p = parse_cgf(data)
    if not p['meshes']:
        sys.exit('无可导出几何: ' + '; '.join(p['errors']))
    out = args.out or os.path.splitext(os.path.basename(args.file))[0] + '.obj'
    v_off = 1
    with open(out, 'w') as f:
        f.write(f'# huntcgf export: {os.path.basename(args.file)}\n')
        for m in p['meshes']:
            f.write(f'o {m["name"] or "mesh_%d" % m["chunkId"]}\n')
            for v in m['positions']:
                x, y, z = xform(m['transform'], v)
                f.write(f'v {x:.6f} {y:.6f} {z:.6f}\n')
            for uv in m['uvs']:
                f.write(f'vt {uv[0]:.6f} {uv[1]:.6f}\n')
            for n in m['normals']:
                f.write(f'vn {n[0]:.4f} {n[1]:.4f} {n[2]:.4f}\n')
            has_vt = len(m['uvs']) == len(m['positions'])
            has_vn = len(m['normals']) == len(m['positions'])
            cur_mtl = None
            subs = m['subsets'] or [{'firstIndex': 0,
                                     'numIndices': len(m['indices']) * 3,
                                     'matId': -1}]
            for s in subs:
                mn = mat_name(p, m['matChunkId']) if s['matId'] < 0 \
                    else f"{mat_name(p, m['matChunkId'])}#{s['matId']}"
                if mn != cur_mtl:
                    f.write(f'usemtl {mn}\n')
                    cur_mtl = mn
                for fi in range(s['firstIndex'] // 3,
                                (s['firstIndex'] + s['numIndices']) // 3):
                    a, b, cc = m['indices'][fi]
                    a += v_off; b += v_off; cc += v_off
                    if has_vt and has_vn:
                        f.write(f'f {a}/{a}/{a} {b}/{b}/{b} {cc}/{cc}/{cc}\n')
                    elif has_vt:
                        f.write(f'f {a}/{a} {b}/{b} {cc}/{cc}\n')
                    else:
                        f.write(f'f {a} {b} {cc}\n')
            v_off += len(m['positions'])
    print(f'# OBJ → {out} ({len(p["meshes"])} 网格)')


def cmd_jsonview(args):
    data = open(args.file, 'rb').read()
    p = parse_cgf(data)
    meshes = []
    for m in p['meshes']:
        meshes.append({
            'name': m['name'] or f"mesh_{m['chunkId']}",
            'mat': mat_name(p, m['matChunkId']),
            'transform': m['transform'],
            'pos': [round(c, 5) for v in m['positions'] for c in v],
            'uv': [round(c, 5) for v in m['uvs'] for c in v],
            'idx': [i + 1 for tri in m['indices'] for i in tri],
            'subsets': m['subsets']})
    payload = {'file': os.path.basename(args.file), 'meshes': meshes,
               'bones': [{'name': b['name'], 'parentOff': b['offsetParent'],
                          'b2w': [round(x, 5) for x in b['b2w']]}
                         for b in p['skeleton']]}
    out = args.out or os.path.splitext(os.path.basename(args.file))[0] + '.json'
    with open(out, 'w') as f:
        json.dump(payload, f, separators=(',', ':'))
    print(f'# JSON → {out} ({len(meshes)} 网格, {os.path.getsize(out)//1024}KB)')


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest='cmd', required=True)
    for name, fn in (('diag', cmd_diag), ('stats', cmd_stats),
                     ('obj', cmd_obj), ('jsonview', cmd_jsonview)):
        p = sub.add_parser(name)
        p.add_argument('file')
        p.add_argument('-o', '--out')
        p.set_defaults(fn=fn)
    args = ap.parse_args()
    args.fn(args)


if __name__ == '__main__':
    main()
