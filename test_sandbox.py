#!/usr/bin/env python3
# 沙箱联测: 用 cf 隧道当"游戏目录", 挑 6 个代表性 pak
import os, sys, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ.pop('HUNT_BASE', None)
import huntview

T = 'https://twelve-sheep-proprietary-nuclear.trycloudflare.com'
huntview.collect_paks = lambda root: [
    f'{T}/game_hunt/characters-part0.pak',
    f'{T}/game_hunt/characters_lods-part1.pak',
    f'{T}/game_hunt/animations.pak',
    f'{T}/game_hunt/objects_lods-part0.pak',
]

print('═ 建索引（过隧道拉 CDR）═')
idx = huntview.AssetIndex('unused', log=lambda m: print('  ' + m))
print(f'文件数: {len(idx.files):,}')

print('\n═ /api/ls 根目录 ═')
root = idx.ls('')
print('dirs:', root['dirs'][:10])

print('\n═ 搜索 spider ═')
for h in idx.search('spider_body')[:6]:
    print('  ', h['path'], h['size'])

print('\n═ 模型: spider_body.skin(应自动配 skinm) ═')
pl = huntview.model_payload(idx, 'characters/spider/spider_body.skin')
print(f"模型数={len(pl['models'])}, 骨骼={len(pl['bones'])}, 错误={pl['errors']}")
for m in pl['models']:
    print(f"  ▸ {m['name']}  顶点={len(m['pos'])//3}  面={len(m['idx'])//3}  材质={m['mat']}")

print('\n═ 模型: 静态武器 cgf(鱼叉弹头) ═')
pl2 = huntview.model_payload(idx, 'characters/weapons/2m/lance/attachments/ammo/ammo_harpoon_explosive/ammo_harpoon_explosive.cgf')
print(f"模型数={len(pl2['models'])}, 骨骼={len(pl2['bones'])}")
for m in pl2['models']:
    print(f"  ▸ {m['name']}  顶点={len(m['pos'])//3}  面={len(m['idx'])//3}")

print('\n═ 动画清单: spider_body.skin ═')
an = huntview.anims_payload(idx, 'characters/spider/spider_body.skin')
print('found:', an['found'], '| chr:', an.get('chr'))
for a in an['anims'][:10]:
    print(f"  🎞 {a['name']}  → {a['dba']}")
print(f"  …共 {len(an.get('anims',[]))} 条")
