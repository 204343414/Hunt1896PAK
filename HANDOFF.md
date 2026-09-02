# HANDOFF — Hunt: Showdown 资产预览器项目交接
> 写给下一个接手工作的 LLM/助手。读这份+PLAN.md+README.txt 就能接着干。

## 项目是什么

给《Hunt: Showdown 1896》做的**只读资产浏览器**(Python 单文件服务+浏览器 WebGL 预览)。
目的: 供用户做 VRChat avatar/world 同人整活内容。非修改游戏、非作弊工具。

用户画像: VRChat 老创作者(约 1 万小时 Unity avatar/world 经验), 中文, 极简操作为上,
注意力易涣散——**所有回复开头放一行 TL;DR**, 操作步骤给可直接复制的命令。

## 工作区地图

```
/home/user/huntview/          ← 主程序目录(本地版 + demo 服务器都从这份跑)
  huntview.py    主程序: HTTP server + SPA(浏览器端全部 JS 在 SPA 字符串里) + 索引/装配/贴图
  huntpak.py     CryEngine PAK 解密(RSA/AES)+ZIP64 读取 + HTTP Range 数据源
  huntcgf.py     cgf/chr/skin/skinm/cgfm 几何+骨骼+蒙皮权重解析
  huntglb.py     glTF 2.0 二进制(.glb)导出封装器
  huntdd.cpp/huntdd  DDS 解码器 BC1/2/3/4/5 + bc7decomp(来自 richgel999/bc7enc_rdo)
  huntserve.py   Range-aware 静态文件服务器(隧道端供给用)
  ww2ogg + packed_codebooks*.bin  wem→ogg 音频转码
  README.txt     给用户的说明
  PLAN.md        阶段计划+理论上限
  HANDOFF.md     本文件
/home/user/huntrip/           ← 研发区(idx_all/*.json.gz 是全资产索引, 读时 gzip.open)
  cmodel_main_ref.cpp         cmodel 主程序(分裂 DDS 重组权威注释)
  cgf_parser_ref.cpp          StrangerWay cgf 解析参考
  paks.json                   旧隧道 URL 清单(会过期, 别硬用)
/tmp/                          ← 运行时缓存(huntview_tex/huntview_audio), 不持久
```

## 运行形态

- **本地版**(用户主力): `bash start.sh` → http://127.0.0.1:8796, 直接读游戏目录 pak。
- **在线 demo**: 用户在自己机器跑 `python3 huntserve.py 8000`(游戏根目录) + cloudflared quick
  tunnel; 沙箱里 `huntview.py <隧道URL> 8796` 通过 HTTP Range 拉数据。
- SPA 在 huntview.py 的 `SPA = r"""..."""` 字符串里, 改前端=改那段。

## 已实现(别再重做)

- pak 解密/索引/搜索; cgf/skin/skinm 几何+骨架+蒙皮权重; 分裂 DDS 重组(stub+.N 分片跨包)
- BC1/BC3/BC5/BC7 解码; mtl 文本 XML 解析 + SubMaterials→贴图路径; .tif→.dds 转换规则
- cdf 整模装配(CA_SKIN+CA_BONE 骨骼挂点变换; 空 attachment 回退同目录/attachments 前缀扫描)
- 猎人换装编号套装装配(/api/outfit?g=male|female&n=001..020); mtl/dds 查看器
- 双灯+法线贴图(TBN 屏幕微分)+spec 高光渲染; glTF 导出(含蒙皮 joints/weights + PNG 内嵌)
- wem→ogg 在线播放; ↑↓ 同目录速切; Shift+点击叠加拼装; 杂件隐藏过滤; 物品栏 45° 缩略图墙

## 已知的坑(排障速查)

1. **demo 502/索引 files=0** → 先看隧道是否活着(curl 根 URL), 再看 Range 支持(curl -I 要
   有 Accept-Ranges), 新版 huntserve.py 已修 send_head 不发头的误判。
2. **某模型没几何/只有一个三角** → 查该角色的 skinm 在哪个 characters_lods-partN(demo
   filter 是否挂了那个包; 本地版无此问题)。蜘蛛在 part1, 狗/猎人在 part0。
3. **贴图缺失显示土色块** → 贴图分片散在 82 个 textures-* 包里随机分布; demo 只挂了 4 个,
   fallback 纯色不是美术脏。本地版全包没这问题。
4. **JSON 解析失败空响应** → 往往是 curl 超时截断, 不是服务器错; 加 -m 300+。
5. **python http.server 不支持 Range** → 隧道侧必须用 huntserve.py(带 Range)。
6. 大改 SPA 后浏览器要**强刷**(已对 / 响应加 Cache-Control: no-cache)。

## 没做完(按 PLAN.md 优先级)

- 动画播放( caf/dba 关键帧解码 → 蒙皮驱动; 单动画为目标, 不做混合树)
- 音效关联反推(animevents parameter 是 CryEngine 音频控制 ID, 中间映射表还没找到)
- glTF 导出轴向/蒙皮精度若用户导入 Unity 报歪, 优先查根节点 rotX(-90) 那个约定
- dog 那类 chr 内 IntSkinVertices(chunk 0x2003, Markemp 项目有格式)兜底解码(spider/dog
  已由 skinm 路径解决, 此条仅极端老格式才需要)

## 用户协作约定

- 中文回复; 命令给可复制的行; 别问英语操作。
- 分类/挑选/整理类活用户会让**别的 chat 的 AI** 干, 别抢; 你的份内是把预览器做好。
- 每轮交付走 demo 热更新 + 用户要时重新打 zip(/home/user/huntview_vX.Y.zip)。
