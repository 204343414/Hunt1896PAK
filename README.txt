═══════════════════════════════════════════════════════
 猎杀对决 (Hunt: Showdown 1896) 资产浏览器 · v1.12 归档
 只读预览工具 · 不解题不出售 · 同人整活纪念用途
 2026-09-03 停工。能用的是 mesh+权重导出；音频/骨架预览/法线未过验收。
 详见 ARCHIVE.md
═══════════════════════════════════════════════════════

【怎么用 — 3 步】
 1. 解压本 zip(不能直接双击 zip 里运行!)
 2. 进入解压出的 huntview/ 目录, 运行:  bash start.sh
 3. 浏览器打开 http://127.0.0.1:8796
    (找不到游戏目录时: bash start.sh "/你的/Hunt Showdown 1896")

【v1.3 新东西(工作区开发版)】
 ▶ 完整材质预览: diffuse + 法线(ddna) + 高光(spec) 全通道上屏(接近游戏观感)
 ▶ 一键导出 glTF(.glb): 几何+骨架+蒙皮权重+全部贴图打包, Unity/Blender/VRChat SDK 直接认
 ▶ 猎人按编号整套装配: 侧栏编号下拉(001~020 实有号自动列出) + 男/女按钮
 ▶ mtl 材质查看器(子材质+贴图缩略图) · dds 贴图直击大图
 ▶ ↑↓ 方向键速切同目录模型 · Shift+点击=叠加拼装 · 目录树默认隐藏杂件

【v1.2 已有】
 ▶ 整模型一键装配: 点 .cdf 自动把骨架 + 全部皮肤部件合成一个场景
   · 蜘蛛 → 身体+毛发+毒牙+内脏 一次齐
   · 屠夫/meathead → 身体+四柱+猪头+木刺 全到位
   · dog 这类部分角色只出骨架(它的几何在 chr 里, 下版补)
 ▶ 贴图预览: .mtl 引用自动解出分裂 DDS(BC1/BC3/BC7…), 模型带皮出图,
   顶栏"贴图"按钮可开关; 无贴图部件回落为色块
 ▶ 动作清单: 从 .animevents 抓出该角色全部动画名(右侧栏 🎬)
 ▶ 音频在线播放保留: .wem 点开即播(内部 ww2ogg 转码)

【操作】
 鼠标左键拖动=旋转 · 右键拖动=平移 · 滚轮=缩放
 顶栏: 线框 / 骨架 / 贴图 / 复位 / 下载原始文件

【目录】
 角色: characters/ 下各怪 (spider/, meathead/, animals/dog …)
 猎人皮肤: characters/hunter_male|hunter_female/…
 武器武器: characters/weapons/
 音频: audio/wwise/…(.wem 可播, .bnk 是容器请"下载原始文件")
 静态物件: objects/

【文件说明】
 huntview.py  主程序(服务器+网页一体, 无第三方前端依赖)
 huntpak.py   pak 加密读取(CryEngine RSA/AES)
 huntcgf.py   cgf/chr/skin/skinm 几何+骨骼解码
 huntdd       DDS 贴图解码器(BC1/2/3/4/5/BC7, 自编译)
 ww2ogg+两个码书  wem→ogg 音频转码
 start.sh     一键启动(自动装 pycryptodome/zstandard 依赖)

【调参】
 端口: bash start.sh 端口号        默认 8796
 全量包: HUNT_SKIP='' bash start.sh    默认跳过 shader/本地化/fastload 等

【常见问题】
 Q: 为什么 zip 不能直接跑?
    A: 它是压缩包, 不是程序。解压 → 进目录 → bash start.sh
 Q: 首次加载模型有点慢?
    A: 正常: 贴图/几何按需从 pak 解压, 首次会在磁盘留缓存, 之后秒开
 Q: 某个模型没贴图?
    A: 部分怪(如 dog)几何结构特殊, 目前只出骨架; 屠夫贴图正常
 Q: VRChat 导出?
    A: 计划中 v2(v1.2 是"看爽"版; 导出走 glTF, Unity/Blender 直接认)

═══════════════════════════════════════════════════════
