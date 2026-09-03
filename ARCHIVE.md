# Hunt 资产浏览器 · 归档（2026-09-03）

用户宣布停工。代码冻在 **v1.12.1**（`9281bdc`）。不要再给法线/音频/骨架预览补丁，除非有人明确回头。

## 实际能用（用户验收过）

- 只读浏览 Hunt 1896 pak，不改游戏文件
- 点 `.cdf` 装配整模；搜索装配单永远排前
- 几何 + **蒙皮权重** 进 glTF，Blender/Unity 能当带权重 mesh 用
- 贴图（漫反射）预览、mtl/dds 查看、猎人编号套装
- 相机：左旋右移滚轮；俯仰夹紧（v1.6）
- `.dba` 只能扫出片段**名字**，播不了

启动：解压后 `bash start.sh`，浏览器开 `localhost:8796`。HK 更新不要走 GitHub HTTPS。

## 明确失败，停在这里

| 项 | 事实 |
|---|---|
| 法线/PBR | 关「法线」干净；开了污泥。用户原法线=绿红 BC5。**停。** |
| 音频播放 | Hunt 新包大量 Wwise Opus（fmt 0x3040/3041）。ww2ogg 只吃 Vorbis。本机点 `.wem` **无声**。v1.12 加了 ffmpeg 兜底和失败文案，用户仍无声。`.bnk` 是容器。 |
| 预览「骨架」按钮 | 用户看不见变化。线曾被深度挡住；武器 chr 可能只有 1–2 根骨。 |
| 导出骨骼在 Blender | 叶子 0 长骨显示成球。v1.12 加了 5cm 尾巴，用户未确认。 |
| 动画关键帧 | 无独立 `.caf`；clip 在 `.dba`。**未解码。骨架预览不对则动画必错，不要先做。** |

## 不要再做的实验

- 法线通道 / Y 翻转 / packed-sRGB / 屏幕微分 TBN
- 只改 `<audio src>` 不报错
- `git fetch origin main` 当 HK 第一更新路径

## 文件

`huntview.py` 服务+SPA · `huntpak.py` pak · `huntcgf.py` 几何骨骼 · `huntglb.py` glTF · `huntdd` DDS · `start.sh` 启动

私钥 `id_huntview` 不进 git。
