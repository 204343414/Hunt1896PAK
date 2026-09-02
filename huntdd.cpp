// huntdd.cpp — DDS(BC1/2/3/4/5/BC7/未压缩) → RGBA8 原始像素
// 用法: huntdd <in.dds> <out.raw>        out.raw = [w u32 LE][h u32 LE] + RGBA8
// 自动兼容 CryEngine 合并分片(调用侧把 stub 头+像素拼好后传进来)。
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cmath>
#include <vector>
#include "bc7decomp.h"

static uint16_t r16(const uint8_t* p) { return p[0] | (p[1] << 8); }
static uint32_t r32(const uint8_t* p) { return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24); }

// ═══ BC1/DXT1 ═══
static void dec_bc1(const uint8_t* b, uint8_t* px /*16×4*/) {
    uint32_t c0 = r16(b), c1 = r16(b + 2);
    uint8_t col[4][4];
    auto exp565 = [](uint32_t c, uint8_t* o) {
        o[0] = (uint8_t)((c >> 8) & 0xF8); o[0] |= o[0] >> 5;
        o[1] = (uint8_t)((c >> 3) & 0xFC); o[1] |= o[1] >> 6;
        o[2] = (uint8_t)((c << 3) & 0xF8); o[2] |= o[2] >> 5;
        o[3] = 255;
    };
    exp565(c0, col[0]); exp565(c1, col[1]);
    if (c0 > c1) {
        for (int i = 0; i < 3; i++) {
            col[2][i] = (uint8_t)((2 * col[0][i] + col[1][i]) / 3);
            col[3][i] = (uint8_t)((col[0][i] + 2 * col[1][i]) / 3);
        }
        col[2][3] = col[3][3] = 255;
    } else {
        for (int i = 0; i < 3; i++) col[2][i] = (uint8_t)((col[0][i] + col[1][i]) / 2);
        col[2][3] = 255; col[3][0] = col[3][1] = col[3][2] = 0; col[3][3] = 0;
    }
    uint32_t idx = r32(b + 4);
    for (int i = 0; i < 16; i++) memcpy(px + i * 4, col[(idx >> (i * 2)) & 3], 4);
}

// DXT5 风格 alpha (a0,a1 + 48bit)
static void dec_alpha(const uint8_t* b, uint8_t* a16) {
    uint32_t a0 = b[0], a1 = b[1];
    uint8_t A[8]; A[0] = (uint8_t)a0; A[1] = (uint8_t)a1;
    if (a0 > a1) { for (int i = 1; i <= 6; i++) A[i + 1] = (uint8_t)(((7 - i) * a0 + i * a1) / 7); }
    else { for (int i = 1; i <= 4; i++) A[i + 1] = (uint8_t)(((5 - i) * a0 + i * a1) / 5); A[6] = 0; A[7] = 255; }
    uint64_t bits = 0; for (int i = 0; i < 6; i++) bits |= (uint64_t)b[2 + i] << (i * 8);
    for (int i = 0; i < 16; i++) a16[i] = A[(bits >> (i * 3)) & 7];
}

int main(int argc, char** argv) {
    if (argc != 3) { fprintf(stderr, "usage: huntdd in.dds out.raw\n"); return 2; }
    FILE* f = fopen(argv[1], "rb");
    if (!f) { fprintf(stderr, "cannot open %s\n", argv[1]); return 1; }
    fseek(f, 0, SEEK_END); long fsz = ftell(f); fseek(f, 0, SEEK_SET);
    std::vector<uint8_t> buf(fsz);
    if (fread(buf.data(), 1, fsz, f) != (size_t)fsz) { fclose(f); return 1; }
    fclose(f);
    if (fsz < 148 || memcmp(buf.data(), "DDS ", 4)) { fprintf(stderr, "not DDS\n"); return 1; }
    const uint8_t* d = buf.data();
    uint32_t W = r32(d + 16), H = r32(d + 12), MIP = r32(d + 28);
    uint32_t fourcc = r32(d + 76 + 8);   // ddspf.dwFourCC
    uint32_t rgbbits = r32(d + 76 + 12);
    bool dx10 = (fourcc == 0x30315844u);
    uint32_t dxgi = 0;
    size_t hdrBytes = 128;
    if (dx10) { dxgi = r32(d + 128); hdrBytes = 148; }
    if (dx10 && dxgi == 0) { fprintf(stderr, "dx10 but dxgi=0?\n"); return 1; }

    // 格式 → 块字节数/类型
    // 1=BC1 2=BC2(DXT3) 3=BC3(DXT5) 4=BC4U 5=BC5U 7=BC7 0=未压缩
    int fmt = 0; int blockBytes = 0;
    if (dx10) {
        switch (dxgi) {
            case 70: case 71: case 72: fmt = 1; blockBytes = 8; break;
            case 73: case 74: case 75: fmt = 2; blockBytes = 16; break;
            case 76: case 77: case 78: fmt = 3; blockBytes = 16; break;
            case 79: case 80: case 81: fmt = 4; blockBytes = 8; break;
            case 82: case 83: case 84: case 85: fmt = 5; blockBytes = 16; break;
            case 98: case 99: fmt = 7; blockBytes = 16; break;
            case 28: case 87: case 88: fmt = 0; blockBytes = 0; break; // RGBA8/BGRA8
            default: fmt = -1;
        }
    } else {
        switch (fourcc) {
            case 0x31545844: case 0x31435441: fmt = 1; blockBytes = 8; break;   // DXT1/ATC?
            case 0x33545844: fmt = 2; blockBytes = 16; break;   // DXT3
            case 0x35545844: fmt = 3; blockBytes = 16; break;   // DXT5
            case 0x31495441: case 0x55344342: fmt = 4; blockBytes = 8; break;   // ATI1/BC4U
            case 0x32495441: case 0x55354342: case 0x32435441: fmt = 5; blockBytes = 16; break; // ATI2/BC5U/A2XY
            default:
                if (rgbbits == 32) { fmt = 0; blockBytes = 0; }
                else fmt = -1;
        }
    }
    if (fmt < 0) { fprintf(stderr, "unsupported fmt fourcc=0x%08x dxgi=%u rgb=%u\n", fourcc, dxgi, rgbbits); return 1; }

    const uint8_t* px = d + hdrBytes;
    size_t pay = fsz - hdrBytes;

    // 定位实际 mip: 在头标称 W/H 上找匹配级别(向下除2)
    uint32_t w = W, h = H;
    if (fmt == 0) {
        while ((size_t)w * h * 4 > pay && (w > 1 || h > 1)) { if (w > 1) w >>= 1; if (h > 1) h >>= 1; }
    } else {
        while (((size_t)(w + 3) / 4) * ((size_t)(h + 3) / 4) * (size_t)blockBytes > pay && (w > 1 || h > 1)) { if (w > 1) w >>= 1; if (h > 1) h >>= 1; }
    }
    if (w == 0 || h == 0) { fprintf(stderr, "size resolve failed\n"); return 1; }

    uint32_t bw = (w + 3) / 4, bh = (h + 3) / 4;
    std::vector<uint8_t> out((size_t)w * h * 4, 255);

    if (fmt == 0) {
        // 未压缩 RGBA/BGRA (假定 32bpp)
        size_t need = (size_t)w * h * 4;
        if (pay < need) { fprintf(stderr, "raw payload short\n"); return 1; }
        // 判别 BGRA: 按 mask 在 84..96 位(common 0x00FF0000_R 0xFF00_G 0xFF_B)
        uint32_t rm = r32(d + 76 + 16), gm = r32(d + 76 + 20), bm = r32(d + 76 + 24), am = r32(d + 76 + 28);
        int ro, go, bo, ao;
        auto shiftof = [&](uint32_t m) { int s = 0; if (!m) return 0; while (!(m & 1)) { m >>= 1; s++; } return s; };
        ro = shiftof(rm); go = shiftof(gm); bo = shiftof(bm); ao = shiftof(am);
        for (size_t i = 0; i < (size_t)w * h; i++) {
            uint32_t v = r32(px + i * 4);
            out[i * 4 + 0] = (uint8_t)((v >> ro) & 0xFF);
            out[i * 4 + 1] = (uint8_t)((v >> go) & 0xFF);
            out[i * 4 + 2] = (uint8_t)((v >> bo) & 0xFF);
            out[i * 4 + 3] = am ? (uint8_t)((v >> ao) & 0xFF) : 255;
        }
    } else {
        for (uint32_t by = 0; by < bh; by++) for (uint32_t bx = 0; bx < bw; bx++) {
            const uint8_t* blk = px + ((size_t)by * bw + bx) * blockBytes;
            if (blk + blockBytes > d + fsz) continue;
            uint8_t cell[64];
            memset(cell, 0, 64);
            if (fmt == 1) dec_bc1(blk, cell);
            else if (fmt == 2) { // DXT3: 8B alpha + bc1色块(无key色)
                for (int yy = 0; yy < 4; yy++) for (int xx = 0; xx < 4; xx++) {
                    uint32_t a4 = (r16(blk + yy * 2) >> (xx * 4)) & 0xF;
                    cell[(yy * 4 + xx) * 4 + 3] = (uint8_t)(a4 * 17);
                }
                uint8_t tmp[64]; dec_bc1(blk + 8, tmp);
                for (int i = 0; i < 16; i++) { cell[i * 4] = tmp[i * 4] | 1; memcpy(cell + i * 4, tmp + i * 4, 3); }
            } else if (fmt == 3) { // DXT5
                uint8_t a16[16]; dec_alpha(blk, a16);
                uint8_t tmp[64]; dec_bc1(blk + 8, tmp);
                for (int i = 0; i < 16; i++) { memcpy(cell + i * 4, tmp + i * 4, 3); cell[i * 4 + 3] = a16[i]; }
            } else if (fmt == 4) { // BC4U → 灰度进 R
                uint8_t a16[16]; dec_alpha(blk, a16);
                for (int i = 0; i < 16; i++) { cell[i * 4] = a16[i]; cell[i * 4 + 1] = a16[i]; cell[i * 4 + 2] = a16[i]; cell[i * 4 + 3] = 255; }
            } else if (fmt == 5) { // BC5U → R,G
                uint8_t r16v[16], g16v[16]; dec_alpha(blk, r16v); dec_alpha(blk + 8, g16v);
                for (int i = 0; i < 16; i++) { cell[i * 4] = r16v[i]; cell[i * 4 + 1] = g16v[i]; cell[i * 4 + 2] = 0; cell[i * 4 + 3] = 255; }
            } else if (fmt == 7) {
                bc7decomp::color_rgba c16[16];
                std::memset(c16, 0, sizeof(c16));
                if (!bc7decomp::unpack_bc7(blk, c16)) { /* mode 非法时留黑 */ }
                for (int i = 0; i < 16; i++) { cell[i * 4] = c16[i].m_comps[0]; cell[i * 4 + 1] = c16[i].m_comps[1]; cell[i * 4 + 2] = c16[i].m_comps[2]; cell[i * 4 + 3] = c16[i].m_comps[3]; }
            }
            for (int yy = 0; yy < 4 && by * 4 + yy < h; yy++) {
                uint8_t* row = out.data() + ((size_t)(by * 4 + yy) * w + bx * 4) * 4;
                int n = (int)w - (int)bx * 4; if (n > 4) n = 4;
                for (int xx = 0; xx < n; xx++) memcpy(row + xx * 4, cell + (yy * 4 + xx) * 4, 4);
            }
        }
    }

    FILE* o = fopen(argv[2], "wb");
    if (!o) { fprintf(stderr, "cannot write %s\n", argv[2]); return 1; }
    uint8_t hd[8] = { (uint8_t)(w & 255), (uint8_t)((w >> 8) & 255), (uint8_t)((w >> 16) & 255), (uint8_t)((w >> 24) & 255),
                      (uint8_t)(h & 255), (uint8_t)((h >> 8) & 255), (uint8_t)((h >> 16) & 255), (uint8_t)((h >> 24) & 255) };
    fwrite(hd, 1, 8, o);
    fwrite(out.data(), 1, out.size(), o);
    fclose(o);
    fprintf(stderr, "%ux%u fmt=%d pay=%zu → %s\n", w, h, fmt, pay, argv[2]);
    return 0;
}
