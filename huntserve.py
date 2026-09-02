#!/usr/bin/env python3
"""huntserve.py — 支持 HTTP Range 的极简静态文件服务器
(供 cloudflared 隧道把 pak 数据遥送给在线 demo 用; 本地版 start.sh 不需要本件)
用法:  cd "/你的/Hunt Showdown 1896"(hunt.exe 所在目录)
       python3 huntserve.py 8000"""
import http.server
import os
import re
import sys


class RangedHandler(http.server.SimpleHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def send_response(self, code, message=None):
        # 所有 200/206 应答(含 HEAD)都宣告 Range 能力, 探测头才不误判
        super().send_response(code, message)
        if code in (200, 206):
            self.send_header('Accept-Ranges', 'bytes')

    def send_head(self):
        rng = self.headers.get('Range')
        path = self.translate_path(self.path)
        if not rng or os.path.isdir(path) or rng.startswith('bytes=!'):
            return super().send_head()
        m = re.match(r'bytes=(\d*)-(\d*)$', rng)
        if not m:
            return super().send_head()
        try:
            fsz = os.path.getsize(path)
        except OSError:
            self.send_error(404, 'File not found')
            return None
        s = int(m.group(1)) if m.group(1) else None
        e = int(m.group(2)) if m.group(2) else None
        if s is None and e is None:
            return super().send_head()
        if s is None:                      # bytes=-N 尾部
            s, e = max(0, fsz - e), fsz - 1
        elif e is None or e >= fsz:
            e = fsz - 1
        if s > e or s >= fsz:
            self.send_error(416, 'Requested Range Not Satisfiable')
            self.send_header('Content-Range', f'bytes */{fsz}')
            return None
        n = e - s + 1
        f = open(path, 'rb')
        f.seek(s)
        self.send_response(206)
        self.send_header('Content-Type', self.guess_type(path))
        self.send_header('Content-Range', f'bytes {s}-{e}/{fsz}')
        self.send_header('Accept-Ranges', 'bytes')
        self.send_header('Content-Length', str(n))
        self.end_headers()
        return RangeReader(f, n)

    def log_message(self, *a):
        pass


class RangeReader:
    """按剩余字节截断的文件读器(供 copyfile 只读 n 字节)"""
    def __init__(self, f, n):
        self.f, self.left = f, n

    def read(self, n=-1):
        if self.left <= 0:
            return b''
        if n < 0 or n > self.left:
            n = self.left
        d = self.f.read(n)
        self.left -= len(d)
        return d

    def close(self):
        self.f.close()


if __name__ == '__main__':
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    http.server.ThreadingHTTPServer.allow_reuse_address = True
    srv = http.server.ThreadingHTTPServer(('0.0.0.0', port), RangedHandler)
    print(f'Serving with Range support on 0.0.0.0:{port}  (Ctrl+C 停止)')
    srv.serve_forever()
