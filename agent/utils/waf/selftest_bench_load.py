"""bench_load.py 的本地自测：起一个 chunked HTTP 服务，跑压测器，校验吞吐。

单独放文件而不是塞进 python -c：多行 -c 在 bash 里转义太容易出错，
而且超时行为不直观（hang 住时看不出卡在哪一步）。
"""

import http.server
import os
import socketserver
import subprocess
import sys
import threading

PORT = 18095


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        body = b"ok"
        self.send_response(200)
        # openresty 的 ngx.say 默认就是 chunked，解析路径必须覆盖它
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        self.wfile.write(b"%x\r\n%s\r\n0\r\n\r\n" % (len(body), body))

    def log_message(self, *args):
        pass


def main() -> None:
    srv = socketserver.ThreadingTCPServer(("127.0.0.1", PORT), Handler)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        out = subprocess.run(
            [sys.executable, "bench_load.py", "--port", str(PORT),
             "--conns", "8", "--procs", "2", "--duration", "3"],
            capture_output=True, text=True,
            env=dict(os.environ, BENCH_DEBUG="1"),
            timeout=25,
        )
        print("stdout:", out.stdout.strip())
        print("stderr:", out.stderr.strip()[-200:])
        rps = float(out.stdout.split()[0])
        assert rps > 1000, f"吞吐过低：{rps} rps，说明 keep-alive 解析仍有问题"
        print("PASS")
    except subprocess.TimeoutExpired:
        print("FAIL: 压测器挂住（主进程等不到 worker 结果）")
        sys.exit(1)
    finally:
        srv.shutdown()


if __name__ == "__main__":
    main()