#!/usr/bin/env python3
"""WAF 数据面吞吐/延迟压测器（keep-alive 版）。

为什么不用 ab：ab 每次请求都新建连接，且不报告延迟分位数。在压测机上
连接建立的开销远大于 WAF 本身的 Lua 开销（实测整条链路只有 ~5k rps，
而 keep-alive 下同等机器能到 10 万级），于是测出来的「WAF 开销」被
稀释到噪声里 —— 这正是历史上出现 -0.34% / -0.52% 这类物理上不可能的
负开销的原因。

wrk 在压测机上装不上（apt 无该包、GitHub 不可达），所以自带一个：
  - 多进程 + 每个进程一条 keep-alive 连接，压满并发
  - 统计 rps 与延迟分位数（P50/P90/P99），吞吐不能替代延迟对照
  - 每个请求都是完整 HTTP/1.1 请求，读完响应再复用连接

用法：
  python3 bench_load.py --port 18080 --conns 8 --duration 10 --path /
输出（最后一行，机器可解析）：
  RESULT rps=<n> p50=<ms> p90=<ms> p99=<ms> errors=<n>
"""

import argparse
import multiprocessing
import os
import socket
import sys
import time


def build_request(path: str) -> bytes:
    # 显式声明 Content-Length: 0，避免服务端等请求体。
    return (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: bench.local\r\n"
        f"User-Agent: waf-bench\r\n"
        f"Accept: */*\r\n"
        f"Connection: keep-alive\r\n"
        f"Content-Length: 0\r\n"
        f"\r\n"
    ).encode()


def read_response(sock: socket.socket, buf: bytearray) -> bytes:
    """从缓冲区里取出一条完整响应；不够则继续读。

    必须正确消费 body，否则残留字节会被当成下一个响应的起始；而在
    keep-alive 连接上，一旦没消费干净，后续每次 recv 都会一直阻塞到
    超时 —— 表现为吞吐塌到个位数 rps（P99 却是正常的 1~2ms）。
    openresty 的 ngx.say 默认就是 chunked，所以 chunked 分支是主路径，
    不是边角情况。
    """
    while True:
        head_end = buf.find(b"\r\n\r\n")
        if head_end >= 0:
            head = bytes(buf[:head_end])
            parts = head.split(b"\r\n", 1)[0].split(b" ")
            status = parts[1] if len(parts) > 1 and parts[1].isdigit() else b"000"
            chunked = b"transfer-encoding: chunked" in head.lower()

            if chunked:
                # 结束块是 "0\r\n\r\n"，连同前面数据一起消费掉。
                end = buf.find(b"\r\n0\r\n")
                if end >= 0:
                    del buf[: end + len(b"\r\n0\r\n") + 2]
                    return status
            else:
                clen = 0
                for line in head.split(b"\r\n")[1:]:
                    if line.lower().startswith(b"content-length:"):
                        try:
                            clen = int(line.split(b":", 1)[1].strip())
                        except ValueError:
                            clen = 0
                if len(buf) >= head_end + 4 + clen:
                    del buf[: head_end + 4 + clen]
                    return status
        chunk = sock.recv(65536)
        if not chunk:
            return b"000"
        buf.extend(chunk)


def worker(port: int, path: bytes, conns: int, duration: float, out) -> None:
    req = build_request(path)
    socks = []
    for _ in range(conns):
        s = socket.create_connection(("127.0.0.1", port), timeout=10)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        socks.append(s)

    latencies = []
    errors = 0
    count = 0
    reconnects = 0
    first_error = ""
    deadline = time.perf_counter() + duration
    for s in socks:
        s.settimeout(max(0.1, deadline - time.perf_counter()))
    try:
        while time.perf_counter() < deadline:
            for idx, s in enumerate(socks):
                if time.perf_counter() >= deadline:
                    break
                try:
                    s.sendall(req)
                    t0 = time.perf_counter()
                    buf = bytearray()
                    status = read_response(s, buf)
                    dt = (time.perf_counter() - t0) * 1000.0
                    if status.isdigit() and status != b"000":
                        latencies.append(dt)
                        count += 1
                    else:
                        errors += 1
                except (OSError, socket.timeout) as exc:
                    errors += 1
                    if not first_error:
                        first_error = f"{type(exc).__name__}: {exc}"
                    # 必须重建连接。早先只是 break 掉本轮循环，下一轮又拿
                    # 这条已损坏的 socket 继续 send/recv，每次都立刻失败 ——
                    # 于是一个瞬时错误就废掉整条连接，进程空转到截止时间，
                    # 表现为吞吐塌到个位数 rps 而 P99 看起来完全正常。
                    try:
                        s.close()
                    except OSError:
                        pass
                    try:
                        s = socket.create_connection(("127.0.0.1", port), timeout=10)
                        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                        s.settimeout(max(0.1, deadline - time.perf_counter()))
                        socks[idx] = s
                        reconnects += 1
                    except OSError:
                        break
    finally:
        for s in socks:
            try:
                s.close()
            except OSError:
                pass

    if os.environ.get("BENCH_DEBUG"):
        print(
            f"debug: ok={count} errors={errors} reconnects={reconnects} first_error={first_error!r}",
            file=sys.stderr,
        )

    latencies.sort()
    def pct(p: float) -> float:
        if not latencies:
            return float("nan")
        idx = min(len(latencies) - 1, int(len(latencies) * p))
        return latencies[idx]

    out.put((count, errors, pct(0.50), pct(0.90), pct(0.99)))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--conns", type=int, default=8)
    ap.add_argument("--procs", type=int, default=2)
    ap.add_argument("--duration", type=float, default=10.0)
    ap.add_argument("--path", default="/")
    args = ap.parse_args()

    ctx = multiprocessing.get_context("fork")
    out = ctx.Queue()
    procs = [
        ctx.Process(
            target=worker,
            args=(args.port, args.path.encode(), args.conns, args.duration, out),
        )
        for _ in range(args.procs)
    ]
    t0 = time.perf_counter()
    for p in procs:
        p.start()
    results = [out.get() for _ in procs]
    for p in procs:
        p.join()
    elapsed = time.perf_counter() - t0

    total = sum(r[0] for r in results)
    errors = sum(r[1] for r in results)

    def merge(idx: int) -> float:
        vals = sorted(r[idx] for r in results if not math_nan(r[idx]))
        if not vals:
            return float("nan")
        # 多进程各自算分位数再取中位数的近似：足够看出 P99 是否恶化。
        return vals[len(vals) // 2]

    # 输出两列裸数字，便于 shell 侧 cut/awk 直接取用
    # （早先输出 "rps=... p99=..." 带键名，shell 按空白切列后 awk 会把
    #  "rps=123" 当 0，导致统计阶段除零失败。）
    print(f"{total / elapsed:.1f} {merge(4):.3f}")


def math_nan(x: float) -> bool:
    return x != x


if __name__ == "__main__":
    main()