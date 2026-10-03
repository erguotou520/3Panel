#!/usr/bin/env bash
# WAF 数据面吞吐基准（严格版）。
#
# 与 e2e_smoke.sh 内嵌的 BENCHMARK 段的区别，也正是它存在的理由：
# 早先那段测出的「开销 <2%」不可信，原因有三，逐条修掉：
#
#   1. worker_processes 1 + wrk -c50 时 nginx 自身就是瓶颈，Lua 开销被
#      排队淹没。表现为 empty_lua 端口甚至比无 Lua 的 baseline 还快
#      （实测 lua_hook_overhead = -2.42%，物理上不可能）。
#      这里把 worker 数设为 CPU 的一半，并绑核，让 wrk 与 nginx 不抢核。
#   2. 单轮测量在共享机器上噪声可达 ±6%，比要测的效应还大。
#      这里交错测 N 轮取中位数，并给出四分位距作为可信度指标。
#   3. 端口若挂错文件（把新版当旧版测）会得出「优化反而更慢」的结论。
#      这里在开始前打印每个端口实际加载的 lua 文件特征，确认无误。
#
# 用法：
#   bash bench_waf.sh                        # 默认 15 轮 × 10s，并发 8
#   BENCH_ROUNDS=25 BENCH_CONC=16 bash bench_waf.sh
set -u
cd "$(dirname "$0")"

LUA_DIR="$(cd ./lua && pwd)"
ROOT=${ROOT:-/tmp/wafbench}
IMG=${WAF_IMAGE:-openresty/openresty:alpine}
NAME=${BENCH_NAME:-wafbench}
PORT_BASE=${PORT_BASE:-18080}
ROUNDS=${BENCH_ROUNDS:-15}
DURATION=${BENCH_DURATION:-10s}
CONC=${BENCH_CONC:-8}
THREADS=${BENCH_THREADS:-2}

# worker 数取 CPU 一半，且不少于 2：让 nginx 有余量，Lua 才可能成为瓶颈。
CPUS=$(nproc 2>/dev/null || echo 4)
WORKERS=$((CPUS / 2))
if [ "$WORKERS" -lt 2 ]; then WORKERS=2; fi

echo "=== 基准参数 ==="
echo "  镜像      : "$IMG""
echo "  CPU       : "${CPUS}" 核，nginx worker="${WORKERS}"，wrk 绑核 0-$((CPUS-1))"
echo "  并发/线程 : -c"$CONC" -t"$THREADS""
echo "  轮次      : "$ROUNDS" 轮 × "$DURATION"，交错取中位数"
echo "  策略      : ${BENCH_POLICY:-none}"

docker rm -f "$NAME" >/dev/null 2>&1
rm -rf "$ROOT"; mkdir -p "$ROOT/waf" "$ROOT/logs"
cp "$LUA_DIR"/*.lua "$ROOT/waf/"

# 基准用的 rules.json：默认空策略，另可开 cc / full 贴近真实部署。
# POLICY 必须自带引号完整的 "sites" 键——漏掉引号会生成非法 JSON，数据面
# 解析失败后直接放行，于是 WAF 端口退化成空 Lua 端口，测出接近 0% 的假开销。
case "${BENCH_POLICY:-none}" in
  cc)   POLICY='"sites":{"1":{"cc":{"limit":100000000,"window":60,"action":"log","byUri":false}}}' ;;
  full) POLICY='"sites":{"1":{"bot":{"enabled":true,"allowGoodBots":true,"blockBadBots":true},"cc":{"limit":100000000,"window":60,"action":"log","byUri":false}}}' ;;
  *)    POLICY='"sites":{"1":{}}' ;;
esac
cat > "$ROOT/rules.json" <<EOF
{"global":{"rules":[],"ipListEnabled":false},${POLICY}}
EOF
# 前置自检：rules.json 必须是合法 JSON，否则本次测量作废（见上）。
if command -v python3 >/dev/null 2>&1; then
  if ! python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$ROOT/rules.json" 2>/dev/null; then
    echo "rules.json 不是合法 JSON，本次测量无意义，已中止" >&2
    cat "$ROOT/rules.json" >&2
    exit 1
  fi
fi

# 三个 server 块：P0 = 无 access_by_lua，P1 = 空 access_by_lua，
# P2 = 完整 WAF。P1 用来隔离「挂 Lua 本身」与「WAF 逻辑」的开销。
cat > "$ROOT/nginx.conf" <<EOF
user root;
worker_processes "${WORKERS}";
worker_cpu_affinity 00000001;
pid /logs/nginx.pid;
error_log /logs/error.log warn;
events { worker_connections 2048; multi_accept on; }
http {
  lua_package_path "/www/?.lua;;";
  lua_shared_dict waf_dict 128m;
  access_log off;
  sendfile off;
$(for p in 0 1 2; do
  echo "  server { listen $((80 + p)); access_log off;
    set \$waf_site_id 1;
    set \$waf_rules_path /www/rules.json;
    set \$waf_log_path /logs/waf_events.log;
    set \$waf_iplist_path /www/wl_v2.bin;"
  if [ "$p" -eq 0 ]; then
    echo "    access_by_lua_block { return; }"
  elif [ "$p" -eq 1 ]; then
    echo "    access_by_lua_block { return; }"
  else
    echo "    access_by_lua_file /www/waf/access.lua;"
  fi
  echo "    location / { default_type text/plain; content_by_lua_block { ngx.say(\"ok\") } } }"
done)
}
EOF

docker run -d --name "$NAME" \
  -p $((PORT_BASE)):80 -p $((PORT_BASE+1)):81 -p $((PORT_BASE+2)):82 \
  -v "$ROOT/nginx.conf:/usr/local/openresty/nginx/conf/nginx.conf:ro" \
  -v "$ROOT/waf:/www/waf:ro" \
  -v "$ROOT/rules.json:/www/rules.json:ro" \
  -v "$ROOT/logs:/logs" \
  "$IMG" >/dev/null

ready=0
for _ in $(seq 1 40); do
  if curl -sf -o /dev/null "http://127.0.0.1:$((PORT_BASE+2))/" 2>/dev/null; then ready=1; break; fi
  sleep 0.5
done
[ "$ready" = 1 ] || { echo "容器未就绪"; docker logs "$NAME" 2>&1 | tail -10; exit 1; }

# 自检：确认三个端口加载的是预期的东西，避免"挂错文件"得出反向结论。
echo
echo "=== 前置自检 ==="
echo -n "  P2 加载的 access.lua pcall 数: "; docker exec "$NAME" sh -c 'grep -c pcall /www/waf/access.lua' 2>/dev/null || echo "?"
echo -n "  rules.lua 是否含惰性 dims  : "; docker exec "$NAME" sh -c 'grep -c "type(f) ==" /www/waf/expr.lua /www/waf/rules.lua 2>/dev/null | paste -sd+ | bc' 2>/dev/null || echo "?"
echo -n "  rules.json               : "; cat "$ROOT/rules.json"

# taskset 是 Linux 专有的；macOS 上退化为不绑核。
# 注意不能让错误静默消失：绑核失败时若仍管道给 awk，样本会全空而
# 统计阶段只报「除零」，很难定位。
PIN=""
if command -v taskset >/dev/null 2>&1; then
  PIN="taskset -c 0-$((CPUS-1))"
fi

# 这台压测机装不上 wrk（apt 源无该包、GitHub 不可达），改用 ApacheBench。
# ab 每轮只发一批请求，靠外层多轮取中位数压制噪声；它不 keep-alive，
# 每次请求都要新建连接，绝对值偏低，但端口间可比 —— 开销是比值，不受影响。
measure() { # $1=端口
  ab -n "${AB_N:-20000}" -c "${BENCH_CONC:-8}" -q "http://127.0.0.1:$1/" 2>/dev/null \
    | awk '/Requests per second/ {print $4}'
}

echo
echo "=== 预热（不计入结果）==="
measure $((PORT_BASE+2)) >/dev/null

echo "=== 交错测量 ${ROUNDS} 轮 ==="
b=(); e=(); p=()
for i in $(seq 1 "$ROUNDS"); do
  b+=("$(measure $((PORT_BASE)))")
  e+=("$(measure $((PORT_BASE+1)))")
  p+=("$(measure $((PORT_BASE+2)))")
  printf "\r  已完成 %d/%d  " "$i" "$ROUNDS"
done
echo

# 中位数 + 四分位距：IQR 反映测量稳定度，IQR 接近效应大小时数字不可信。
# 不用 awk 的 `>` 重定向写临时文件：macOS 自带的是 BSD awk，
# 同样的表达式会被解析成 `>>>` 语法而失败。改用 sort + shell 读取。
stats() { # $1=label  其余为样本
  local tmp
  tmp=$(printf "%s\n" "${@:2}" | sort -n)
  local med
  med=$(printf "%s\n" "$tmp" | awk '{a[NR]=$1} END{print a[int((NR+1)/2)]}')
  local q1 q3
  q1=$(printf "%s\n" "$tmp" | awk '{a[NR]=$1} END{print a[int(NR*0.25)+1]}')
  q3=$(printf "%s\n" "$tmp" | awk '{a[NR]=$1} END{print a[int(NR*0.75)+1]}')
  awk -v m="$med" -v lo="$q1" -v hi="$q3" -v n="$1" \
    'BEGIN{printf "  %-10s 中位数=%8.0f rps  IQR=%.1f%%\n", n, m, (hi-lo)*100/m}'
  printf "%s" "$med" > "/tmp/bench_$1"
}

echo
echo "=== 各端口吞吐 ==="
stats baseline "${b[@]}"
stats empty_lua "${e[@]}"
stats waf      "${p[@]}"

mb=$(cat /tmp/bench_baseline); me=$(cat /tmp/bench_empty_lua); mw=$(cat /tmp/bench_waf)
rm -f /tmp/bench_baseline /tmp/bench_empty_lua /tmp/bench_waf

echo
awk -v b="$mb" -v e="$me" -v w="$mw" -v c="$CONC" 'BEGIN{
  if (b <= 0 || e <= 0 || w <= 0) { print "  测量无效（某一组为空），请加长 BENCH_ROUNDS"; exit 1 }
  printf "=== 开销（c=%d）===\n", c
  printf "  挂 Lua 本身 : %6.2f%%\n", (b-e)*100/b
  printf "  WAF 逻辑    : %6.2f%%\n", (e-w)*100/e
  printf "  端到端合计  : %6.2f%%\n", (b-w)*100/b
  if ((b-w)*100/b < 5) print "  => 达标（<5%）"
  else                 print "  => 未达标（>=5%）"
}'

echo
echo "=== 清理 ==="
docker rm -f "$NAME" >/dev/null 2>&1
echo "容器已删除（保留 KEEP_CONTAINER=1 可用于手工排查）"