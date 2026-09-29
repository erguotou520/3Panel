#!/usr/bin/env bash
# WAF OpenResty 端到端冒烟测试（Docker 版）
# 用法: bash agent/utils/waf/e2e_smoke.sh
set -u
LUA_DIR="$(cd "$(dirname "$0")/lua" && pwd)"
ROOT=/tmp/waf_e2e
IMG="${WAF_IMAGE:-openresty/openresty:alpine}"
WAF_DIR=/www/waf
NAME=waf-e2e
RULES_FILE="$ROOT/waf/rules.json"
pass=0; fail=0

check() {
  local name="$1" expected="$2" actual="$3"
  if [ "$expected" = "$actual" ]; then pass=$((pass+1)); else fail=$((fail+1)); echo "FAIL: $name (expect $expected, got $actual)"; fi
}

docker rm -f "$NAME" >/dev/null 2>&1
rm -rf "$ROOT"; mkdir -p "$ROOT/waf" "$ROOT/logs"
cp "$LUA_DIR"/*.lua "$ROOT/waf/"

# 白名单放行 docker 网关网段（容器内 remote_addr 是网关而非 127.0.0.1）
cat > "$RULES_FILE" <<'EOF'
{
  "global": {"rules": [
    {"id": 10, "name": "allow-docker-net1", "priority": 5, "match_type": "ip", "match_value": "172.16.0.0/12", "match_op": "exact", "action": "allow", "enabled": true},
    {"id": 11, "name": "allow-docker-net2", "priority": 5, "match_type": "ip", "match_value": "192.168.0.0/16", "match_op": "exact", "action": "allow", "enabled": true},
    {"id": 20, "name": "deny-banned", "priority": 10, "match_type": "ip", "match_value": "9.9.9.9", "match_op": "exact", "action": "deny", "enabled": true}
  ]},
  "sites": {"1": {"enabled": true,
    "rules": [
      {"id": 30, "name": "site-deny-git", "priority": 10, "match_type": "path", "match_value": "/.git", "match_op": "prefix", "action": "deny", "enabled": true}
    ],
    "compiled": {"path": {
      "/compiled-only": {"id": 31, "name": "site-compiled", "priority": 10, "action": "deny"}
    }},
    "cc": {"limit": 100, "window": 60, "action": "deny", "byUri": false}
  }}
}
EOF

cat > "$ROOT/nginx.conf" <<EOF
user root;
worker_processes 1;
pid /logs/nginx.pid;
error_log /logs/error.log warn;
events { worker_connections 256; }
http {
  lua_package_path "/www/?.lua;;";
  lua_shared_dict waf_dict 32m;
  access_log off;
  server {
    listen 80;
    set \$waf_site_id 1;
    set \$waf_rules_path $WAF_DIR/rules.json;
    set \$waf_log_path /logs/waf_events.log;
    access_by_lua_file $WAF_DIR/access.lua;
    location / { default_type text/plain; content_by_lua_block { ngx.say("ok") } }
  }
  server {
    listen 81;
    access_log off;
    location / { default_type text/plain; content_by_lua_block { ngx.say("ok") } }
  }
  server {
    listen 82;
    access_log off;
    access_by_lua_block { return; }
    location / { default_type text/plain; content_by_lua_block { ngx.say("ok") } }
  }
}
EOF

docker run -d --name "$NAME" -p 18080:80 -p 18081:81 -p 18082:82 \
  -v "$ROOT/nginx.conf":/usr/local/openresty/nginx/conf/nginx.conf:ro \
  -v "$ROOT/waf":$WAF_DIR:ro \
  -v "$ROOT/logs":/logs \
  "$IMG" >/dev/null
# 等待端口就绪（首次拉起在 CI/Docker Desktop 上可能明显慢于 restart）
ready=0
for i in $(seq 1 60); do
  if curl -s -o /dev/null http://127.0.0.1:18080/ 2>/dev/null; then ready=1; break; fi
  sleep 0.5
done
if [ "$ready" != "1" ]; then
  echo "FAIL: OpenResty did not become ready"
  docker logs "$NAME" 2>&1 | tail -40
  docker rm -f "$NAME" >/dev/null 2>&1
  exit 1
fi

req() { curl -s -o /dev/null -w "%{http_code}" "$@"; }

# 1. 白名单 IP：正常请求放行
check "whitelist-normal" 200 "$(req http://127.0.0.1:18080/)"
# 2. 白名单 IP：SQLi payload 也放行（allow 优先于检测）
check "whitelist-skips-detect" 200 "$(req "http://127.0.0.1:18080/login?id=1%20OR%201=1")"
# 3. 站点级路径黑名单（优先级更高，覆盖白名单放行）
check "site-rule-beats-allow" 403 "$(req http://127.0.0.1:18080/.git/config)"
# 4. Go 侧预编译的 exact 规则在没有慢规则命中时仍生效
check "compiled-site-rule" 403 "$(req http://127.0.0.1:18080/compiled-only)"
# 5. XFF 伪造黑名单 IP 不影响（名单基于 remote_addr，不可伪造）
check "xff-spoof-ignored" 200 "$(req -H "X-Forwarded-For: 9.9.9.9" http://127.0.0.1:18080/)"

# 6. 检测矩阵：把白名单 IP 换成非白名单不可行（物理同源），
#    改为临时移除白名单规则、重启容器来测检测管线
cat > "$RULES_FILE" <<'EOF'
{
  "global": {"rules": [
    {"id": 20, "name": "deny-banned", "priority": 10, "match_type": "ip", "match_value": "9.9.9.9", "match_op": "exact", "action": "deny", "enabled": true}
  ]},
  "sites": {"1": {"enabled": true,
    "rules": [],
    "cc": {"limit": 1000, "window": 60, "action": "deny", "byUri": false}
  }}
}
EOF
wait_up() {
  for i in $(seq 1 20); do
    curl -s -o /dev/null http://127.0.0.1:18080/ 2>/dev/null && return 0
    sleep 0.5
  done
  return 1
}
docker restart "$NAME" >/dev/null; wait_up

check "normal-pass"        200 "$(req http://127.0.0.1:18080/)"
check "sqli-403"           403 "$(req "http://127.0.0.1:18080/login?id=1%20OR%201=1")"
check "sqli-comment"       403 "$(req "http://127.0.0.1:18080/q?u=admin%27%20OR%20%271%27=%271%27--")"
check "union-select"       403 "$(req "http://127.0.0.1:18080/q?u=1%20UNION%20ALL%20SELECT%20*%20FROM%20users")"
check "xss-403"            403 "$(req "http://127.0.0.1:18080/q?x=%3Cscript%3Ealert(1)%3C/script%3E")"
check "lfi-403"            403 "$(req "http://127.0.0.1:18080/../../../../etc/passwd")"
check "double-encode-lfi"  403 "$(req "http://127.0.0.1:18080/%252e%252e%252fetc%252fpasswd")"
check "body-sqli-403"      403 "$(curl -s -o /dev/null -w "%{http_code}" -X POST -d "name=1' OR '1'='1" http://127.0.0.1:18080/submit)"
check "fp-natural-lang"    200 "$(req "http://127.0.0.1:18080/search?q=select%20your%20seats%20from%20the%20map")"
check "fp-js-doc"          200 "$(req "http://127.0.0.1:18080/read?p=learn%20javascript:%20basics")"

# 数据面启停：只替换 rules.json，不 reload/restart OpenResty。
sed 's/"sites": {"1": {"enabled": true/"sites": {"1": {"enabled": false/' "$RULES_FILE" > "$ROOT/rules.next"
cp "$ROOT/rules.next" "$RULES_FILE"; rm -f "$ROOT/rules.next"
sleep 6
check "site-disable-hot"   200 "$(req "http://127.0.0.1:18080/login?id=1%20OR%201=1")"
sed 's/"sites": {"1": {"enabled": false/"sites": {"1": {"enabled": true/' "$RULES_FILE" > "$ROOT/rules.next"
cp "$ROOT/rules.next" "$RULES_FILE"; rm -f "$ROOT/rules.next"
sleep 6
check "site-enable-hot"    403 "$(req "http://127.0.0.1:18080/login?id=1%20OR%201=1")"

if [ "${RUN_BENCHMARK:-0}" = "1" ] && command -v wrk >/dev/null 2>&1; then
  # Benchmark the P0 detection hot path without optional CC/bot/probe policies.
  cat > "$RULES_FILE" <<'EOF'
{"global":{"rules":[]},"sites":{"1":{"enabled":true,"rules":[]}}}
EOF
  sleep 2
  duration="${BENCH_DURATION:-5s}"
  # 交错测量 + 取中位数。
  #
  # 两个问题让早先的单轮串行测量完全不可信：
  #  1. 噪声：Docker Desktop 调度抖动大，曾出现 empty_lua 比 baseline
  #     还快 43% 的物理上不可能的数值。
  #  2. 漂移：三个配置串行测，期间机器负载（别的进程、CPU 降频）会变，
  #     后测的配置天然吃亏。
  # 交错让三个配置面对尽量相同的负载条件；中位数压掉离群值。
  rounds="${BENCH_ROUNDS:-5}"
  declare -a B E P
  for _ in $(seq 1 "$rounds"); do
    B+=("$(wrk -t2 -c50 -d"$duration" http://127.0.0.1:18081/ | awk '/Requests\/sec/ {print $2}')")
    E+=("$(wrk -t2 -c50 -d"$duration" http://127.0.0.1:18082/ | awk '/Requests\/sec/ {print $2}')")
    P+=("$(wrk -t2 -c50 -d"$duration" http://127.0.0.1:18080/ | awk '/Requests\/sec/ {print $2}')")
  done
  med() { printf '%s\n' "$@" | sort -n | awk '{a[NR]=$1} END {print a[int((NR+1)/2)]}'; }
  baseline=$(med "${B[@]}")
  empty_lua=$(med "${E[@]}")
  protected=$(med "${P[@]}")
  overhead=$(awk -v b="$baseline" -v p="$protected" 'BEGIN { if (b > 0) printf "%.2f", (b-p)*100/b; else print "nan" }')
  lua_overhead=$(awk -v b="$baseline" -v p="$empty_lua" 'BEGIN { if (b > 0) printf "%.2f", (b-p)*100/b; else print "nan" }')
  waf_overhead=$(awk -v e="$empty_lua" -v p="$protected" 'BEGIN { if (e > 0) printf "%.2f", (e-p)*100/e; else print "nan" }')
  echo "BENCHMARK baseline_rps=$baseline empty_lua_rps=$empty_lua protected_rps=$protected lua_hook_overhead_pct=$lua_overhead waf_logic_overhead_pct=$waf_overhead total_overhead_pct=$overhead"
fi

# CC 限流：单独阶段把 limit 调为 5 并重启清空计数器，第 6 次被拒
cat > "$RULES_FILE" <<'EOF'
{
  "global": {"rules": []},
  "sites": {"1": {"enabled": true, "rules": [], "cc": {"limit": 5, "window": 60, "action": "deny", "byUri": false}}}
}
EOF
wait_up() {
  for i in $(seq 1 20); do
    curl -s -o /dev/null http://127.0.0.1:18080/ 2>/dev/null && return 0
    sleep 0.5
  done
  return 1
}
docker restart "$NAME" >/dev/null; wait_up
cc6=""
for i in 1 2 3 4 5 6; do cc6=$(req "http://127.0.0.1:18080/cc$i"); done
check "cc-6th-403" 403 "$cc6"

# 事件日志落盘
sleep 0.3
events=$(wc -l < "$ROOT/logs/waf_events.log" 2>/dev/null | tr -d ' ')
if [ "${events:-0}" -ge 8 ]; then pass=$((pass+1)); else fail=$((fail+1)); echo "FAIL: events logged ($events < 8)"; fi
if grep -q '"attackType":"sqli"' "$ROOT/logs/waf_events.log" 2>/dev/null; then pass=$((pass+1)); else fail=$((fail+1)); echo "FAIL: no sqli event in log"; fi

echo "--- $pass passed, $fail failed"
if [ "${KEEP_CONTAINER:-0}" != "1" ]; then docker rm -f "$NAME" >/dev/null 2>&1; fi
[ "$fail" = "0" ]
