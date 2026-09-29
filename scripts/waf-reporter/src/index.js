// WAF 攻击上报 Worker。
//
// 3panel 实例检测到攻击并拦截后，可选地把该次拦截上报到这里。
// Worker 的作用不是"立刻封禁"，而是做去重与升格：
//
//   单实例单次  -> 只记录，不进任何黑名单
//   多实例多次  -> 达到阈值后进入候选池，供 CI 聚合时参考
//
// 这样做的原因是：开源面板的流量汇入中心库涉及信任与隐私问题，
// 且攻击源高度集中在云厂商 IDC 段，无差别封禁会误伤同样在用这些段的
// 正常用户。只有"多个互不相关的实例都报了这个 IP 确实是攻击源"，
// 才值得放进全局名单。
//
// 隐私约束（重要）：不接收也不存储 header / cookie / 请求体。
// 只保留检测引擎判定为攻击的那一个参数值（payload 截断），
// 以及定位问题所必需的 URL、攻击类型、来源实例哈希。

const REPORT_VERSION = 1;

// 单条上报的字段上限。超出即截断，避免有人把 WAF 当成免费存储。
const MAX_PAYLOAD = 512;
const MAX_URL = 1024;
const MAX_BODY = 16 * 1024;

// 每个 IP 需要多少个不同实例上报才升格为候选。
const CANDIDATE_MIN_REPORTS = 3;
// 候选的有效期（秒），过期自动清理。
const CANDIDATE_TTL = 30 * 24 * 3600;

/** @type {KVNamespace} */
let REPORTS;
/** @type {KVNamespace} */
let CANDIDATES;

// ---------- 入口 ----------

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    switch (url.pathname) {
      case '/report':
        return handleReport(request, env, ctx);
      case '/status':
        return handleStatus(env);
      case '/candidates':
        return handleCandidates(request, env);
      case '/candidates.txt':
        return handleCandidatesText(env);
      default:
        return json({ error: 'not found' }, 404);
    }
  },
};

/**
 * 上报入口。只接受 POST，避免被浏览器预取或爬虫 GET 触发。
 * 面板侧不携带凭证，靠上报内容的合理性做基本限流；
 * 真正的门槛是"多实例一致性"，单点刷量不会升格。
 */
async function handleReport(request, env, ctx) {
  if (request.method !== 'POST') {
    return json({ error: 'method not allowed' }, 405);
  }

  // 这里是 3panel 面板服务器的出口 IP，不是攻击者 IP。
  // 面板部署在云上时它与被攻击站点毫无关系，只作审计留痕，
  // 绝不能拿它去校验上报的 ip（早先正是这么写的，导致上报 100% 失效）。
  const reporterIP = clientIP(request);
  if (!reporterIP) {
    return json({ error: 'no client ip' }, 400);
  }

  let payload;
  try {
    payload = await request.json();
  } catch {
    return json({ error: 'invalid json' }, 400);
  }

  const report = normalize(payload, reporterIP);
  if (!report) {
    return json({ error: 'invalid report' }, 400);
  }

  // 以 (来源实例, 被攻击者 IP, 攻击类型) 为键去重。
  // 同一个实例对同一个 IP 的重复扫描只计一次，否则单个实例就能刷够阈值。
  const dedupKey = `r:${report.panelId}:${report.ip}:${report.attackType}`;

  const already = await env.REPORTS.get(dedupKey);
  if (already) {
    return json({ ok: true, duplicate: true });
  }

  await env.REPORTS.put(dedupKey, JSON.stringify(report), { expirationTtl: CANDIDATE_TTL });

  // 每个实例一个槽位 key，天然幂等：同一实例重复上报只会覆盖自己的槽位。
  const slotKey = `slot:${report.ip}:${report.panelId}`;
  const alreadyCounted = await env.REPORTS.get(slotKey);
  if (alreadyCounted === null || alreadyCounted === undefined) {
    await env.REPORTS.put(slotKey, String(Date.now()), { expirationTtl: CANDIDATE_TTL });
  }

  // 统计该 IP 有多少个不同实例报过。
  //
  // 不能靠 list() 计数：Cloudflare KV 的写入对 list 也有最长约 60s 的
  // 最终一致延迟，刚 put 的槽位立刻列举不到（实测 distinctPanels 恒为 1，
  // 永远升不了格）。改用「候选记录自带计数 + 定期对账」：
  // 每次上报都把当前计数推高（至多 +1），并把 panelId 记入 seen 列表，
  // 列表长度才是权威值。seen 有上限，避免单个 IP 无限增长。
  const MIN = Number(env.CANDIDATE_MIN_REPORTS || CANDIDATE_MIN_REPORTS);
  const candKey = `c:${report.ip}`;
  const prev = (await env.CANDIDATES.get(candKey, 'json')) || {
    ip: report.ip, reports: 0, firstSeen: Date.now(), attackTypes: [], seen: [],
  };
  if (!prev.seen.includes(report.panelId)) {
    prev.seen.push(report.panelId);
    if (prev.seen.length > 200) prev.seen = prev.seen.slice(-200);
    prev.lastSeen = Date.now();
    if (!prev.attackTypes.includes(report.attackType)) {
      prev.attackTypes.push(report.attackType);
      if (prev.attackTypes.length > 10) prev.attackTypes = prev.attackTypes.slice(-10);
    }
  }
  prev.reports = prev.seen.length;
  await env.CANDIDATES.put(candKey, JSON.stringify(prev), { expirationTtl: CANDIDATE_TTL });
  const distinct = prev.seen.length;
  const promoted = distinct >= MIN;

  ctx.waitUntil(Promise.resolve());
  return json({ ok: true, distinctPanels: distinct, promoted });
}

/** 运维查看当前状态。 */
async function handleStatus(env) {
  const candidates = await listCandidates(env);
  return json({
    candidates: candidates.length,
    recent: candidates.slice(0, 20),
  });
}

/** 候选池（JSON），供 CI 聚合时拉取。 */
async function handleCandidates(request, env) {
  const url = new URL(request.url);
  const min = Number(url.searchParams.get('min') || CANDIDATE_MIN_REPORTS);
  const all = await listCandidates(env);
  return json({ count: all.length, candidates: all.filter((c) => c.reports >= min) });
}

/**
 * 候选池（纯文本，一行一个 IP），CI 直接并入聚合。
 *
 * 必须按 min 过滤：这个文件是 CI 无人工介入直接吞进全局名单的，
 * 若把只报过一次的 IP 也输出，单个实例就能往全局黑名单塞任意地址。
 */
async function handleCandidatesText(env) {
  const min = Number(env.CANDIDATE_MIN_REPORTS || CANDIDATE_MIN_REPORTS);
  const all = await listCandidates(env);
  const body = all.filter((c) => c.reports >= min).map((c) => c.ip).join('\n');
  return new Response(body + '\n', {
    headers: {
      'content-type': 'text/plain; charset=utf-8',
      'access-control-allow-origin': '*',
      'x-candidate-count': String(all.filter((c) => c.reports >= min).length),
    },
  });
}

async function listCandidates(env) {
  const out = [];
  let cursor;
  let complete = false;
  // KV 单次 list 最多 1000 条，这里翻页取全量。
  while (!complete) {
    const res = await env.CANDIDATES.list(cursor ? { cursor } : undefined);
    for (const item of res.keys) {
      // 键格式 c:<ip>，去前缀后才是 IP 本身
      if (!item.name.startsWith('c:')) continue;
      const v = await env.CANDIDATES.get(item.name, 'json');
      if (v) out.push(v);
    }
    complete = !!res.list_complete || !res.cursor || res.cursor === cursor;
    cursor = res.cursor;
  }
  return out;
}

// ---------- 校验与归一化 ----------

/**
 * 校验并裁剪上报内容。
 *
 * 只接受有限的白名单字段；payload 与 url 截断到上限。
 * 显式丢弃 header / cookie / body —— 即使面板侧误传也不入库。
 */
function normalize(input, fallbackIP) {
  if (!input || typeof input !== 'object') return null;

  const panelId = str(input.panelId, 64);
  const attackType = str(input.attackType, 32);
  // ip 是「被检测到的攻击源 IP」，由面板从 WAF 日志的 remote_addr 取得，
  // 与本 Worker 看到的请求来源（面板服务器 IP）无关，因此不能做等值校验。
  //
  // 安全前提：panelId 未经验签，任何人都能伪造上报。当前设计依赖
  // 「候选池只作参考、不自动进全局名单」来限制危害；若改成自动封禁，
  // 必须先加 HMAC 签名（每实例独立密钥，Worker 持有验证材料）。
  const ip = normalizeIP(input.ip);
  if (!panelId || !attackType || !ip) return null;

  return {
    v: REPORT_VERSION,
    ip,
    panelId,
    attackType,
    url: str(input.url, MAX_URL),
    payload: str(input.payload, MAX_PAYLOAD),
    ua: str(input.ua, 256),
    method: str(input.method, 16),
    website: str(input.website, 128), // 站点标识（面板生成的哈希，非域名）
    reporter: fallbackIP,            // 上报面板的出口 IP，仅供审计
    ts: Date.now(),
  };
}

function str(v, max) {
  if (typeof v !== 'string') return '';
  return v.length > max ? v.slice(0, max) : v;
}

function normalizeIP(v) {
  if (typeof v !== 'string' || v.length > 45) return '';
  // Cloudflare 可能给出 "1.2.3.4:5678" 形式
  const ip = v.includes(':') && v.split(':').length === 2 ? v.split(':')[0] : v;
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(ip)) return ip;
  if (/^[0-9a-fA-F:]+$/.test(ip) && ip.includes(':')) return ip;
  return '';
}

function clientIP(request) {
  return request.headers.get('CF-Connecting-IP') || '';
}

function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'access-control-allow-origin': '*',
    },
  });
}
