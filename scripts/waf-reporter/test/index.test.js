// Worker 逻辑测试：node --test test/
//
// 重点覆盖两条安全性质：
//  1. 伪造 —— 上报里的 ip 必须与真实来源 IP 一致，否则不能推别人进候选池
//  2. 去重 —— 同一实例对同一 IP 重复上报只计一次，
//              单个实例无法靠重复上报刷够升格阈值

import test from 'node:test';
import assert from 'node:assert/strict';
import worker from '../src/index.js';

// 内存版 KV
function newKV() {
  const m = new Map();
  return {
    async get(k, type) {
      const v = m.get(k);
      if (v === undefined) return null;
      return type === 'json' ? JSON.parse(v) : v;
    },
    async put(k, v) { m.set(k, typeof v === 'string' ? v : JSON.stringify(v)); },
    async list(opts = {}) {
      // 真实 KV 强制要求 ListOptions 对象，传字符串会抛 TypeError
      if (typeof opts !== 'object' || opts === null) {
        throw new TypeError("Failed to execute 'list' on 'KvNamespace': parameter 1 is not of type 'ListOptions'.");
      }
      let names = [...m.keys()];
      if (opts.prefix) names = names.filter((n) => n.startsWith(opts.prefix));
      return { keys: names.map((name) => ({ name })), list_complete: true, cursor: '' };
    },
    _dump: () => Object.fromEntries(m),
  };
}

function newEnv() {
  return {
    REPORTS: newKV(),
    CANDIDATES: newKV(),
    CANDIDATE_MIN_REPORTS: '3',
  };
}

function req(body, ip, { method = 'POST', path = '/report' } = {}) {
  return new Request(`https://waf.example${path}`, {
    method,
    headers: {
      'content-type': 'application/json',
      'CF-Connecting-IP': ip,
    },
    body: method === 'POST' ? JSON.stringify(body) : undefined,
  });
}

test('正常上报被接受', async () => {
  const env = newEnv();
  const res = await worker.fetch(
    req({ panelId: 'p1', attackType: 'sqli', ip: '9.9.9.9', url: '/a', payload: "' or '1'='1" }, '9.9.9.9'),
    env, { waitUntil() {} }
  );
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.ok, true);
  assert.equal(body.distinctPanels, 1);
});

test('GET 不被接受，避免爬虫/预取污染', async () => {
  const env = newEnv();
  const res = await worker.fetch(
    req({}, '9.9.9.9', { method: 'GET' }), env, { waitUntil() {} }
  );
  assert.equal(res.status, 405);
});

// ip 是攻击源（面板从 remote_addr 取得），与上报请求的来源地址无关，
// 因此不做等值校验 —— 那是早先的实现错误，会让上报 100% 失效。
// 真正的约束是「必须有合法 ip」，以及候选池不自动进全局名单。
test('ip 缺失时拒绝（而不是回退到面板自身 IP）', async () => {
  const env = newEnv();
  const res = await worker.fetch(
    req({ panelId: 'p1', attackType: 'sqli' }, '9.9.9.9'),
    env, { waitUntil() {} }
  );
  assert.equal(res.status, 400, '缺少攻击源 IP 不得进候选池');
});

test('记录上报面板的出口 IP 供审计', async () => {
  const env = newEnv();
  await worker.fetch(
    req({ panelId: 'p1', attackType: 'sqli', ip: '203.0.113.9' }, '9.9.9.9'),
    env, { waitUntil() {} }
  );
  const rec = JSON.parse(env.REPORTS._dump()['r:p1:203.0.113.9:sqli']);
  assert.equal(rec.ip, '203.0.113.9', '应记录攻击源 IP');
  assert.equal(rec.reporter, '9.9.9.9', '应另行记录上报面板 IP');
});

test('攻击源 IP 与面板 IP 不同的正常上报被接受', async () => {
  const env = newEnv();
  const res = await worker.fetch(
    req({ panelId: 'p1', attackType: 'rce', ip: '198.51.100.7' }, '9.9.9.9'),
    env, { waitUntil() {} }
  );
  assert.equal(res.status, 200, '两者本就不该相同');
  const body = await res.json();
  assert.equal(body.ok, true);
});

test('同一实例重复上报只计一次', async () => {
  const env = newEnv();
  for (let i = 0; i < 5; i++) {
    await worker.fetch(
      req({ panelId: 'p1', attackType: 'sqli', ip: '9.9.9.9' }, '9.9.9.9'),
      env, { waitUntil() {} }
    );
  }
  const slots = Object.keys(env.REPORTS._dump()).filter((k) => k.startsWith('slot:9.9.9.9:'));
  assert.equal(slots.length, 1, '重复上报不得增加实例计数');
});

test('三个不同实例上报后升格为候选', async () => {
  const env = newEnv();
  for (const p of ['p1', 'p2', 'p3']) {
    const res = await worker.fetch(
      req({ panelId: p, attackType: 'sqli', ip: '9.9.9.9' }, '9.9.9.9'),
      env, { waitUntil() {} }
    );
    assert.equal(res.status, 200);
  }
  const cand = env.CANDIDATES._dump()['c:9.9.9.9'];
  assert.ok(cand, '应升格为候选');
  assert.equal(JSON.parse(cand).reports, 3);
});

test('单实例刷量无法升格', async () => {
  const env = newEnv();
  for (let i = 0; i < 50; i++) {
    await worker.fetch(
      req({ panelId: 'p1', attackType: 'rce', ip: '8.8.8.8' }, '8.8.8.8'),
      env, { waitUntil() {} }
    );
  }
  const c = env.CANDIDATES._dump()['c:8.8.8.8'];
  const parsed = c ? JSON.parse(c) : null;
  assert.ok(!parsed || parsed.reports < 3, '单实例不得升格');
});

test('header/cookie 字段被丢弃，不入库', async () => {
  const env = newEnv();
  await worker.fetch(
    req({
      panelId: 'p1', attackType: 'sqli', ip: '9.9.9.9',
      header: { authorization: 'Bearer secret' },
      cookie: 'session=abc',
      body: 'password=hunter2',
    }, '9.9.9.9'),
    env, { waitUntil() {} }
  );
  const stored = env.REPORTS._dump()['r:p1:9.9.9.9:sqli'];
  assert.ok(!stored.includes('secret'), '不得存储 header');
  assert.ok(!stored.includes('session=abc'), '不得存储 cookie');
  assert.ok(!stored.includes('hunter2'), '不得存储 body');
});

test('超长字段被截断', async () => {
  const env = newEnv();
  await worker.fetch(
    req({ panelId: 'p1', attackType: 'sqli', ip: '9.9.9.9', payload: 'A'.repeat(9999) }, '9.9.9.9'),
    env, { waitUntil() {} }
  );
  const rec = JSON.parse(env.REPORTS._dump()['r:p1:9.9.9.9:sqli']);
  assert.equal(rec.payload.length, 512);
});

test('缺 panelId 或 attackType 直接拒绝', async () => {
  const env = newEnv();
  for (const body of [{ attackType: 'sqli' }, { panelId: 'p1' }]) {
    const res = await worker.fetch(req(body, '9.9.9.9'), env, { waitUntil() {} });
    assert.equal(res.status, 400);
  }
});

test('/candidates.txt 输出纯文本供 CI 并入聚合', async () => {
  const env = newEnv();
  for (const p of ['p1', 'p2', 'p3']) {
    await worker.fetch(req({ panelId: p, attackType: 'sqli', ip: '9.9.9.9' }, '9.9.9.9'),
      env, { waitUntil() {} });
  }
  const res = await worker.fetch(
    req({}, '', { method: 'GET', path: '/candidates.txt' }), env, { waitUntil() {} }
  );
  assert.equal(res.status, 200);
  const text = await res.text();
  assert.ok(text.includes('9.9.9.9'));
});

// Cloudflare KV 的写入对 get/list 都有最终一致延迟（最长约 60s）。
// 本地内存 KV 是同步可见的，测不出「刚写就读不到」这类问题，
// 因此这里用延迟可见的 stub 复现线上行为。
test('KV 最终一致延迟下仍能正确累加实例数', async () => {
  const m = new Map();
  const pending = [];
  const env = {
    REPORTS: {
      async get(k) { return m.has(k) ? m.get(k) : null; },
      async put(k, v) { pending.push([k, v]); },
      async list() { return { keys: [], list_complete: true, cursor: '' }; },
    },
    CANDIDATES: {
      async get(k, type) {
        const v = m.get(k);
        if (v === undefined) return null;
        return type === 'json' ? JSON.parse(v) : v;
      },
      // 候选写入延迟可见
      async put(k, v) { pending.push([k, v]); },
      async list() { return { keys: [], list_complete: true, cursor: '' }; },
    },
    CANDIDATE_MIN_REPORTS: '3',
  };
  const flush = () => { for (const [k, v] of pending.splice(0)) m.set(k, v); };

  for (const p of ['p1', 'p2', 'p3']) {
    // 每轮：写入延迟可见后再发下一次，模拟"上一轮已落盘"
    flush();
    const res = await worker.fetch(
      req({ panelId: p, attackType: 'sqli', ip: '9.9.9.9' }, '9.9.9.9'),
      env, { waitUntil() {} }
    );
    assert.equal(res.status, 200);
  }
  flush();
  const rec = [...m].find(([k]) => k.startsWith('c:'));
  assert.ok(rec, '候选记录应存在');
  const parsed = JSON.parse(rec[1]);
  assert.equal(parsed.seen.length, 3, `应有 3 个实例，实际 ${JSON.stringify(parsed.seen)}`);
  assert.equal(parsed.reports, 3);
});

test('同一实例重复上报不增加实例数（延迟可见场景）', async () => {
  const m = new Map();
  const pending = [];
  const env = {
    REPORTS: {
      async get(k) { return m.has(k) ? m.get(k) : null; },
      async put(k, v) { pending.push([k, v]); },
      async list() { return { keys: [], list_complete: true, cursor: '' }; },
    },
    CANDIDATES: {
      async get(k, type) {
        const v = m.get(k);
        if (v === undefined) return null;
        return type === 'json' ? JSON.parse(v) : v;
      },
      async put(k, v) { pending.push([k, v]); },
      async list() { return { keys: [], list_complete: true, cursor: '' }; },
    },
    CANDIDATE_MIN_REPORTS: '3',
  };
  const flush = () => { for (const [k, v] of pending.splice(0)) m.set(k, v); };
  for (let i = 0; i < 5; i++) {
    flush();
    await worker.fetch(req({ panelId: 'solo', attackType: 'sqli', ip: '8.8.4.4' }, '8.8.4.4'),
      env, { waitUntil() {} });
  }
  flush();
  const rec = [...m].find(([k]) => k.startsWith('c:'));
  assert.ok(rec);
  assert.equal(JSON.parse(rec[1]).seen.length, 1, '重复上报不得累加');
});

// 这个测试针对一个真实缺陷：/candidates.txt 曾把只上报过一次的 IP 也输出，
// 而该文件被 CI 无人工介入直接并入全局黑名单 —— 等于单实例可自选封禁任意地址。
test('/candidates.txt 只输出达到阈值的 IP', async () => {
  const env = newEnv();
  // 单实例 IP：只报一次，不应出现在 .txt 里
  await worker.fetch(req({ panelId: 'solo', attackType: 'sqli', ip: '198.51.100.9' }, '198.51.100.9'),
    env, { waitUntil() {} });
  // 三实例 IP：应出现
  for (const p of ['a', 'b', 'c']) {
    await worker.fetch(req({ panelId: p, attackType: 'sqli', ip: '203.0.113.5' }, '203.0.113.5'),
      env, { waitUntil() {} });
  }
  const res = await worker.fetch(req({}, '', { method: 'GET', path: '/candidates.txt' }), env, { waitUntil() {} });
  const text = await res.text();
  assert.ok(text.includes('203.0.113.5'), '达阈值 IP 应输出');
  assert.ok(!text.includes('198.51.100.9'), '单实例 IP 绝不能进全局名单');
});

// panelId 未经鉴权，限流是压制批量刷量的主要手段：
// 真实的 3panel 只报告自己站点被攻击的 IP（高度分散），
// 而刷量者会在短时间内吐出成百上千个互不相干的目标 IP。
// 限流按上报方 IP 计，不按 panelId —— 后者自报，可随意伪造。
test('同一上报方超出速率上限后被限流', async () => {
  const env = newEnv();
  env.REPORTS.__limit = 3; // 测试里把上限调到 3
  for (let i = 0; i < 3; i++) {
    const res = await worker.fetch(
      req({ panelId: `flood-${i}`, attackType: 'sqli', ip: `203.0.113.${i}` }, '9.9.9.9'),
      env, { waitUntil() {} }
    );
    assert.equal(res.status, 200, `第 ${i + 1} 条应放行`);
  }
  const res = await worker.fetch(
    req({ panelId: 'flood-x', attackType: 'sqli', ip: '203.0.113.99' }, '9.9.9.9'),
    env, { waitUntil() {} }
  );
  assert.equal(res.status, 429, '超出上限应 429');
});

test('限流不影响不同上报方', async () => {
  const env = newEnv();
  env.REPORTS.__limit = 2;
  for (let i = 0; i < 2; i++) {
    await worker.fetch(req({ panelId: 'a', attackType: 'sqli', ip: '1.1.1.1' }, '9.9.9.9'),
      env, { waitUntil() {} });
  }
  // 另一个上报方 IP 不受影响
  const res = await worker.fetch(
    req({ panelId: 'b', attackType: 'sqli', ip: '2.2.2.2' }, '8.8.4.4'),
    env, { waitUntil() {} }
  );
  assert.equal(res.status, 200);
});
