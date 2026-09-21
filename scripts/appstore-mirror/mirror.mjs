#!/usr/bin/env node
/**
 * Mirror the upstream 1Panel app store into a Cloudsmith Generic repository.
 *
 * Run it locally (no subrequest limits, unlike a Cloudflare Worker):
 *
 *   cd scripts/appstore-mirror
 *   cp .env.example .env      # fill in your Cloudsmith credentials
 *   node --env-file=.env mirror.mjs
 *
 * What the panel actually requests from your domain — all of it has to exist:
 *
 *   {DST}/{mode}/3panel.json.zip                       store index (zip entry named 3panel.json)
 *   {DST}/{mode}/3panel.json.version.txt               version stamp
 *   {DST}/{mode}/3panel/{app}/logo.png                 app icon
 *   {DST}/{mode}/3panel/{app}/{ver}/docker-compose.yml needed for EVERY app type
 *   {DST}/{mode}/3panel/{app}/{ver}/{app}-{ver}.tar.gz app package (downloadUrl)
 *
 * Two details that are easy to get wrong and that this script handles:
 *
 *  1. Icons and packages are referenced by ABSOLUTE urls inside the store JSON, so the JSON is
 *     rewritten while mirroring — otherwise the panel keeps talking to the upstream host.
 *  2. The panel fetches docker-compose.yml for ANY app whose local compose cache is empty
 *     (agent/app/service/app.go). It is not limited to runtime/php/node apps: mirroring it only
 *     for those types makes every other install page fail with ErrAppVersionUnavailable
 *     ("当前应用版本已从远程服务下架"). This script mirrors it for every app + version.
 */

import { deflateRawSync, inflateRawSync } from 'node:zlib';
import { existsSync, readFileSync, writeFileSync, promises as fs } from 'node:fs';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const STATE_FILE = join(HERE, '.mirror-state.json');
const execFileAsync = promisify(execFile);

/* ------------------------------------------------------------------ config */

const argv = new Set(process.argv.slice(2));
const hasFlag = (name) => argv.has(`--${name}`);

const trimSlash = (value) => String(value || '').replace(/\/+$/, '');
const num = (value, fallback) => {
    const parsed = Number(value);
    return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
};

const cfg = {
    repository: process.env.CLOUDSMITH_REPOSITORY || '3panel/3panel',
    apiKey: process.env.CLOUDSMITH_API_KEY || process.env.CS_TOKEN || '',
    mode: process.env.MODE || 'stable',
    src: trimSlash(process.env.SRC_ORIGIN || 'https://apps.1panel.pro'),
    dst: trimSlash(process.env.DST_ORIGIN || 'https://generic.cloudsmith.io/3panel/3panel'),

    concurrency: num(process.env.CONCURRENCY, 6),
    packages: process.env.SYNC_APP_PACKAGES !== 'false',
    dataYml: process.env.SYNC_DATA_YML !== 'false',
    // Per-request cap (headers + body). Without it a stalled transfer keeps a worker busy
    // forever; app packages reach ~80 MB, so this is generous on purpose.
    timeoutMs: num(process.env.TIMEOUT_MS, 300000),

    force: hasFlag('force'),
    dryRun: hasFlag('dry-run'),
    verifyOnly: hasFlag('verify-only'),
    limit: num(process.env.LIMIT || (argv.has('--limit') ? process.argv[process.argv.indexOf('--limit') + 1] : 0), 0),
};

/* ------------------------------------------------------------------- utils */

const log = (...parts) => console.log(...parts);
const warn = (...parts) => console.warn(...parts);
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const RETRYABLE = new Set([403, 408, 425, 429, 500, 502, 503, 504]);

/** Fetch with backoff. `null` means the upstream said 404 (a genuine gap, not an error). */
async function fetchWithRetry(url, headers = {}, attempts = 4) {
    let reason = 'unknown';
    for (let attempt = 0; attempt < attempts; attempt++) {
        if (attempt > 0) await sleep(500 * 2 ** (attempt - 1));
        try {
            const res = await fetch(url, {
                headers,
                redirect: 'follow',
                signal: AbortSignal.timeout(cfg.timeoutMs),
            });
            if (res.status === 404) return { missing: true };
            if (res.ok || res.status === 304) return { res };
            reason = `HTTP ${res.status}`;
            if (!RETRYABLE.has(res.status)) return { failed: reason };
        } catch (err) {
            reason = err.message;
        }
    }
    return { failed: reason };
}

/** Bounded-concurrency pool. */
async function runPool(items, concurrency, handler) {
    let cursor = 0;
    const size = Math.max(1, Math.min(concurrency, items.length));
    await Promise.all(
        Array.from({ length: size }, async () => {
            while (cursor < items.length) {
                const index = cursor++;
                await handler(items[index], index);
            }
        }),
    );
}

function contentTypeFor(key) {
    if (key.endsWith('.png')) return 'image/png';
    if (key.endsWith('.jpg') || key.endsWith('.jpeg')) return 'image/jpeg';
    if (key.endsWith('.svg')) return 'image/svg+xml';
    if (key.endsWith('.zip')) return 'application/zip';
    if (key.endsWith('.json')) return 'application/json; charset=utf-8';
    if (key.endsWith('.yml') || key.endsWith('.yaml')) return 'text/yaml; charset=utf-8';
    if (key.endsWith('.txt')) return 'text/plain; charset=utf-8';
    if (key.endsWith('.tar.gz') || key.endsWith('.tgz')) return 'application/gzip';
    return 'application/octet-stream';
}

/** Map an upstream asset url onto the bucket key the panel will request. */
function assetKey(url, mode) {
    const { pathname } = new URL(url);
    return pathname.replace(`/${mode}/1panel/`, `/${mode}/3panel/`).replace(/^\//, '');
}

/* --------------------------------------------------------------- zip codec */

const ZIP_LOCAL = 0x04034b50;
const ZIP_CENTRAL = 0x02014b50;
const ZIP_EOCD = 0x06054b50;

/** Read one entry out of a zip archive (sizes taken from the central directory). */
function readZipEntry(bytes, wanted) {
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);

    let eocd = -1;
    const lowerBound = Math.max(0, bytes.length - 22 - 0xffff);
    for (let i = bytes.length - 22; i >= lowerBound; i--) {
        if (view.getUint32(i, true) === ZIP_EOCD) {
            eocd = i;
            break;
        }
    }
    if (eocd < 0) throw new Error('zip: EOCD not found');

    const total = view.getUint16(eocd + 10, true);
    let ptr = view.getUint32(eocd + 16, true);

    for (let i = 0; i < total; i++) {
        if (view.getUint32(ptr, true) !== ZIP_CENTRAL) throw new Error('zip: bad central directory');
        const method = view.getUint16(ptr + 10, true);
        const compSize = view.getUint32(ptr + 20, true);
        const nameLen = view.getUint16(ptr + 28, true);
        const extraLen = view.getUint16(ptr + 30, true);
        const commentLen = view.getUint16(ptr + 32, true);
        const localOffset = view.getUint32(ptr + 42, true);
        const name = new TextDecoder().decode(bytes.subarray(ptr + 46, ptr + 46 + nameLen));

        if (!wanted || name === wanted || name.endsWith('/' + wanted)) {
            if (view.getUint32(localOffset, true) !== ZIP_LOCAL) throw new Error('zip: bad local header');
            const lNameLen = view.getUint16(localOffset + 26, true);
            const lExtraLen = view.getUint16(localOffset + 28, true);
            const dataStart = localOffset + 30 + lNameLen + lExtraLen;
            const data = bytes.subarray(dataStart, dataStart + compSize);
            return { name, method, data: method === 8 ? inflateRawSync(data) : data };
        }
        ptr += 46 + nameLen + extraLen + commentLen;
    }
    throw new Error(`zip: entry ${wanted || '*'} not found`);
}

let CRC_TABLE = null;
function crc32(bytes) {
    if (!CRC_TABLE) {
        CRC_TABLE = new Uint32Array(256);
        for (let i = 0; i < 256; i++) {
            let c = i;
            for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
            CRC_TABLE[i] = c >>> 0;
        }
    }
    let c = 0xffffffff;
    for (let i = 0; i < bytes.length; i++) c = CRC_TABLE[(c ^ bytes[i]) & 0xff] ^ (c >>> 8);
    return (c ^ 0xffffffff) >>> 0;
}

/** Build a single-entry zip archive. */
function buildZipEntry(name, content) {
    const nameBytes = new TextEncoder().encode(name);
    const compressed = deflateRawSync(content);
    const crc = crc32(content);

    const now = new Date();
    const dosTime = ((now.getHours() << 11) | (now.getMinutes() << 5) | (now.getSeconds() >> 1)) & 0xffff;
    const dosDate = (((now.getFullYear() - 1980) << 9) | ((now.getMonth() + 1) << 5) | now.getDate()) & 0xffff;

    const local = Buffer.alloc(30 + nameBytes.length + compressed.length);
    local.writeUInt32LE(ZIP_LOCAL, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(0, 6);
    local.writeUInt16LE(8, 8);
    local.writeUInt16LE(dosTime, 10);
    local.writeUInt16LE(dosDate, 12);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(compressed.length, 18);
    local.writeUInt32LE(content.length, 22);
    local.writeUInt16LE(nameBytes.length, 26);
    local.writeUInt16LE(0, 28);
    Buffer.from(nameBytes).copy(local, 30);
    compressed.copy(local, 30 + nameBytes.length);

    const central = Buffer.alloc(46 + nameBytes.length);
    central.writeUInt32LE(ZIP_CENTRAL, 0);
    central.writeUInt16LE(20, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(0, 8);
    central.writeUInt16LE(8, 10);
    central.writeUInt16LE(dosTime, 12);
    central.writeUInt16LE(dosDate, 14);
    central.writeUInt32LE(crc, 16);
    central.writeUInt32LE(compressed.length, 20);
    central.writeUInt32LE(content.length, 24);
    central.writeUInt16LE(nameBytes.length, 28);
    central.writeUInt16LE(0, 30);
    central.writeUInt16LE(0, 32);
    central.writeUInt16LE(0, 34);
    central.writeUInt16LE(0, 36);
    central.writeUInt32LE(0, 38);
    central.writeUInt32LE(0, 42);
    Buffer.from(nameBytes).copy(central, 46);

    const eocd = Buffer.alloc(22);
    eocd.writeUInt32LE(ZIP_EOCD, 0);
    eocd.writeUInt16LE(1, 8);
    eocd.writeUInt16LE(1, 10);
    eocd.writeUInt32LE(central.length, 12);
    eocd.writeUInt32LE(local.length, 16);

    return Buffer.concat([local, central, eocd]);
}

/* ---------------------------------------------------------- Cloudsmith I/O */

async function connectBucket() {
    return {
        async put(key, body, contentType) {
            const bytes = Buffer.isBuffer(body) ? body : Buffer.from(body);
            const temp = await fs.mkdtemp('/tmp/3panel-cloudsmith-');
            const file = join(temp, key.split('/').pop());
            try {
                await fs.writeFile(file, bytes);
                const env = cfg.apiKey ? { ...process.env, CLOUDSMITH_API_KEY: cfg.apiKey } : process.env;
                try {
                    await execFileAsync('cloudsmith', ['push', 'generic', cfg.repository, file, '--filepath', key, '--republish'], { env });
                } catch (err) {
                    const detail = [err.stdout, err.stderr].filter(Boolean).join('\n').trim();
                    throw new Error(`Cloudsmith upload ${key} failed${detail ? `:\n${detail}` : ''}`);
                }
            } finally {
                await fs.rm(temp, { recursive: true, force: true });
            }
        },
        async has(key) {
            return (await fetch(`${cfg.dst}/${key}`, { method: 'HEAD' })).ok;
        },
        async text(key) {
            const res = await fetch(`${cfg.dst}/${key}`);
            return res.ok ? res.text() : null;
        },
        // Cloudsmith Generic has no unauthenticated prefix-list endpoint. Callers test the
        // exact file paths they need, which also works on a fresh GitHub Actions runner.
        async list(prefix) {
            return new Set();
        },
    };
}

/** Upload with retries — R2 occasionally drops a connection mid PUT. */
async function putObject(bucket, key, bytes, contentType, attempts = 3) {
    let reason = 'unknown';
    for (let attempt = 0; attempt < attempts; attempt++) {
        if (attempt > 0) await sleep(500 * 2 ** (attempt - 1));
        try {
            await bucket.put(key, bytes, contentType);
            return { ok: true };
        } catch (err) {
            reason = err.message;
        }
    }
    return { ok: false, reason };
}

/* -------------------------------------------------------------------- main */

function loadState() {
    try {
        return JSON.parse(readFileSync(STATE_FILE, 'utf8'));
    } catch {
        return {};
    }
}

/** Everything the store JSON points at, before the JSON is rewritten. */
function buildManifest(store, mode, src) {
    const items = new Map();
    const push = (url) => {
        if (!url) return;
        const key = assetKey(url, mode);
        if (!items.has(key)) items.set(key, { url, key });
    };

    for (const app of store.apps || []) {
        const props = app.additionalProperties || {};
        const appKey = props.key;
        push(app.icon);

        for (const version of app.versions || []) {
            if (appKey && version.name) {
                const dir = `${src}/${mode}/1panel/${appKey}/${version.name}`;
                push(`${dir}/docker-compose.yml`);
                if (cfg.dataYml) push(`${dir}/data.yml`);
            }
            if (cfg.packages && version.downloadUrl) push(version.downloadUrl);
        }
    }
    return [...items.values()];
}

async function main() {
    if (!cfg.dst) throw new Error('DST_ORIGIN is required (public url of your bucket, e.g. https://generic.cloudsmith.io/3panel/3panel)');

    log(`[mirror] source : ${cfg.src}/${cfg.mode}`);
    log(`[mirror] target : ${cfg.dst}/${cfg.mode}`);
    log(`[mirror] mode   : ${cfg.dryRun ? 'DRY RUN (no upload)' : 'upload'}${cfg.force ? ' + force' : ''}`);

    // 1. version stamp + store index
    const versionUrl = `${cfg.src}/${cfg.mode}/1panel.json.version.txt`;
    const versionRes = await fetchWithRetry(versionUrl);
    if (!versionRes.res) throw new Error(`cannot read ${versionUrl}: ${versionRes.failed || 'HTTP 404'}`);
    const version = (await versionRes.res.text()).trim();

    const zipUrl = `${cfg.src}/${cfg.mode}/1panel.json.zip`;
    const zipRes = await fetchWithRetry(zipUrl);
    if (!zipRes.res) throw new Error(`cannot read ${zipUrl}: ${zipRes.failed || 'HTTP 404'}`);
    const entry = readZipEntry(Buffer.from(await zipRes.res.arrayBuffer()), '1panel.json');
    const storeText = entry.data.toString('utf8');
    const store = JSON.parse(storeText);

    const manifest = buildManifest(store, cfg.mode, cfg.src);
    log(`[mirror] upstream version ${version}, ${store.apps?.length || 0} apps, ${manifest.length} assets to mirror`);

    // 2. rewrite every absolute url onto our own domain. Nothing inside the published index may
    //    point back at the upstream host: the mirror is the single source the panel talks to.
    const rewritten = storeText
        .split(`${cfg.src}/${cfg.mode}/1panel/`)
        .join(`${cfg.dst}/${cfg.mode}/3panel/`)
        .split(cfg.src)
        .join(cfg.dst);

    const indexKey = `${cfg.mode}/3panel.json.zip`;
    const versionKey = `${cfg.mode}/3panel.json.version.txt`;

    if (cfg.verifyOnly) {
        return verify(indexKey, manifest);
    }

    const bucket = cfg.dryRun ? null : await connectBucket();
    const state = loadState();
    const publishedVersion = bucket && !cfg.force ? await bucket.text(versionKey) : null;
    if (!cfg.dryRun && publishedVersion?.trim() !== version) {
        await bucket.put(indexKey, buildZipEntry('3panel.json', Buffer.from(rewritten, 'utf8')), 'application/zip');
        await bucket.put(versionKey, version, 'text/plain; charset=utf-8');
        log(`[mirror] published ${indexKey} (entry: 3panel.json) + ${versionKey}`);
    } else if (!cfg.dryRun) {
        log(`[mirror] index already matches upstream version ${version}`);
    }

    // 3. mirror assets
    const items = cfg.limit ? manifest.slice(0, cfg.limit) : manifest;
    const totals = { uploaded: 0, unchanged: 0, skipped: 0, missing: 0, failed: 0 };
    const missing = [];
    const failed = [];

    let done = 0;
    const tick = () => {
        done++;
        if (done % 50 === 0 || done === items.length) {
            process.stdout.write(`\r[mirror] ${done}/${items.length}  uploaded=${totals.uploaded} unchanged=${totals.unchanged} skipped=${totals.skipped} missing=${totals.missing} failed=${totals.failed}   `);
        }
    };

    await runPool(items, cfg.concurrency, async (item) => {
        const stateKey = `${cfg.mode}|${item.key}`;
        const knownEtag = state[stateKey];
        // Each cron run starts on a new runner, so the Cloudsmith object itself
        // is the source of truth for incrementality rather than a local cache.
        const exists = !cfg.force && (await bucket.has(item.key));

        if (exists && !cfg.force && !knownEtag) {
            // Already mirrored and we have no validator for it: trust the copy.
            totals.skipped++;
            tick();
            return;
        }

        // Only send a validator for objects the bucket already holds. A 304 on a key that is
        // MISSING from the bucket means "upstream unchanged" — reading it as "nothing to do"
        // would silently leave the mirror incomplete.
        const headers = {};
        if (exists && !cfg.force && knownEtag) headers['If-None-Match'] = knownEtag;

        const outcome = await fetchWithRetry(item.url, headers);
        if (outcome.missing) {
            totals.missing++;
            if (missing.length < 20) missing.push(item.key);
            tick();
            return;
        }
        if (!outcome.res) {
            totals.failed++;
            if (failed.length < 20) failed.push(`${item.key} (${outcome.failed})`);
            tick();
            return;
        }

        if (outcome.res.status === 304) {
            totals.unchanged++;
            tick();
            return;
        }

        const etag = outcome.res.headers.get('etag') || '';
        if (!cfg.dryRun) {
            let bytes;
            try {
                // Reading the body shares the request timeout, so it has to be guarded as well:
                // an abort here would otherwise escape the pool and kill the entire run.
                bytes = Buffer.from(await outcome.res.arrayBuffer());
            } catch (err) {
                totals.failed++;
                if (failed.length < 20) failed.push(`${item.key} (read: ${err.message})`);
                tick();
                return;
            }

            const put = await putObject(bucket, item.key, bytes, contentTypeFor(item.key));
            if (!put.ok) {
                totals.failed++;
                if (failed.length < 20) failed.push(`${item.key} (put: ${put.reason})`);
                tick();
                return;
            }
        }
        if (etag) state[stateKey] = etag;
        totals.uploaded++;
        tick();
    });

    process.stdout.write('\n');
    if (!cfg.dryRun) writeFileSync(STATE_FILE, JSON.stringify(state, null, 2));

    log(
        `[mirror] done: uploaded=${totals.uploaded} unchanged=${totals.unchanged} ` +
            `already-present=${totals.skipped} missing-upstream=${totals.missing} failed=${totals.failed}`,
    );
    if (totals.skipped) {
        log('[mirror] objects already in the bucket were not re-verified; run with --force to check them against upstream');
    }
    if (missing.length) {
        log(`[mirror] upstream has no such file (harmless, usually non-container apps): ${missing.slice(0, 5).join(', ')}${missing.length > 5 ? ` … +${missing.length - 5}` : ''}`);
    }
    if (failed.length) {
        warn('[mirror] failures:');
        for (const line of failed) warn(`  - ${line}`);
        warn('[mirror] re-run the script: failures are retried, everything already in the bucket is skipped');
    }

    await verify(indexKey, manifest);
    return totals;
}

/** Sample check that the published urls really resolve on the mirror host. */
async function verify(indexKey, manifest) {
    const samples = [];
    samples.push(indexKey);
    samples.push(`${cfg.mode}/3panel.json.version.txt`);
    const icons = manifest.filter((item) => item.key.endsWith('/logo.png')).slice(0, 3);
    const composes = manifest.filter((item) => item.key.endsWith('/docker-compose.yml')).slice(0, 3);
    for (const item of [...icons, ...composes]) samples.push(item.key);

    log('[verify] sampling the published urls:');
    let bad = 0;
    for (const key of samples) {
        const url = `${cfg.dst}/${key}`;
        try {
            const res = await fetch(url, { method: 'GET', headers: { range: 'bytes=0-0' } });
            const ok = res.ok || res.status === 206;
            if (!ok) bad++;
            log(`  ${ok ? 'OK  ' : 'FAIL'} ${res.status}  ${url}`);
        } catch (err) {
            bad++;
            log(`  FAIL       ${url}  (${err.message})`);
        }
    }
    if (bad) {
        warn(`[verify] ${bad} of ${samples.length} sampled urls are not reachable — check the R2 public domain / cache.`);
    } else {
        log('[verify] all sampled urls are reachable');
    }
}

export { assetKey, buildManifest, buildZipEntry, readZipEntry };

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
    main().catch((err) => {
        warn(`[mirror] fatal: ${err.message}`);
        process.exitCode = 1;
    });
}
