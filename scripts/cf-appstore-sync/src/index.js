/**
 * Cloudflare Worker: mirror the upstream 1Panel app store into Cloudsmith Generic.
 *
 * Why this shape:
 *   - The panel requests `{AppRepoURL}/{mode}/3panel.json.zip`,
 *     `{AppRepoURL}/{mode}/3panel.json.version.txt` and, per app,
 *     `{AppRepoURL}/{mode}/3panel/{key}/{version}/docker-compose.yml`.
 *   - Icons and app packages are referenced by ABSOLUTE urls inside the store JSON,
 *     so the JSON has to be rewritten while mirroring, otherwise the panel keeps
 *     talking to the upstream host.
 *
 * The worker therefore:
 *   1. checks `{SRC}/{mode}/1panel.json.version.txt`. If it is unchanged AND a sweep for that
 *      version already finished, the whole run is a no-op (a few R2 reads + one fetch)
 *   2. when the version changed it downloads `{SRC}/{mode}/1panel.json.zip`, rewrites
 *      brand/origin inside the JSON, renames the archive entry `1panel.json` -> `3panel.json`
 *      and writes the new zip + version stamp + asset manifest to R2
 *   3. mirrors icons (and docker-compose.yml for runtime/php/node apps) in batches so a single
 *      run stays inside the subrequest budget. A cursor lives in R2 and wraps around, and every
 *      asset is fetched with If-None-Match so an unchanged file costs one 304 and no write.
 *
 * Bindings / vars: see wrangler.toml
 */

const SRC_ORIGIN_DEFAULT = 'https://apps.1panel.pro';
const INIT_TYPES = new Set(['runtime', 'php', 'node']);

const ZIP_LOCAL = 0x04034b50;
const ZIP_CENTRAL = 0x02014b50;
const ZIP_EOCD = 0x06054b50;

/* ------------------------------------------------------------------ crc32 */

let CRC_TABLE = null;
function getCrcTable() {
    if (CRC_TABLE) return CRC_TABLE;
    const table = new Uint32Array(256);
    for (let i = 0; i < 256; i++) {
        let c = i;
        for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
        table[i] = c >>> 0;
    }
    CRC_TABLE = table;
    return table;
}

function crc32(bytes) {
    const table = getCrcTable();
    let c = 0xffffffff;
    for (let i = 0; i < bytes.length; i++) c = table[(c ^ bytes[i]) & 0xff] ^ (c >>> 8);
    return (c ^ 0xffffffff) >>> 0;
}

/* -------------------------------------------------------- deflate helpers */

async function inflateRaw(bytes) {
    const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream('deflate-raw'));
    return new Uint8Array(await new Response(stream).arrayBuffer());
}

async function deflateRaw(bytes) {
    const stream = new Blob([bytes]).stream().pipeThrough(new CompressionStream('deflate-raw'));
    return new Uint8Array(await new Response(stream).arrayBuffer());
}

/* ------------------------------------------------------------- zip reader */

/**
 * Read one entry out of a zip archive.
 * Sizes are taken from the central directory, which stays correct even when the
 * writer used data descriptors (local header sizes would be zero in that case).
 */
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
            return { name, method, data: bytes.subarray(dataStart, dataStart + compSize) };
        }
        ptr += 46 + nameLen + extraLen + commentLen;
    }
    throw new Error(`zip: entry ${wanted || '*'} not found`);
}

/* ------------------------------------------------------------- zip writer */

/** Build a single-entry zip archive. */
async function buildZipEntry(name, content) {
    const nameBytes = new TextEncoder().encode(name);
    const compressed = await deflateRaw(content);
    const crc = crc32(content);

    const now = new Date();
    const dosTime = ((now.getHours() << 11) | (now.getMinutes() << 5) | (now.getSeconds() >> 1)) & 0xffff;
    const dosDate = (((now.getFullYear() - 1980) << 9) | ((now.getMonth() + 1) << 5) | now.getDate()) & 0xffff;

    const local = new Uint8Array(30 + nameBytes.length + compressed.length);
    const lv = new DataView(local.buffer);
    lv.setUint32(0, ZIP_LOCAL, true);
    lv.setUint16(4, 20, true);
    lv.setUint16(6, 0, true);
    lv.setUint16(8, 8, true);
    lv.setUint16(10, dosTime, true);
    lv.setUint16(12, dosDate, true);
    lv.setUint32(14, crc, true);
    lv.setUint32(18, compressed.length, true);
    lv.setUint32(22, content.length, true);
    lv.setUint16(26, nameBytes.length, true);
    lv.setUint16(28, 0, true);
    local.set(nameBytes, 30);
    local.set(compressed, 30 + nameBytes.length);

    const central = new Uint8Array(46 + nameBytes.length);
    const cv = new DataView(central.buffer);
    cv.setUint32(0, ZIP_CENTRAL, true);
    cv.setUint16(4, 20, true);
    cv.setUint16(6, 20, true);
    cv.setUint16(8, 0, true);
    cv.setUint16(10, 8, true);
    cv.setUint16(12, dosTime, true);
    cv.setUint16(14, dosDate, true);
    cv.setUint32(16, crc, true);
    cv.setUint32(20, compressed.length, true);
    cv.setUint32(24, content.length, true);
    cv.setUint16(28, nameBytes.length, true);
    cv.setUint16(30, 0, true);
    cv.setUint16(32, 0, true);
    cv.setUint16(34, 0, true);
    cv.setUint16(36, 0, true);
    cv.setUint32(38, 0, true);
    cv.setUint32(42, 0, true);
    central.set(nameBytes, 46);

    const eocd = new Uint8Array(22);
    const ev = new DataView(eocd.buffer);
    ev.setUint32(0, ZIP_EOCD, true);
    ev.setUint16(8, 1, true);
    ev.setUint16(10, 1, true);
    ev.setUint32(12, central.length, true);
    ev.setUint32(16, local.length, true);

    const out = new Uint8Array(local.length + central.length + eocd.length);
    out.set(local, 0);
    out.set(central, local.length);
    out.set(eocd, local.length + central.length);
    return out;
}

/* ---------------------------------------------------------------- helpers */

async function readJson(bucket, key) {
    const object = await bucket.get(key);
    if (!object) return null;
    try {
        return await object.json();
    } catch {
        return null;
    }
}

/** Cloudsmith Generic preserves the path-based layout the panel requires. */
function cloudsmithBucket(env) {
    const owner = env.CLOUDSMITH_OWNER || '3panel';
    const repo = env.CLOUDSMITH_REPOSITORY || '3panel';
    const base = `https://generic.cloudsmith.io/${owner}/${repo}`;
    const api = 'https://api.cloudsmith.io/v1';
    const key = env.CLOUDSMITH_API_KEY;
    if (!key) throw new Error('missing Cloudsmith secret CLOUDSMITH_API_KEY');
    const headers = { 'X-Api-Key': key, Accept: 'application/json' };
    const filename = (path) => path.split('/').pop() || 'asset';
    return {
        async get(path) {
            const res = await fetch(`${base}/${path}`);
            return res.ok ? { json: () => res.json() } : null;
        },
        async head(path) {
            return (await fetch(`${base}/${path}`, { method: 'HEAD' })).ok;
        },
        async put(path, body) {
            const bytes = body instanceof ReadableStream ? await new Response(body).arrayBuffer() : body;
            const blob = new Blob([bytes]);
            const digest = await crypto.subtle.digest('MD5', await blob.arrayBuffer());
            const md5 = Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('');
            const create = await fetch(`${api}/files/${owner}/${repo}/`, {
                method: 'POST', headers: { ...headers, 'Content-Type': 'application/json' },
                body: JSON.stringify({ filename: filename(path), md5_checksum: md5, method: 'post' }),
            });
            if (!create.ok) throw new Error(`Cloudsmith file upload: HTTP ${create.status}`);
            const upload = await create.json();
            const form = new FormData();
            for (const [name, value] of Object.entries(upload.upload_fields || {})) form.append(name, value);
            form.append('file', blob, filename(path));
            const uploaded = await fetch(upload.upload_url, { method: 'POST', body: form });
            if (!uploaded.ok) throw new Error(`Cloudsmith file transfer: HTTP ${uploaded.status}`);
            const publish = await fetch(`${api}/packages/${owner}/${repo}/upload/generic/`, {
                method: 'POST', headers: { ...headers, 'Content-Type': 'application/json' },
                body: JSON.stringify({ package_file: upload.identifier, filepath: path, republish: true }),
            });
            if (!publish.ok) throw new Error(`Cloudsmith generic publish: HTTP ${publish.status}`);
        },
    };
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

function escapeRegExp(value) {
    return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

const RETRYABLE_STATUS = new Set([403, 408, 425, 429, 500, 502, 503, 504]);
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Fetch an asset, retrying throttling / transient failures with backoff.
 * The upstream host throttles bursts (a 403/429 must not be treated as permanent),
 * and a 304 means our copy is still valid. `sub` is the invocation subrequest budget:
 * once it is exhausted we stop cleanly instead of burning the run on "Too many subrequests" errors.
 */
async function fetchAsset(url, headers, sub, attempts = 3) {
    let reason = 'unknown';
    for (let attempt = 0; attempt < attempts; attempt++) {
        if (sub && sub.used >= sub.budget) return { exhausted: true };
        if (attempt > 0) await sleep(400 * 3 ** (attempt - 1));
        if (sub) sub.used++;
        try {
            const res = await fetch(url, { headers, cf: { cacheTtl: 0 } });
            if (res.status === 304 || res.ok) return { res };
            reason = `HTTP ${res.status}`;
            if (!RETRYABLE_STATUS.has(res.status)) return { reason };
        } catch (err) {
            reason = err.message;
        }
    }
    return { reason };
}

async function runPool(items, concurrency, handler) {
    let cursor = 0;
    const size = Math.max(1, Math.min(concurrency, items.length));
    const workers = [];
    for (let w = 0; w < size; w++) {
        workers.push(
            (async () => {
                while (cursor < items.length) {
                    const index = cursor++;
                    await handler(items[index], index);
                }
            })(),
        );
    }
    await Promise.all(workers);
}

/** Map an upstream asset url onto the bucket key the panel will request. */
function assetKey(url, mode) {
    const pathname = new URL(url).pathname;
    return pathname.replace(`/${mode}/1panel/`, `/${mode}/3panel/`).replace(/^\//, '');
}

/**
 * Collect everything the store JSON points at, before the JSON is rewritten.
 * Icons are always mirrored; docker-compose.yml only matters for runtime/php/node.
 */
function buildManifest(store, mode, srcOrigin, syncPackages) {
    const items = new Map();
    const push = (src) => {
        if (!src) return;
        const key = assetKey(src, mode);
        if (!items.has(key)) items.set(key, { src, key });
    };

    for (const app of store.apps || []) {
        const props = app.additionalProperties || {};
        const key = props.key;
        push(app.icon);

        const needsCompose = INIT_TYPES.has(props.type);
        for (const version of app.versions || []) {
            if (needsCompose && key && version.name) {
                push(`${srcOrigin}/${mode}/1panel/${key}/${version.name}/docker-compose.yml`);
            }
            if (syncPackages && version.downloadUrl) push(version.downloadUrl);
        }
    }
    return [...items.values()];
}

/* ------------------------------------------------------- resource channel */

/**
 * Besides the app store, the panel pulls a second group of objects from the same
 * bucket - the "resource channel" (ResourceURL(), default `<host>/resource`):
 *
 *   /resource/scripts/data.yaml        script-library index
 *   /resource/scripts/scripts.tar.gz   the scripts themselves
 *   /resource/scripts/version.txt      freshness stamp (unix seconds)
 *   /resource/language/lang.tar.gz     language pack
 *   /resource/geo/GeoIP.mmdb           IP -> location database
 *
 * Upstream deliberately splits these across two prefixes: the script library moved
 * to `/resource/v2/`, while the language pack and GeoIP stayed under `/resource/`.
 * Do NOT "unify" the base - the v1 script path and the v2 language/geo paths are 404.
 */
const RESOURCE_SRC_DEFAULT = 'https://resource.fit2cloud.com/1panel';
const MMDB_MARKER = 'MaxMind.com';

function resourceSource(env) {
    return (env.RESOURCE_SRC || RESOURCE_SRC_DEFAULT).replace(/\/+$/, '');
}

async function gunzip(bytes) {
    const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream('gzip'));
    return new Uint8Array(await new Response(stream).arrayBuffer());
}

/** Walk a tar archive and return `{name, size, dir}` per entry. Null = unusable header. */
function listTarEntries(bytes) {
    const decoder = new TextDecoder();
    const entries = [];
    let offset = 0;
    while (offset + 512 <= bytes.length) {
        const header = bytes.subarray(offset, offset + 512);
        if (header.every((b) => b === 0)) break;

        const rawName = decoder.decode(header.subarray(0, 100));
        const nul = rawName.indexOf('\0');
        const name = nul === -1 ? rawName : rawName.slice(0, nul);

        const sizeField = decoder.decode(header.subarray(124, 136)).replace(/\0/g, '').trim();
        const size = sizeField === '' ? 0 : parseInt(sizeField, 8);
        if (!Number.isFinite(size)) return null; // base-256 size or a corrupt header

        entries.push({ name, size, dir: String.fromCharCode(header[156]) === '5' });
        offset += 512 + Math.ceil(size / 512) * 512;
    }
    return entries;
}

/**
 * Never publish a script library the panel cannot serve.
 *
 * `script_library.go` reads `$tmpDir/scripts/sh/<key>.sh` for every key listed in
 * data.yaml. One missing file becomes an empty script in the UI, with no error
 * surfacing anywhere - which is exactly what this check exists to prevent.
 * Throw = the current (working) copy in R2 is left untouched.
 */
function checkScriptLibrary(yamlText, entries) {
    if (!/^\s*scripts:\s*$/m.test(yamlText) || !/^\s*sh:\s*$/m.test(yamlText)) {
        throw new Error('data.yaml: scripts/sh section not found (upstream layout changed?)');
    }
    const keys = [...yamlText.matchAll(/^\s*-\s*key:\s*([A-Za-z0-9_.-]+)\s*$/gm)].map((match) => match[1]);
    if (keys.length === 0) throw new Error('data.yaml: no script keys found (upstream layout changed?)');

    const files = new Map();
    for (const entry of entries) {
        if (entry.dir) continue;
        const match = /^(?:\.\/)?scripts\/sh\/([^/]+)\.sh$/.exec(entry.name);
        if (match) files.set(match[1], entry.size);
    }
    if (files.size === 0) throw new Error('scripts.tar.gz: no scripts/sh/*.sh entries');

    const missing = keys.filter((key) => !files.has(key));
    if (missing.length) throw new Error(`scripts.tar.gz: no file for key(s) ${missing.join(', ')}`);

    const empty = [...files].filter(([, size]) => size === 0).map(([key]) => key);
    if (empty.length) throw new Error(`scripts.tar.gz: empty script(s) ${empty.join(', ')}`);

    return { keys: keys.length, files: files.size, orphans: [...files.keys()].filter((key) => !keys.includes(key)) };
}

/** `initLang()` uses /usr/local/bin/lang/zh.sh as its "pack installed" sentinel. */
function checkLangPack(entries) {
    const names = new Set(entries.map((entry) => entry.name.replace(/^\.\//, '')));
    if (!names.has('lang/zh.sh')) throw new Error('lang.tar.gz: lang/zh.sh missing (initLang sentinel)');
    if (!names.has('lang/en.sh')) throw new Error('lang.tar.gz: lang/en.sh missing (install.sh fallback)');
    return { files: [...names].filter((name) => name.endsWith('.sh')).length };
}

/** Reject anything that is not a plausible MaxMind database (e.g. an error page). */
function checkGeoIp(bytes) {
    if (bytes.length < 1024 * 1024) throw new Error(`GeoIP.mmdb: implausibly small (${bytes.length} bytes)`);
    const tail = new TextDecoder('latin1').decode(bytes.subarray(Math.max(0, bytes.length - 131072)));
    if (!tail.includes(MMDB_MARKER)) throw new Error('GeoIP.mmdb: MaxMind metadata marker not found');
    return { bytes: bytes.length };
}

const RESOURCE_SCRIPTS = [
    { key: 'resource/scripts/version.txt', path: '/resource/v2/scripts/version.txt', type: 'text/plain; charset=utf-8' },
    { key: 'resource/scripts/data.yaml', path: '/resource/v2/scripts/data.yaml', type: 'text/yaml; charset=utf-8' },
    { key: 'resource/scripts/scripts.tar.gz', path: '/resource/v2/scripts/scripts.tar.gz', type: 'application/gzip' },
];

/**
 * Mirror the resource channel into R2.
 *
 * The script library is gated by upstream's version.txt, so an unchanged upstream
 * costs one fetch and no write. The language pack and GeoIP are opt-in (default
 * off): the language pack is produced by release-stable.yml from the repo's own
 * `packaging/lang/`, and letting a cron overwrite it would make the two fight.
 */
async function runResourceSync(env, { force = false, dry = false, lang, geoip } = {}) {
    const bucket = cloudsmithBucket(env);

    const wantLang = lang === undefined ? String(env.SYNC_RESOURCE_LANG || 'false') === 'true' : lang;
    const wantGeoip = geoip === undefined ? String(env.SYNC_RESOURCE_GEOIP || 'false') === 'true' : geoip;
    const src = resourceSource(env);
    const dst = (env.DST_ORIGIN || '').replace(/\/+$/, '');

    const stateKey = 'resource/scripts/.sync-state.json';
    const state = (await readJson(bucket, stateKey)) || {};
    const notes = [];
    const published = [];
    const skipped = [];

    const put = async (key, body, contentType) => {
        if (dry) return;
        await bucket.put(key, body, { httpMetadata: { contentType } });
    };

    // ---------------------------------------------------------- script library
    const stampRes = await fetch(`${src}${RESOURCE_SCRIPTS[0].path}`, { cf: { cacheTtl: 0 } });
    if (!stampRes.ok) throw new Error(`scripts/version.txt: HTTP ${stampRes.status}`);
    const stamp = (await stampRes.text()).trim();
    if (!stamp) throw new Error('scripts/version.txt: empty stamp');

    const heads = await Promise.all(RESOURCE_SCRIPTS.slice(1).map((item) => bucket.head(item.key)));
    let validation = state.scripts || null;

    if (!force && state.stamp === stamp && heads.every(Boolean)) {
        skipped.push(`scripts (stamp=${stamp} unchanged)`);
    } else {
        const [dataRes, tarRes] = await Promise.all([
            fetch(`${src}${RESOURCE_SCRIPTS[1].path}`, { cf: { cacheTtl: 0 } }),
            fetch(`${src}${RESOURCE_SCRIPTS[2].path}`, { cf: { cacheTtl: 0 } }),
        ]);
        if (!dataRes.ok) throw new Error(`scripts/data.yaml: HTTP ${dataRes.status}`);
        if (!tarRes.ok) throw new Error(`scripts/scripts.tar.gz: HTTP ${tarRes.status}`);

        const dataYaml = await dataRes.text();
        const tarBytes = new Uint8Array(await tarRes.arrayBuffer());
        const entries = listTarEntries(await gunzip(tarBytes));
        if (!entries) throw new Error('scripts.tar.gz: unreadable tar header');

        validation = checkScriptLibrary(dataYaml, entries);
        if (validation.orphans.length) {
            notes.push(`scripts.tar.gz: ${validation.orphans.length} file(s) not referenced by data.yaml (panel ignores them)`);
        }

        await put(RESOURCE_SCRIPTS[0].key, stamp, RESOURCE_SCRIPTS[0].type);
        await put(RESOURCE_SCRIPTS[1].key, dataYaml, RESOURCE_SCRIPTS[1].type);
        await put(RESOURCE_SCRIPTS[2].key, tarBytes, RESOURCE_SCRIPTS[2].type);

        state.stamp = stamp;
        state.scripts = validation;
        published.push(...RESOURCE_SCRIPTS.map((item) => item.key));
        notes.push(
            `scripts published: ${validation.keys} scripts / ${validation.files} files (stamp=${stamp}, ${tarBytes.length} bytes)`,
        );
    }

    // ------------------------------------------------------- optional extras
    const extras = [];
    if (wantLang) {
        extras.push({ key: 'resource/language/lang.tar.gz', path: '/resource/language/lang.tar.gz', type: 'application/gzip', check: 'lang' });
    }
    if (wantGeoip) {
        extras.push({ key: 'resource/geo/GeoIP.mmdb', path: '/resource/geo/GeoIP.mmdb', type: 'application/octet-stream', check: 'mmdb' });
    }

    state.etags = state.etags || {};
    for (const item of extras) {
        const headers = !force && state.etags[item.key] ? { 'If-None-Match': state.etags[item.key] } : {};
        const res = await fetch(`${src}${item.path}`, { headers, cf: { cacheTtl: 0 } });
        if (res.status === 304) {
            skipped.push(`${item.key} (unchanged)`);
            continue;
        }
        if (!res.ok) throw new Error(`${item.key}: HTTP ${res.status}`);

        const bytes = new Uint8Array(await res.arrayBuffer());
        if (item.check === 'lang') {
            const entries = listTarEntries(await gunzip(bytes));
            if (!entries) throw new Error('lang.tar.gz: unreadable tar header');
            checkLangPack(entries);
        } else {
            checkGeoIp(bytes);
        }

        await bucket.put(item.key, bytes, { httpMetadata: { contentType: item.type } });
        const etag = res.headers.get('ETag');
        if (etag) state.etags[item.key] = etag;
        published.push(item.key);
        notes.push(`${item.key} mirrored (${bytes.length} bytes)`);
    }

    state.checkedAt = new Date().toISOString();
    if (!dry) await bucket.put(stateKey, JSON.stringify(state), { httpMetadata: { contentType: 'application/json; charset=utf-8' } });

    for (const note of notes) console.log(`[resource-sync] ${note}`);

    const managed = [...RESOURCE_SCRIPTS.map((item) => item.key), ...extras.map((item) => item.key)];
    return {
        ok: true,
        dry,
        stamp,
        validation,
        published,
        skipped,
        notes,
        urls: dst ? managed.map((key) => `${dst}/${key}`) : [],
    };
}

/* ------------------------------------------------------------------- sync */

async function runSync(env, { force = false } = {}) {
    const mode = env.MODE || 'stable';
    const src = env.SRC_ORIGIN || SRC_ORIGIN_DEFAULT;
    const dst = env.DST_ORIGIN;
    const bucket = cloudsmithBucket(env);
    if (!dst) throw new Error('missing DST_ORIGIN (public url of your R2 bucket)');

    const batch = Number(env.ASSETS_PER_RUN || 60);
    const concurrency = Number(env.CONCURRENCY || 8);
    const syncPackages = String(env.SYNC_APP_PACKAGES || 'false') === 'true';

    const indexKey = `${mode}/3panel.json.zip`;
    const versionKey = `${mode}/3panel.json.version.txt`;
    const manifestKey = `${mode}/.manifest.json`;
    const etagsKey = `${mode}/.etags.json`;
    const stateKey = `${mode}/.sync-state.json`;

    const notes = [];
    let state = (await readJson(bucket, stateKey)) || { version: '', cursor: 0 };
    let etags = (await readJson(bucket, etagsKey)) || {};

    // 1. upstream version stamp - the single signal that decides whether the index must be rebuilt
    const versionRes = await fetch(`${src}/${mode}/1panel.json.version.txt`, { cf: { cacheTtl: 0 } });
    if (!versionRes.ok) throw new Error(`version.txt: ${versionRes.status}`);
    const version = (await versionRes.text()).trim();

    // 2. index + manifest (only when upstream changed, or nothing published yet)
    const [indexObject, manifestObject] = await Promise.all([bucket.head(indexKey), bucket.head(manifestKey)]);
    const indexChanged = force || state.version !== version || !indexObject || !manifestObject;
    let manifest = [];
    if (indexChanged) {
        const zipRes = await fetch(`${src}/${mode}/1panel.json.zip`, { cf: { cacheTtl: 0 } });
        if (!zipRes.ok) throw new Error(`1panel.json.zip: ${zipRes.status}`);
        const entry = readZipEntry(new Uint8Array(await zipRes.arrayBuffer()), '1panel.json');

        const raw = entry.method === 8 ? await inflateRaw(entry.data) : entry.data;
        const text = new TextDecoder().decode(raw);
        const store = JSON.parse(text);

        manifest = buildManifest(store, mode, src, syncPackages);

        // Point every url inside the store at the mirror: icons, and app packages when mirrored.
        let rewritten = text.split(`${src}/${mode}/1panel/`).join(`${dst}/${mode}/3panel/`).split(src).join(dst);

        if (!syncPackages) {
            // App packages (*.tar.gz) are not uploaded to R2 in this mode, so keep them on the
            // upstream host - otherwise install/upgrade would hit a 404 on our own domain.
            const pattern = new RegExp(`${escapeRegExp(dst)}/${escapeRegExp(mode)}/3panel/([^"'\\s]+?\\.tar\\.gz)`, 'g');
            rewritten = rewritten.replace(pattern, `${src}/${mode}/1panel/$1`);
        }

        const zipOut = await buildZipEntry('3panel.json', new TextEncoder().encode(rewritten));

        await bucket.put(indexKey, zipOut, { httpMetadata: { contentType: 'application/zip' } });
        await bucket.put(versionKey, version, { httpMetadata: { contentType: 'text/plain; charset=utf-8' } });
        await bucket.put(manifestKey, JSON.stringify(manifest), {
            httpMetadata: { contentType: 'application/json; charset=utf-8' },
        });

        // validators of assets that vanished from the store are dropped along with them
        const validKeys = new Set(manifest.map((item) => item.key));
        etags = Object.fromEntries(Object.entries(etags).filter(([key]) => validKeys.has(key)));
        await bucket.put(etagsKey, JSON.stringify(etags), {
            httpMetadata: { contentType: 'application/json; charset=utf-8' },
        });

        // a rebuilt index always invalidates the current sweep
        state = { version, cursor: 0, total: manifest.length, completedVersion: '' };
        notes.push(`index published (version=${version}, apps=${(store.apps || []).length}, assets=${manifest.length})`);
    } else {
        manifest = (await readJson(bucket, manifestKey)) || [];
        state.total = manifest.length;
        notes.push(`index up to date (version=${version})`);
    }

    // 3. asset batch
    //    - a cursor walks the manifest so one run stays inside the subrequest budget
    //    - every asset is fetched with If-None-Match, so an unchanged file costs one 304 and no write
    //    - throttled/transient failures are retried, then parked in a retry queue that is drained
    //      first on the next run (the cursor alone would not revisit them until the next sweep)
    //    - once a sweep for the current version has completed, idle runs skip this step entirely
    const sweepDone = state.cursor === 0 && state.completedVersion === version;
    const retryAttemptsMax = Number(env.RETRY_MAX_ATTEMPTS || 5);

    // Keep in sync with [limits].subrequests in wrangler.toml.
    // Free plans are capped at 50 subrequests per invocation, paid plans default to 10000.
    // 20% headroom covers the version/index fetches and concurrent overshoot.
    const subrequestLimit = Number(env.SUBREQUEST_LIMIT || 50);
    const sub = { used: indexChanged ? 2 : 1, budget: Math.max(4, Math.floor(subrequestLimit * 0.8)) };
    const manifestByKey = new Map(manifest.map((item) => [item.key, item]));

    if (manifest.length > 0 && !sweepDone) {
        const start = Math.min(state.cursor || 0, manifest.length - 1);
        const slice = manifest.slice(start, start + batch);

        const attempts = { ...(state.retry || {}) };
        const work = [];
        const queued = new Set();
        for (const key of Object.keys(attempts)) {
            const item = manifestByKey.get(key);
            if (item) {
                queued.add(key);
                work.push(item);
            }
        }
        for (const item of slice) {
            if (!queued.has(item.key)) {
                queued.add(item.key);
                work.push(item);
            }
        }

        let uploaded = 0;
        let unchanged = 0;
        let deferred = 0;
        let etagsDirty = false;
        let sliceDone = 0;
        const failed = new Map();
        const sliceKeys = new Set(slice.map((item) => item.key));

        await runPool(work, concurrency, async (item) => {
            const headers = {};
            if (etags[item.key]) headers['If-None-Match'] = etags[item.key];

            const outcome = await fetchAsset(item.src, headers, sub);
            if (outcome.exhausted) {
                // out of budget: leave the item for the next run instead of recording a bogus failure
                deferred++;
                return;
            }
            if (sliceKeys.has(item.key)) sliceDone++;

            if (!outcome.res) {
                failed.set(item.key, outcome.reason);
                return;
            }
            if (outcome.res.status === 304) {
                delete attempts[item.key];
                unchanged++;
                return;
            }

            try {
                await bucket.put(item.key, outcome.res.body, {
                    httpMetadata: { contentType: contentTypeFor(item.key) },
                });
            } catch (err) {
                failed.set(item.key, `put: ${err.message}`);
                return;
            }

            delete attempts[item.key];
            const etag = outcome.res.headers.get('ETag');
            if (etag && etag !== etags[item.key]) {
                etags[item.key] = etag;
                etagsDirty = true;
            }
            uploaded++;
        });

        for (const [key, reason] of failed) attempts[key] = (attempts[key] || 0) + 1;

        // only advance past the items we actually attempted; deferred ones are retried next run
        const next = start + sliceDone;
        state.cursor = next >= manifest.length ? 0 : next;
        state.assetRuns = (state.assetRuns || 0) + 1;
        state.lastRunAt = new Date().toISOString();
        state.subrequestsUsed = sub.used;

        // give up on entries that keep failing so the sweep can still finish and go idle
        const dropped = Object.entries(attempts).filter(([, count]) => count > retryAttemptsMax);
        state.retry = Object.fromEntries(Object.entries(attempts).filter(([, count]) => count <= retryAttemptsMax));
        state.lastErrors = [...failed.entries()].slice(0, 10).map(([key, reason]) => ({ key, reason }));

        const pending = Object.keys(state.retry).length;
        if (state.cursor === 0 && pending === 0) {
            state.completedVersion = version;
            state.lastFullSweepAt = state.lastRunAt;
        }
        notes.push(
            `assets ${start}..${start + sliceDone - 1} of ${manifest.length}: uploaded=${uploaded} unchanged=${unchanged} ` +
                `failed=${failed.size} deferred=${deferred} retryQueue=${pending} subrequests=${sub.used}/${sub.budget}` +
                (dropped.length ? ` dropped=${dropped.length}` : '') +
                (failed.size
                    ? ` e.g. ${[...failed.entries()]
                          .slice(0, 3)
                          .map(([k, r]) => `${k} (${r})`)
                          .join(' | ')}`
                    : ''),
        );

        if (etagsDirty) {
            await bucket.put(etagsKey, JSON.stringify(etags), {
                httpMetadata: { contentType: 'application/json; charset=utf-8' },
            });
        }
    } else if (manifest.length > 0) {
        notes.push(`assets up to date (version=${version}, ${manifest.length} objects, no sweep pending)`);
    }

    await bucket.put(stateKey, JSON.stringify(state), {
        httpMetadata: { contentType: 'application/json; charset=utf-8' },
    });

    for (const note of notes) console.log(`[appstore-sync] ${note}`);
    return { ok: true, mode, version, cursor: state.cursor, total: state.total || 0, notes };
}

/* ------------------------------------------------------------------ entry */

export default {
    async scheduled(event, env, ctx) {
        // A second cron expression (FORCE_CRON) re-validates every asset even when the upstream
        // version stamp did not change, which covers store edits that skip a version bump.
        const forceCron = String(env.FORCE_CRON || '').trim();
        const force = forceCron !== '' && event && event.cron === forceCron;
        ctx.waitUntil(
            runSync(env, { force }).catch((err) => {
                console.error(`[appstore-sync] scheduled failed: ${err.stack || err.message}`);
            }),
        );

        // The resource channel rides along: it is one extra fetch, and the script objects are
        // only rewritten when upstream's stamp moved. Disable with SYNC_RESOURCE = "false".
        if (String(env.SYNC_RESOURCE || 'true') === 'true') {
            ctx.waitUntil(
                runResourceSync(env, {}).catch((err) => {
                    console.error(`[resource-sync] scheduled failed: ${err.stack || err.message}`);
                }),
            );
        }
    },

    async fetch(request, env, ctx) {
        const url = new URL(request.url);

        if (url.pathname === '/sync') {
            const force = url.searchParams.get('force') === 'true';
            ctx.waitUntil(
                runSync(env, { force }).catch((err) => {
                    console.error(`[appstore-sync] manual sync failed: ${err.stack || err.message}`);
                }),
            );
            return new Response(`sync triggered (force=${force}), check logs\n`, { status: 202 });
        }

        if (url.pathname === '/sync-resource') {
            // Runs synchronously so the caller gets the report (validation counts, urls,
            // what was skipped) instead of having to dig through the logs.
            //   ?dry=true            validate upstream, write nothing
            //   ?force=true           ignore the stamp / etags and re-upload
            //   ?lang=true|false      mirror the language pack
            //   ?geoip=true|false     mirror GeoIP.mmdb (~19.5 MB)
            const flag = (name) => {
                const value = url.searchParams.get(name);
                return value === null ? undefined : value === 'true';
            };
            const options = {
                force: url.searchParams.get('force') === 'true',
                dry: url.searchParams.get('dry') === 'true',
                lang: flag('lang'),
                geoip: flag('geoip'),
            };
            try {
                return Response.json(await runResourceSync(env, options));
            } catch (err) {
                console.error(`[resource-sync] manual sync failed: ${err.stack || err.message}`);
                return Response.json({ ok: false, error: err.message }, { status: 500 });
            }
        }

        if (url.pathname === '/status') {
            const mode = env.MODE || 'stable';
            const [state, resource] = await Promise.all([
                readJson(cloudsmithBucket(env), `${mode}/.sync-state.json`),
                readJson(cloudsmithBucket(env), 'resource/scripts/.sync-state.json'),
            ]);
            return Response.json({ mode, state: state || null, resource: resource || null });
        }

        return new Response('POST-free worker: try /sync, /sync-resource or /status\n', { status: 404 });
    },
};
