// ---- Ayarlar (istersen degistir) ----
const PER_IP_DAILY = 10;   // bir kisinin gunluk derleme hakki
const GLOBAL_DAILY = 40;   // tum kullanicilar icin gunluk toplam sinir
const USER_DAILY = 15;     // Google ile giris yapmis kullanicinin gunluk hakki
const TTL = 3600;          // dosyalarin saklanma suresi (saniye)
// -------------------------------------

const STAGES = ['getfile', 'cap', 'settings', 'keys', 'gradle', 'sign', 'send'];
const PNG_SIG = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
const FILE_TYPES = {
  apk: 'application/vnd.android.package-archive',
  aab: 'application/octet-stream',
  keystore: 'application/octet-stream',
  keyinfo: 'text/plain; charset=utf-8',
};
const FILE_NAMES = {
  apk: 'app-release.apk',
  aab: 'app-release.aab',
  keystore: 'upload-keystore.jks',
  keyinfo: 'anahtar-bilgisi.txt',
};

// ---- Veritabani (Cloudflare D1, istege bagli) ----
const SCHEMA = [
  `CREATE TABLE IF NOT EXISTS projects (
    uid TEXT NOT NULL, pkg TEXT NOT NULL, app_name TEXT NOT NULL,
    version_name TEXT NOT NULL, version_code INTEGER NOT NULL,
    orientation TEXT NOT NULL DEFAULT 'unspecified', splash TEXT NOT NULL DEFAULT '#12161c',
    icon TEXT NOT NULL DEFAULT '', updated_at INTEGER NOT NULL,
    PRIMARY KEY (uid, pkg))`,
  `CREATE TABLE IF NOT EXISTS builds (
    id TEXT PRIMARY KEY, uid TEXT NOT NULL, pkg TEXT NOT NULL, app_name TEXT NOT NULL,
    version_name TEXT NOT NULL, version_code INTEGER NOT NULL, sign_mode TEXT NOT NULL,
    status TEXT NOT NULL, error_code TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL, finished_at INTEGER)`,
];
const PKG_RE = /^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$/;
const UPSERT_PROJECT = `INSERT INTO projects (uid, pkg, app_name, version_name, version_code, orientation, splash, icon, updated_at) VALUES (?,?,?,?,?,?,?,?,?) ON CONFLICT(uid, pkg) DO UPDATE SET app_name=excluded.app_name, version_name=excluded.version_name, version_code=excluded.version_code, orientation=excluded.orientation, splash=excluded.splash, icon=COALESCE(NULLIF(excluded.icon, ''), icon), updated_at=excluded.updated_at`;
const MAX_PROJECTS = 30;
const MAX_ICON_CHARS = 120000;
const HISTORY_DAYS = 90;
function checkMeta(f) {
  if (!PKG_RE.test(f.pkg)) return 'Paket adi gecersiz';
  if (!f.appName || f.appName.length > 40 || /["$`\\]/.test(f.appName)) return 'Uygulama adi gecersiz';
  if (!/^[0-9A-Za-z._-]{1,20}$/.test(f.versionName)) return 'Surum adi gecersiz';
  if (!Number.isInteger(f.versionCode) || f.versionCode < 1 || f.versionCode > 2100000000) return 'Surum numarasi gecersiz';
  if (!['portrait', 'landscape', 'unspecified'].includes(f.orientation)) return 'Ekran yonu gecersiz';
  if (!/^#[0-9a-fA-F]{6}$/.test(f.splash)) return 'Renk gecersiz';
  return '';
}

let schemaReady = false;

async function ensureSchema(env) {
  if (!env.DB) return false;
  if (schemaReady) return true;
  await env.DB.batch(SCHEMA.map((q) => env.DB.prepare(q)));
  schemaReady = true;
  return true;
}

// Derleme kaydi: hata olursa derlemeyi bozmaz
async function dbRecordBuild(env, uid, id, b) {
  try {
    if (!(await ensureSchema(env))) return;
    const now = Math.floor(Date.now() / 1000);
    await env.DB.batch([
      env.DB.prepare('INSERT INTO builds (id, uid, pkg, app_name, version_name, version_code, sign_mode, status, created_at) VALUES (?,?,?,?,?,?,?,?,?)')
        .bind(id, uid, b.pkg, b.appName, b.versionName, b.versionCode, b.signMode, 'queued', now),
      env.DB.prepare(UPSERT_PROJECT)
        .bind(uid, b.pkg, b.appName, b.versionName, b.versionCode, b.orientation, b.splash, '', now),
      env.DB.prepare('DELETE FROM builds WHERE uid = ? AND created_at < ?')
        .bind(uid, now - HISTORY_DAYS * 86400),
    ]);
  } catch (e) {}
}
function quotaOf(req, user) {
  const day = new Date().toISOString().slice(0, 10);
  const who = user ? 'u:' + user.uid : 'ip:' + (req.headers.get('CF-Connecting-IP') || 'bilinmiyor');
  return { day, key: 'rl:' + day + ':' + who, limit: user ? USER_DAILY : PER_IP_DAILY };
}
async function dbExec(env, sql, ...args) {
  try {
    if (await ensureSchema(env)) await env.DB.prepare(sql).bind(...args).run();
  } catch (e) {}
}
const nowSec = () => Math.floor(Date.now() / 1000);

// ---- Firebase (Google ile giris) kimlik dogrulama ----
const JWKS_URL = 'https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com';

function b64u(str) {
  const b = str.replace(/-/g, '+').replace(/_/g, '/');
  const padded = b + '='.repeat((4 - (b.length % 4)) % 4);
  return Uint8Array.from(atob(padded), (c) => c.charCodeAt(0));
}

async function getJwks() {
  const r = await fetch(JWKS_URL, { cf: { cacheTtl: 3600 } });
  if (!r.ok) throw new Error('jwks');
  return (await r.json()).keys || [];
}

// Gecerli bir Firebase kimlik belgesi varsa { uid, email }, yoksa null doner
async function verifyIdToken(req, env) {
  const m = (req.headers.get('Authorization') || '').match(/^Bearer\s+(.+)$/i);
  if (!m || !env.FIREBASE_PROJECT_ID) return null;
  const parts = m[1].split('.');
  if (parts.length !== 3) return null;
  try {
    const dec = new TextDecoder();
    const header = JSON.parse(dec.decode(b64u(parts[0])));
    const payload = JSON.parse(dec.decode(b64u(parts[1])));
    const project = env.FIREBASE_PROJECT_ID;
    const now = Math.floor(Date.now() / 1000);
    if (header.alg !== 'RS256' || !header.kid) return null;
    if (payload.aud !== project) return null;
    if (payload.iss !== 'https://securetoken.google.com/' + project) return null;
    if (typeof payload.sub !== 'string' || !payload.sub || payload.sub.length > 128) return null;
    if (!payload.exp || payload.exp <= now) return null;
    if (payload.iat && payload.iat > now + 300) return null;
    const jwk = (await getJwks()).find((k) => k.kid === header.kid);
    if (!jwk) return null;
    const key = await crypto.subtle.importKey(
      'jwk', jwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']
    );
    const ok = await crypto.subtle.verify(
      'RSASSA-PKCS1-v1_5', key, b64u(parts[2]), new TextEncoder().encode(parts[0] + '.' + parts[1])
    );
    return ok ? { uid: payload.sub, email: payload.email || '' } : null;
  } catch (e) {
    return null;
  }
}

async function hmacHex(secret, text) {
  const key = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(text));
  return Array.from(new Uint8Array(sig), (b) => b.toString(16).padStart(2, '0')).join('');
}

function safeEqual(a, b) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}

// Dosyayi indirme izni: imzali kisa omurlu baglanti ya da dosyanin sahibi
async function canDownload(req, env, id, type, url) {
  const exp = Number(url.searchParams.get('exp') || 0);
  const sig = url.searchParams.get('sig') || '';
  if (exp > Math.floor(Date.now() / 1000) && sig && env.WORKER_SECRET) {
    const want = await hmacHex(env.WORKER_SECRET, id + ':' + type + ':' + exp);
    if (safeEqual(sig, want)) return true;
  }
  const u = await verifyIdToken(req, env);
  const owner = await env.FILES.get('owner:' + id);
  return !!u && owner === u.uid;
}
// ------------------------------------------------------

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    const path = url.pathname;
    const cors = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type,X-Secret,Authorization',
    };
    const json = (o, s = 200) => new Response(JSON.stringify(o), {
      status: s, headers: { ...cors, 'Content-Type': 'application/json' },
    });
    const deny = () => json({ error: 'yetkisiz' }, 401);
    if (req.method === 'OPTIONS') return new Response(null, { headers: cors });
    if (!env.FILES) return json({ error: 'FILES KV baglantisi yok' }, 500);
    const authRequired = env.REQUIRE_AUTH === 'true';

    // ---------- Kullanici: derleme baslat ----------
    if (req.method === 'POST' && path === '/build') {
      const user = await verifyIdToken(req, env);
      if (authRequired && !user) return json({ error: 'Devam etmek icin Google ile giris yapmalisin.' }, 401);
      const form = await req.formData();
      const file = form.get('zip');
      const appName = (form.get('appName') || '').toString().trim();
      const pkg = (form.get('packageName') || '').toString().trim();
      const versionName = (form.get('versionName') || '1.0.0').toString().trim();
      const versionCode = parseInt((form.get('versionCode') || '1').toString(), 10);
      let orientation = (form.get('orientation') || 'unspecified').toString();
      if (orientation === 'auto') orientation = 'unspecified';
      const icon = form.get('icon');
      const signMode = (form.get('signMode') || 'new').toString();
      const splashColor = (form.get('splashColor') || '#12161c').toString().trim();

      if (!file || typeof file === 'string') return json({ error: 'Dosya yok' }, 400);
      if (file.size > 20 * 1024 * 1024) return json({ error: 'Dosya en fazla 20 MB' }, 400);
      const bad = checkMeta({ pkg, appName, versionName, versionCode, orientation, splash: splashColor });
      if (bad) return json({ error: bad }, 400);
      if (!['new', 'own'].includes(signMode))
        return json({ error: 'Imzalama secenegi gecersiz' }, 400);

      let ukey = null, alias = '', storePass = '', keyPass = '';
      if (signMode === 'own') {
        const kf = form.get('keystore');
        alias = (form.get('alias') || '').toString().trim();
        storePass = (form.get('storePassword') || '').toString();
        keyPass = (form.get('keyPassword') || '').toString() || storePass;
        if (!kf || typeof kf === 'string' || kf.size === 0)
          return json({ error: 'Anahtar dosyasi yok' }, 400);
        if (kf.size > 200 * 1024) return json({ error: 'Anahtar dosyasi cok buyuk' }, 400);
        if (!alias || alias.length > 64 || /[\r\n]/.test(alias))
          return json({ error: 'Anahtar takma adi gecersiz' }, 400);
        if (!storePass || storePass.length > 128 || keyPass.length > 128 || /[\r\n]/.test(storePass + keyPass))
          return json({ error: 'Anahtar sifresi gecersiz' }, 400);
        ukey = await kf.arrayBuffer();
      }

      let iconBuf = null;
      if (icon && typeof icon !== 'string' && icon.size > 0) {
        if (icon.size > 1024 * 1024) return json({ error: 'Ikon en fazla 1 MB' }, 400);
        iconBuf = await icon.arrayBuffer();
        const head = new Uint8Array(iconBuf.slice(0, 8));
        if (!PNG_SIG.every((b, i) => head[i] === b)) return json({ error: 'Ikon PNG olmali' }, 400);
      }

      // Kullanim siniri: giris yapmis kullanici hesabina, digerleri IP'ye gore
      const { day, key: kSub, limit } = quotaOf(req, user);
      const kAll = 'rl:' + day + ':all';
      const nSub = parseInt((await env.FILES.get(kSub)) || '0', 10);
      const nAll = parseInt((await env.FILES.get(kAll)) || '0', 10);
      if (nAll >= GLOBAL_DAILY)
        return json({ error: 'Bugunluk toplam derleme siniri doldu. Yarin tekrar dene.' }, 429);
      if (nSub >= limit)
        return json({ error: 'Gunluk derleme hakkin doldu (' + limit + '). Yarin tekrar dene.' }, 429);

      const id = crypto.randomUUID();
      if (user) await env.FILES.put('owner:' + id, user.uid, { expirationTtl: TTL });
      if (iconBuf) await env.FILES.put('icon:' + id, iconBuf, { expirationTtl: TTL });
      if (signMode === 'own') {
        await env.FILES.put('ukeystore:' + id, ukey, { expirationTtl: TTL });
        await env.FILES.put('sign:' + id, JSON.stringify({ alias, storePass, keyPass }), { expirationTtl: TTL });
      }
      await env.FILES.put('zip:' + id, await file.arrayBuffer(), { expirationTtl: TTL });
      await env.FILES.put('status:' + id, 'queued', { expirationTtl: TTL });

      const r = await fetch(
        `https://api.github.com/repos/${env.GH_REPO}/actions/workflows/build.yml/dispatches`,
        {
          method: 'POST',
          headers: {
            Authorization: 'Bearer ' + env.GH_TOKEN,
            Accept: 'application/vnd.github+json',
            'User-Agent': 'apk-builder',
            'X-GitHub-Api-Version': '2022-11-28',
          },
          body: JSON.stringify({
            ref: 'main',
            inputs: {
              app_name: appName,
              package_name: pkg,
              job_id: id,
              version_name: versionName,
              version_code: String(versionCode),
              orientation: orientation,
              has_icon: iconBuf ? 'true' : 'false',
              sign_mode: signMode,
              splash_color: splashColor,
            },
          }),
        }
      );
      if (r.status !== 204)
        return json({ error: 'GitHub tetiklenemedi', detail: await r.text() }, 502);

      await env.FILES.put(kSub, String(nSub + 1), { expirationTtl: 90000 });
      await env.FILES.put(kAll, String(nAll + 1), { expirationTtl: 90000 });
      if (user)
        await dbRecordBuild(env, user.uid, id, {
          pkg, appName, versionName, versionCode, signMode, orientation, splash: splashColor,
        });
      return json({ id });
    }

    // ---------- Kullanici: projeler, gecmis, hesap (giris gerekir) ----------
    if (path === '/projects' || path.startsWith('/projects/') || path === '/history' || path === '/account') {
      const user = await verifyIdToken(req, env);
      if (!user) return deny();
      try {
        if (!(await ensureSchema(env))) return json({ error: 'Veritabani baglantisi yok' }, 501);
      } catch (e) {
        return json({ error: 'Veritabani hatasi' }, 500);
      }
      const uid = user.uid;
      const now = Math.floor(Date.now() / 1000);
      try {
        if (req.method === 'GET' && path === '/projects') {
          const r = await env.DB.prepare('SELECT pkg, app_name, version_name, version_code, orientation, splash, icon, updated_at FROM projects WHERE uid = ? ORDER BY updated_at DESC LIMIT ?')
            .bind(uid, MAX_PROJECTS).all();
          return json({
            projects: (r.results || []).map((x) => ({
              pkg: x.pkg, appName: x.app_name, vName: x.version_name, vCode: x.version_code,
              ori: x.orientation, splash: x.splash, icon: x.icon, time: x.updated_at * 1000,
            })),
          });
        }
        if (req.method === 'POST' && path === '/projects') {
          let b;
          try { b = await req.json(); } catch (e) { return json({ error: 'Gecersiz istek' }, 400); }
          const pkg = String(b.pkg || '');
          const appName = String(b.appName || '').trim();
          const vName = String(b.vName || '');
          const vCode = Number(b.vCode);
          let ori = String(b.ori || 'unspecified');
          if (ori === 'auto') ori = 'unspecified';
          const splash = String(b.splash || '#12161c');
          const icon = String(b.icon || '');
          const bad = checkMeta({ pkg, appName, versionName: vName, versionCode: vCode, orientation: ori, splash });
          if (bad) return json({ error: bad }, 400);
          if (icon && (!/^data:image\/(png|webp|jpeg);base64,/.test(icon) || icon.length > MAX_ICON_CHARS))
            return json({ error: 'Ikon gecersiz' }, 400);
          const c = await env.DB.prepare('SELECT COUNT(*) AS n, COALESCE(SUM(pkg = ?), 0) AS has FROM projects WHERE uid = ?').bind(pkg, uid).first();
          if (c && !c.has && c.n >= MAX_PROJECTS) return json({ error: 'En fazla ' + MAX_PROJECTS + ' proje kaydedilebilir' }, 400);
          await env.DB.prepare(UPSERT_PROJECT)
            .bind(uid, pkg, appName, vName, vCode, ori, splash, icon, now).run();
          return json({ ok: true });
        }
        if (req.method === 'DELETE' && path.startsWith('/projects/')) {
          const pkg = decodeURIComponent(path.slice('/projects/'.length));
          if (!PKG_RE.test(pkg)) return json({ error: 'Paket adi gecersiz' }, 400);
          await env.DB.prepare('DELETE FROM projects WHERE uid = ? AND pkg = ?').bind(uid, pkg).run();
          return json({ ok: true });
        }
        if (req.method === 'GET' && path === '/history') {
          const r = await env.DB.prepare('SELECT id, pkg, app_name, version_name, version_code, sign_mode, status, error_code, created_at, finished_at FROM builds WHERE uid = ? ORDER BY created_at DESC LIMIT 30')
            .bind(uid).all();
          return json({
            builds: (r.results || []).map((x) => ({
              id: x.id, pkg: x.pkg, appName: x.app_name, vName: x.version_name, vCode: x.version_code,
              signMode: x.sign_mode, status: x.status, code: x.error_code,
              createdAt: x.created_at * 1000,
              finishedAt: x.finished_at ? x.finished_at * 1000 : 0,
              available: x.status === 'done' && !!x.finished_at && x.finished_at + (TTL - 300) > now,
            })),
          });
        }
        if (req.method === 'DELETE' && path === '/account') {
          await env.DB.batch([
            env.DB.prepare('DELETE FROM projects WHERE uid = ?').bind(uid),
            env.DB.prepare('DELETE FROM builds WHERE uid = ?').bind(uid),
          ]);
          return json({ ok: true });
        }
      } catch (e) {
        return json({ error: 'Veritabani hatasi' }, 500);
      }
      return json({ error: 'bulunamadi' }, 404);
    }

    // ---------- Kullanici: kalan hak ----------
    if (req.method === 'GET' && path === '/me') {
      const user = await verifyIdToken(req, env);
      const { key, limit } = quotaOf(req, user);
      const used = parseInt((await env.FILES.get(key)) || '0', 10);
      return json({ signedIn: !!user, email: user ? user.email : '', limit, used, remaining: Math.max(0, limit - used) });
    }

    // ---------- Kullanici: durum ve indirme ----------
    if (req.method === 'GET' && path.startsWith('/status/')) {
      const id = path.split('/')[2];
      if (authRequired) {
        const u = await verifyIdToken(req, env);
        if (!u || (await env.FILES.get('owner:' + id)) !== u.uid) return deny();
      }
      const s = await env.FILES.get('status:' + id);
      const stage = s === 'queued' ? (await env.FILES.get('stage:' + id)) || '' : '';
      const reason = s === 'failed' ? (await env.FILES.get('reason:' + id)) || '' : '';
      const code = s === 'failed' ? (await env.FILES.get('code:' + id)) || '' : '';
      return json({ status: s || 'unknown', stage, reason, code });
    }
    // Giris yapmis kullanici icin kisa omurlu (10 dk) indirme baglantisi
    if (req.method === 'GET' && path.startsWith('/link/')) {
      const lid = path.split('/')[2];
      const t = url.searchParams.get('type');
      const type = FILE_TYPES[t] ? t : 'aab';
      const u = await verifyIdToken(req, env);
      if (!u || (await env.FILES.get('owner:' + lid)) !== u.uid) return deny();
      if (!env.WORKER_SECRET) return json({ error: 'sunucu ayari eksik' }, 500);
      const exp = Math.floor(Date.now() / 1000) + 600;
      const sig = await hmacHex(env.WORKER_SECRET, lid + ':' + type + ':' + exp);
      return json({ url: url.origin + '/download/' + lid + '?type=' + type + '&exp=' + exp + '&sig=' + sig });
    }
    if (req.method === 'GET' && path.startsWith('/download/')) {
      const t = url.searchParams.get('type');
      const type = FILE_TYPES[t] ? t : 'aab';
      const did = path.split('/')[2];
      if (authRequired && !(await canDownload(req, env, did, type, url)))
        return deny();
      const buf = await env.FILES.get(type + ':' + did, 'arrayBuffer');
      if (!buf) return json({ error: 'Dosya yok' }, 404);
      return new Response(buf, {
        headers: {
          ...cors,
          'Content-Type': FILE_TYPES[type],
          'Content-Disposition': 'attachment; filename="' + FILE_NAMES[type] + '"',
        },
      });
    }

    // ---------- GitHub: sadece gizli anahtarla ----------
    if (req.headers.get('X-Secret') !== env.WORKER_SECRET)
      return deny();
    const id = path.split('/')[2];

    if (req.method === 'GET' && path.startsWith('/zip/')) {
      const buf = await env.FILES.get('zip:' + id, 'arrayBuffer');
      if (!buf) return json({ error: 'Dosya yok' }, 404);
      return new Response(buf, { headers: { 'Content-Type': 'application/zip' } });
    }
    if (req.method === 'GET' && path.startsWith('/icon/')) {
      const buf = await env.FILES.get('icon:' + id, 'arrayBuffer');
      if (!buf) return json({ error: 'Ikon yok' }, 404);
      return new Response(buf, { headers: { 'Content-Type': 'image/png' } });
    }
    // Kullanicinin anahtar bilgileri: bir kez okunur, sonra silinir
    if (req.method === 'GET' && path.startsWith('/sign/')) {
      const v = await env.FILES.get('sign:' + id);
      if (!v) return json({ error: 'Bilgi yok' }, 404);
      await env.FILES.delete('sign:' + id);
      return new Response(v, { headers: { 'Content-Type': 'application/json' } });
    }
    if (req.method === 'GET' && path.startsWith('/ukeystore/')) {
      const buf = await env.FILES.get('ukeystore:' + id, 'arrayBuffer');
      if (!buf) return json({ error: 'Anahtar yok' }, 404);
      await env.FILES.delete('ukeystore:' + id);
      return new Response(buf, { headers: { 'Content-Type': 'application/octet-stream' } });
    }
    if (req.method === 'PUT' && path.startsWith('/result/')) {
      const t = url.searchParams.get('type');
      const type = FILE_TYPES[t] ? t : 'aab';
      await env.FILES.put(type + ':' + id, await req.arrayBuffer(), { expirationTtl: TTL });
      if (type === 'aab') {
        await env.FILES.put('status:' + id, 'done', { expirationTtl: TTL });
        await dbExec(env, "UPDATE builds SET status = 'done', finished_at = ? WHERE id = ?", nowSec(), id);
      }
      return json({ ok: true });
    }
    if (req.method === 'POST' && path.startsWith('/progress/')) {
      const stage = url.searchParams.get('stage') || '';
      if (!STAGES.includes(stage)) return json({ error: 'gecersiz asama' }, 400);
      await env.FILES.put('stage:' + id, stage, { expirationTtl: TTL });
      return json({ ok: true });
    }
    if (req.method === 'POST' && path.startsWith('/fail/')) {
      const reason = ((await req.text()) || '').slice(0, 200);
      const code = (url.searchParams.get('code') || '').replace(/[^a-z]/g, '').slice(0, 20);
      await env.FILES.put('code:' + id, code, { expirationTtl: TTL });
      await env.FILES.put('reason:' + id, reason, { expirationTtl: TTL });
      await env.FILES.put('status:' + id, 'failed', { expirationTtl: TTL });
      await dbExec(env, "UPDATE builds SET status = 'failed', error_code = ?, finished_at = ? WHERE id = ?", code, nowSec(), id);
      return json({ ok: true });
    }
    return json({ error: 'bulunamadi' }, 404);
  },
};
