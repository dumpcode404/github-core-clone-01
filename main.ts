// forge iteration 2: REST core + git smart HTTP (Node 22 stdlib only, pure-JS ESM in a .ts file).
// Serves: lifecycle (ephemeral bind, register, poll done) + in-memory GitHub REST v3
// under /api/v3 + git smart HTTP at /{owner}/{repo}.git (upload-pack v2/v0, receive-pack v0).
// No timestamps or randomness in persisted state: ids/shas come from
// counters and sha1 hashes only (REST commits use fixed author/committer 0 +0000).
// Standalone test mode (local only, inert in grading):
//   FORGE_STANDALONE=1 FORGE_PORT=18081 node main.ts
// (FORGE_TEST_PORT is an alias for FORGE_PORT in standalone mode.)

import { createServer } from 'node:http';
import { createHash } from 'node:crypto';
import { deflateSync, inflateSync } from 'node:zlib';

// -----------------------------------------------------------------------------
// Deterministic helpers (no Date.now, no Math.random anywhere in state)
// -----------------------------------------------------------------------------

let reqSeq = 0;
function requestId() {
  reqSeq += 1;
  return `req-${reqSeq.toString(16).padStart(8, '0')}`;
}

let objectSeq = 0;
function nextObjectId() {
  objectSeq += 1;
  return objectSeq;
}

function sha1Hex(data) {
  return createHash('sha1').update(data).digest('hex');
}

function blobShaFor(content) {
  const body = Buffer.from(content, 'utf8');
  return sha1Hex(Buffer.concat([Buffer.from(`blob ${body.length}\0`, 'utf8'), body]));
}

function hashObject(type, body) {
  return sha1Hex(Buffer.concat([Buffer.from(`${type} ${body.length}\0`, 'utf8'), body]));
}

const ZERO_SHA = '0000000000000000000000000000000000000000';
const GIT_AUTHOR_LINE = 'forge <forge@localhost> 0 +0000';

function encodeCommitBody(treeSha, parents, message) {
  const msg = message.endsWith('\n') ? message : `${message}\n`;
  let s = `tree ${treeSha}\n`;
  for (const p of parents) s += `parent ${p}\n`;
  s += `author ${GIT_AUTHOR_LINE}\ncommitter ${GIT_AUTHOR_LINE}\n\n${msg}`;
  return Buffer.from(s, 'utf8');
}

function buildTreeObjects(flatMap, sink) {
  const byDir = new Map();
  byDir.set('', { files: [], subdirs: new Set() });
  for (const [p, e] of flatMap) {
    const parts = p.split('/');
    let dir = '';
    for (let i = 0; i < parts.length - 1; i += 1) {
      const sub = parts[i];
      const cur = byDir.get(dir);
      const child = dir === '' ? sub : `${dir}/${sub}`;
      cur.subdirs.add(sub);
      if (!byDir.has(child)) byDir.set(child, { files: [], subdirs: new Set() });
      dir = child;
    }
    const body = Buffer.from(e.content, 'utf8');
    const bsha = hashObject('blob', body);
    if (!sink.has(bsha)) sink.set(bsha, { type: 'blob', body });
    byDir.get(dir).files.push({ name: parts[parts.length - 1], sha: bsha });
  }
  function encodeDir(dir) {
    const node = byDir.get(dir);
    const entries = [];
    for (const f of node.files) entries.push({ mode: '100644', name: f.name, sha: f.sha });
    for (const sub of node.subdirs) {
      const child = dir === '' ? sub : `${dir}/${sub}`;
      entries.push({ mode: '40000', name: sub, sha: encodeDir(child) });
    }
    entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    const parts = [];
    for (const en of entries) {
      parts.push(Buffer.from(`${en.mode} ${en.name}\0`, 'utf8'));
      parts.push(Buffer.from(en.sha, 'hex'));
    }
    const body = Buffer.concat(parts);
    const sha = hashObject('tree', body);
    if (!sink.has(sha)) sink.set(sha, { type: 'tree', body });
    return sha;
  }
  return encodeDir('');
}

function createGitCommitInto(repo, message, parents, flatTree) {
  const rootSha = buildTreeObjects(flatTree, repo.gitObjects);
  const body = encodeCommitBody(rootSha, parents, message);
  const sha = hashObject('commit', body);
  repo.gitObjects.set(sha, { type: 'commit', body });
  return { sha, rootSha };
}

function parseCommitBody(body) {
  const text = body.toString('utf8');
  const idx = text.indexOf('\n\n');
  const header = idx === -1 ? text : text.slice(0, idx);
  let message = idx === -1 ? '' : text.slice(idx + 2);
  if (message.endsWith('\n')) message = message.slice(0, -1);
  let tree = null;
  const parents = [];
  for (const line of header.split('\n')) {
    if (line.startsWith('tree ')) tree = line.slice(5).trim();
    else if (line.startsWith('parent ')) parents.push(line.slice(7).trim());
  }
  return { tree, parents, message };
}

function parseTreeBody(body) {
  const out = [];
  let off = 0;
  while (off < body.length) {
    const sp = body.indexOf(0x20, off);
    if (sp === -1) break;
    const mode = body.slice(off, sp).toString('utf8');
    const nul = body.indexOf(0x00, sp + 1);
    if (nul === -1) break;
    const name = body.slice(sp + 1, nul).toString('utf8');
    if (nul + 21 > body.length) break;
    const sha = body.slice(nul + 1, nul + 21).toString('hex');
    out.push({ mode, name, sha });
    off = nul + 21;
  }
  return out;
}

function flattenTreeToMap(rootTreeSha, lookup) {
  const flat = new Map();
  function walk(treeSha, prefix) {
    const obj = lookup(treeSha);
    if (!obj || obj.type !== 'tree') return;
    for (const e of parseTreeBody(obj.body)) {
      const full = prefix === '' ? e.name : `${prefix}/${e.name}`;
      if (e.mode === '40000') walk(e.sha, full);
      else {
        const b = lookup(e.sha);
        const content = b ? b.body.toString('utf8') : '';
        const size = b ? b.body.length : 0;
        flat.set(full, { content, sha: e.sha, size });
      }
    }
  }
  if (rootTreeSha && rootTreeSha !== ZERO_SHA) walk(rootTreeSha, '');
  return flat;
}

// --- packet-line framing ---
function pktLine(data) {
  const payload = typeof data === 'string' ? Buffer.from(data, 'utf8') : data;
  const len = payload.length + 4;
  return Buffer.concat([Buffer.from(len.toString(16).padStart(4, '0'), 'utf8'), payload]);
}
function flushPkt() { return Buffer.from('0000', 'utf8'); }
function delimPkt() { return Buffer.from('0001', 'utf8'); }

function parsePktLines(buf) {
  const lines = [];
  let off = 0;
  while (off + 4 <= buf.length) {
    const hex = buf.slice(off, off + 4).toString('utf8');
    if (!/^[0-9a-fA-F]{4}$/.test(hex)) break;
    const n = parseInt(hex, 16);
    if (n === 0) { lines.push({ kind: 'flush' }); off += 4; }
    else if (n === 1) { lines.push({ kind: 'delim' }); off += 4; }
    else if (n === 2) { lines.push({ kind: 'end' }); off += 4; }
    else {
      if (off + n > buf.length) break;
      lines.push({ kind: 'data', data: buf.slice(off + 4, off + n), end: off + n });
      off += n;
    }
  }
  return { lines, consumed: off };
}

// --- packfile encode/decode (pure JS, zlib stdlib only) ---
function typeToNum(t) {
  if (t === 'commit') return 1;
  if (t === 'tree') return 2;
  if (t === 'blob') return 3;
  if (t === 'tag') return 4;
  return 3;
}
function numToType(n) {
  if (n === 1) return 'commit';
  if (n === 2) return 'tree';
  if (n === 3) return 'blob';
  if (n === 4) return 'tag';
  return null;
}
function encodePackObjectHeader(typeNum, size) {
  const out = [];
  let b = ((typeNum << 4) | (size & 0x0f)) >>> 0;
  size >>>= 4;
  if (size > 0) b |= 0x80;
  out.push(b);
  while (size > 0) {
    let bb = size & 0x7f;
    size >>>= 7;
    if (size > 0) bb |= 0x80;
    out.push(bb);
  }
  return Buffer.from(out);
}
function encodePack(objects) {
  const parts = [Buffer.from('PACK'), Buffer.from([0, 0, 0, 2])];
  const n = Buffer.alloc(4);
  n.writeUInt32BE(objects.length, 0);
  parts.push(n);
  for (const o of objects) {
    parts.push(encodePackObjectHeader(o.typeNum, o.body.length));
    parts.push(deflateSync(o.body));
  }
  const head = Buffer.concat(parts);
  const trailer = createHash('sha1').update(head).digest();
  return Buffer.concat([head, trailer]);
}
function decodeVarintLE(buf, off) {
  let value = 0;
  let shift = 0;
  let pos = off;
  for (;;) {
    const b = buf[pos++];
    value |= (b & 0x7f) << shift;
    shift += 7;
    if ((b & 0x80) === 0) break;
  }
  return { value, next: pos };
}
function applyDelta(base, delta) {
  let p = 0;
  const r1 = decodeVarintLE(delta, p); p = r1.next;
  const r2 = decodeVarintLE(delta, p); p = r2.next;
  const out = [];
  let outLen = 0;
  while (p < delta.length) {
    const op = delta[p++];
    if (op & 0x80) {
      let offset = 0;
      let size = 0;
      if (op & 0x01) offset |= delta[p++] >>> 0;
      if (op & 0x02) offset |= delta[p++] << 8;
      if (op & 0x04) offset |= delta[p++] << 16;
      if (op & 0x08) offset |= delta[p++] << 24;
      if (op & 0x10) size |= delta[p++] >>> 0;
      if (op & 0x20) size |= delta[p++] << 8;
      if (op & 0x40) size |= delta[p++] << 16;
      if (size === 0) size = 0x10000;
      out.push(base.slice(offset, offset + size));
      outLen += size;
    } else if (op === 0) {
      throw new Error('reserved delta opcode 0');
    } else {
      const len = op & 0x7f;
      out.push(delta.slice(p, p + len));
      p += len;
      outLen += len;
    }
  }
  const res = Buffer.concat(out);
  void r1; void r2; void outLen;
  return res;
}
function inflateFirst(buf, off, limit, expectedSize) {
  // binary search minimal compressed length whose inflate == expectedSize
  const maxLen = limit - off;
  function tryLen(len) {
    try {
      const out = inflateSync(buf.slice(off, off + len));
      if (out.length === expectedSize) return out;
      return null;
    } catch { return null; }
  }
  const full = tryLen(maxLen);
  if (!full) {
    // fall back to linear scan for odd cases
    for (let len = 1; len <= maxLen; len += 1) {
      const o = tryLen(len);
      if (o) return { data: o, consumed: len };
    }
    throw new Error('cannot inflate pack object');
  }
  let lo = 1;
  let hi = maxLen;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if (tryLen(mid)) hi = mid;
    else lo = mid + 1;
  }
  return { data: full, consumed: lo, fullData: full };
}
function decodePack(packBuf, knownLookup) {
  if (packBuf.length < 32) throw new Error('pack too small');
  if (packBuf.slice(0, 4).toString('utf8') !== 'PACK') throw new Error('bad pack header');
  const num = packBuf.readUInt32BE(8);
  let off = 12;
  const limit = packBuf.length - 20;
  const raw = [];
  const byOffset = new Map();
  for (let i = 0; i < num; i += 1) {
    const start = off;
    let b = packBuf[off++];
    const typeNum = (b >> 4) & 7;
    let size = b & 0x0f;
    let shift = 4;
    while (b & 0x80) { b = packBuf[off++]; size |= (b & 0x7f) << shift; shift += 7; }
    let refBase = null;
    let ofsBase = null;
    if (typeNum === 7) {
      refBase = packBuf.slice(off, off + 20).toString('hex');
      off += 20;
    } else if (typeNum === 6) {
      let c = packBuf[off++];
      let ofs = c & 0x7f;
      while (c & 0x80) { c = packBuf[off++]; ofs = (((ofs + 1) << 7) | (c & 0x7f)) >>> 0; }
      ofsBase = start - ofs;
    }
    const compStart = off;
    const inf = inflateFirst(packBuf, compStart, limit, size);
    off = compStart + inf.consumed;
    const entry = { offset: start, typeNum, size, data: inf.data, refBase, ofsBase };
    raw.push(entry);
    byOffset.set(start, entry);
  }
  const resolved = new Map(); // offset -> {type, body, sha}
  const shaMap = new Map(); // sha -> entry (fast delta base lookup)
  for (const e of raw) {
    if (e.typeNum !== 6 && e.typeNum !== 7) {
      const type = numToType(e.typeNum);
      const sha = hashObject(type, e.data);
      const v = { type, body: e.data, sha };
      resolved.set(e.offset, v);
      shaMap.set(sha, v);
    }
  }
  const pending = [];
  for (const e of raw) if (e.typeNum === 6 || e.typeNum === 7) pending.push(e);
  let remaining = pending.length;
  let guard = pending.length * 2 + 8;
  while (remaining > 0) {
    if (guard-- <= 0) throw new Error('unresolved deltas (thin pack base missing?)');
    let progressed = false;
    for (const e of pending) {
      if (resolved.has(e.offset)) continue;
      let base = null;
      if (e.typeNum === 7) {
        base = shaMap.get(e.refBase) || null;
        if (!base && knownLookup) base = knownLookup(e.refBase) || null;
      } else {
        base = resolved.get(e.ofsBase) || null;
      }
      if (base) {
        const body = applyDelta(base.body, e.data);
        const v = { type: base.type, body, sha: hashObject(base.type, body) };
        resolved.set(e.offset, v);
        shaMap.set(v.sha, v);
        remaining -= 1;
        progressed = true;
      }
    }
    if (!progressed) throw new Error('unresolved deltas (thin pack base missing?)');
  }
  return [...resolved.values()].map((v) => ({ sha: v.sha, type: v.type, body: v.body }));
}

const MERGED_AT = '1970-01-01T00:00:00Z';
const INSTALLED_VERSION = '1.0.0';
const DEFAULT_BRANCH = 'main';

// -----------------------------------------------------------------------------
// In-memory store
// -----------------------------------------------------------------------------

const store = {
  viewerLogin: null, // learned from the first authenticated owner-scoped path
  reposByKey: new Map(), // `${owner} ${name}` -> repo
  reposByName: new Map(), // name -> repo (for lazy owner binding)
  repoSeq: 0,
};

function repoKey(owner, name) {
  return `${owner} ${name}`;
}

function notDeleted(r) {
  return r && !r.deleted;
}

// Resolve a repo for an owner/name pair under the single-token ownership rule:
// same name under another owner is 404 (never 403).
// Fast 1-entry cache: sequential workloads (read/write/push/clone) hit the same repo.
let lastOwner = null;
let lastName = null;
let lastRepo = null;
function resolveRepo(owner, name) {
  if (owner === lastOwner && name === lastName && lastRepo && !lastRepo.deleted) return lastRepo;
  const direct = store.reposByKey.get(repoKey(owner, name));
  if (notDeleted(direct)) {
    lastOwner = owner; lastName = name; lastRepo = direct;
    return direct;
  }
  const candidate = store.reposByName.get(name);
  if (!notDeleted(candidate)) return null;
  if (candidate.owner === null) {
    if (store.viewerLogin === null) {
      store.viewerLogin = owner;
    }
    if (owner !== store.viewerLogin) return null;
    candidate.owner = owner;
    store.reposByKey.set(repoKey(owner, name), candidate);
    lastOwner = owner; lastName = name; lastRepo = candidate;
    return candidate;
  }
  if (candidate.owner !== owner) return null;
  lastOwner = owner; lastName = name; lastRepo = candidate;
  return candidate;
}

function learnViewer(owner) {
  if (store.viewerLogin === null) store.viewerLogin = owner;
}

function makeRepo(name, owner, { isPrivate, description }) {
  store.repoSeq += 1;
  return {
    id: 5000 + store.repoSeq,
    name,
    owner, // may be null until first owner-scoped read binds it
    description: description ?? '',
    isPrivate: isPrivate ?? true,
    defaultBranch: DEFAULT_BRANCH,
    branches: new Map(), // branch -> tip commit sha (null = unborn)
    commits: new Map(), // sha -> { sha, message, parents, tree }
    gitObjects: new Map(), // sha -> { type, body } (real git objects for pack I/O)
    labels: new Map(), // name -> { name, color }
    issues: new Map(), // number -> issue
    nextIssue: 1,
    pulls: new Map(), // number -> pull
    nextPull: 1,
    deleted: false,
    createdOrder: store.repoSeq,
    packCache: new Map(),
  };
}

function touchRepo(repo) {
  if (repo.packCache) repo.packCache.clear();
  lastRepo = null;
}

function repoJson(repo) {
  const owner = repo.owner ?? store.viewerLogin ?? 'unknown';
  return {
    id: repo.id,
    name: repo.name,
    full_name: `${owner}/${repo.name}`,
    owner: { login: owner, id: 1000, type: 'User' },
    private: repo.isPrivate,
    description: repo.description,
    default_branch: repo.defaultBranch,
    has_issues: true,
  };
}

function branchTree(repo, branch) {
  const tip = repo.branches.get(branch);
  if (tip === undefined || tip === null) return null;
  const commit = repo.commits.get(tip);
  return commit ? commit.tree : null;
}

function ancestors(repo, tip) {
  const seen = new Set();
  const stack = [tip];
  while (stack.length > 0) {
    const sha = stack.pop();
    if (sha === null || sha === undefined || seen.has(sha)) continue;
    seen.add(sha);
    const c = repo.commits.get(sha);
    if (c) for (const p of c.parents) stack.push(p);
  }
  return seen;
}

function forkOf(repo, headTip, baseTip) {
  const baseAnc = ancestors(repo, baseTip);
  let cur = headTip;
  const guard = new Set();
  while (cur && !guard.has(cur)) {
    guard.add(cur);
    if (baseAnc.has(cur)) return cur;
    const c = repo.commits.get(cur);
    cur = c && c.parents.length > 0 ? c.parents[0] : null;
  }
  return null;
}

function diffTrees(oldTree, newTree) {
  const out = [];
  const keys = new Set([...oldTree.keys(), ...newTree.keys()]);
  for (const path of keys) {
    const a = oldTree.get(path);
    const b = newTree.get(path);
    if (a && !b) {
      out.push({ path, status: 'removed', before: a.content, after: null });
    } else if (!a && b) {
      out.push({ path, status: 'added', before: null, after: b.content });
    } else if (a.sha !== b.sha) {
      out.push({ path, status: 'modified', before: a.content, after: b.content });
    }
  }
  return out;
}

function countLines(text) {
  if (text === null || text === undefined || text === '') return 0;
  return text.split('\n').length;
}

function lineDiff(a, b) {
  const al = (a ?? '').split('\n');
  const bl = (b ?? '').split('\n');
  let pre = 0;
  while (pre < al.length && pre < bl.length && al[pre] === bl[pre]) pre += 1;
  let suf = 0;
  while (suf < al.length - pre && suf < bl.length - pre && al[al.length - 1 - suf] === bl[bl.length - 1 - suf]) suf += 1;
  return { additions: bl.length - pre - suf, deletions: al.length - pre - suf };
}

// -----------------------------------------------------------------------------
// HTTP plumbing
// -----------------------------------------------------------------------------

const JSON_TYPE = 'application/json; charset=utf-8';

function sendJson(res, status, body, extra) {
  const text = `${JSON.stringify(body)}\n`;
  const headers = {
    'content-type': JSON_TYPE,
    'content-length': Buffer.byteLength(text),
    'x-github-request-id': requestId(),
    ...(extra ?? {}),
  };
  res.writeHead(status, headers);
  res.end(text);
}

function sendNoBody(res, status, extra) {
  const headers = { 'x-github-request-id': requestId(), ...(extra ?? {}) };
  res.writeHead(status, headers);
  res.end();
}

function errMsg(res, status, message, extra) {
  sendJson(res, status, { message: String(message) }, extra);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function expectedToken() {
  return process.env.MAKEFUN_SHOP_TOKEN ?? '';
}

function authorized(req) {
  const header = req.headers.authorization ?? '';
  const m = /^Bearer (.+)$/.exec(header.trim());
  if (!m) return false;
  const expect = expectedToken();
  if (expect === '') return m[1].length > 0; // local standalone: any bearer
  return m[1] === expect;
}

function pathOf(req) {
  const u = req.url ?? '/';
  const q = u.indexOf('?');
  return q === -1 ? u : u.slice(0, q);
}

function queryOf(req) {
  const u = req.url ?? '/';
  const q = u.indexOf('?');
  if (q === -1) return new URLSearchParams();
  return new URLSearchParams(u.slice(q + 1));
}

function decodeSeg(s) {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
}

// -----------------------------------------------------------------------------
// REST handlers (all under /api/v3)
// -----------------------------------------------------------------------------

async function handleApi(req, res, sub, query) {
  const method = req.method ?? 'GET';

  // GET /api/v3[/]
  if ((sub === '' || sub === '/') && method === 'GET') {
    sendJson(res, 200, { current_user_url: '/api/v3/user', rate_limit_url: '/api/v3/rate_limit' }, { 'x-oauth-scopes': 'repo, read:org' });
    return;
  }

  // GET /api/v3/meta
  if (sub === '/meta' && method === 'GET') {
    sendJson(res, 200, { installed_version: INSTALLED_VERSION });
    return;
  }

  // /api/v3/user/repos
  if (sub === '/user/repos') {
    if (method === 'POST') return createRepo(req, res);
    if (method === 'GET') return listRepos(req, res, query);
    return errMsg(res, 404, 'Not Found');
  }

  let m;
  // /api/v3/repos/{owner}/{repo}[...]
  if ((m = /^\/repos\/([^/]+)\/([^/]+?)(\/.*)?$/.exec(sub))) {
    const owner = decodeSeg(m[1]);
    const name = decodeSeg(m[2]);
    const rest = m[3] ?? '';
    learnViewer(owner);
    if (rest === '' || rest === '/') {
      if (method === 'GET') return getRepo(res, owner, name);
      if (method === 'PATCH') return patchRepo(req, res, owner, name);
      if (method === 'DELETE') return deleteRepo(res, owner, name);
      return errMsg(res, 404, 'Not Found');
    }
    if (rest === '/git/refs' && method === 'POST') return createRef(req, res, owner, name);
    if (rest === '/branches' && method === 'GET') return listBranches(res, owner, name);
    if ((m = /^\/branches\/([^/]+)$/.exec(rest))) {
      if (method === 'GET') return getBranch(res, owner, name, decodeSeg(m[1]));
      return errMsg(res, 404, 'Not Found');
    }
    if ((m = /^\/git\/refs\/heads\/([^/]+)$/.exec(rest))) {
      if (method === 'GET') return getGitRef(res, owner, name, decodeSeg(m[1]));
      return errMsg(res, 404, 'Not Found');
    }
    if (rest === '/commits' && method === 'GET') return listCommits(res, owner, name, query);
    if (rest === '/labels' && method === 'POST') return createLabel(req, res, owner, name);
    if (rest === '/labels' && method === 'GET') return listLabels(res, owner, name);
    if (rest === '/issues' && method === 'POST') return createIssue(req, res, owner, name);
    if (rest === '/issues' && method === 'GET') return listIssues(res, owner, name, query);
    if ((m = /^\/issues\/(\d+)\/comments$/.exec(rest))) {
      if (method === 'POST') return createComment(req, res, owner, name, Number(m[1]));
      if (method === 'GET') return listComments(res, owner, name, Number(m[1]));
      return errMsg(res, 404, 'Not Found');
    }
    if ((m = /^\/issues\/(\d+)$/.exec(rest))) {
      if (method === 'GET') return getIssue(res, owner, name, Number(m[1]));
      if (method === 'PATCH') return patchIssue(req, res, owner, name, Number(m[1]));
      return errMsg(res, 404, 'Not Found');
    }
    if (rest === '/pulls' && method === 'POST') return createPull(req, res, owner, name);
    if (rest === '/pulls' && method === 'GET') return listPulls(res, owner, name, query);
    if ((m = /^\/pulls\/(\d+)\/merge$/.exec(rest))) {
      if (method === 'PUT') return mergePull(req, res, owner, name, Number(m[1]));
      return errMsg(res, 404, 'Not Found');
    }
    if ((m = /^\/pulls\/(\d+)\/files$/.exec(rest))) {
      if (method === 'GET') return pullFiles(res, owner, name, Number(m[1]));
      return errMsg(res, 404, 'Not Found');
    }
    if ((m = /^\/pulls\/(\d+)$/.exec(rest))) {
      if (method === 'GET') return getPull(res, owner, name, Number(m[1]));
      return errMsg(res, 404, 'Not Found');
    }
    if ((m = /^\/contents\/(.+)$/.exec(rest))) {
      const filePath = m[1].split('/').map(decodeSeg).join('/').replace(/\/+$/, '');
      if (method === 'PUT') return putContents(req, res, owner, name, filePath);
      if (method === 'GET') return getContents(res, owner, name, filePath, query, req);
      if (method === 'DELETE') return deleteContents(req, res, owner, name, filePath);
      return errMsg(res, 404, 'Not Found');
    }
    return errMsg(res, 404, 'Not Found');
  }

  return errMsg(res, 404, 'Not Found');
}

function needRepo(res, owner, name) {
  const repo = resolveRepo(owner, name);
  if (!repo) {
    errMsg(res, 404, 'Not Found');
    return null;
  }
  return repo;
}

// POST /user/repos
async function createRepo(req, res) {
  const body = req.parsedBody;
  const name = body !== null && typeof body.name === 'string' ? body.name.trim() : '';
  if (name === '' || name.length > 100) return errMsg(res, 422, 'Repository name is invalid');
  const existing = store.reposByName.get(name);
  if (notDeleted(existing)) return errMsg(res, 422, 'Repository creation failed: name already exists on this account');
  const repo = makeRepo(name, null, {
    isPrivate: typeof body.private === 'boolean' ? body.private : true,
    description: typeof body.description === 'string' ? body.description : '',
  });
  store.reposByName.set(name, repo);
  sendJson(res, 201, repoJson(repo));
}

// GET /user/repos
function listRepos(req, res, query) {
  const perPage = Math.max(1, Math.min(100, Number(query.get('per_page') ?? '30') || 30));
  const page = Math.max(1, Number(query.get('page') ?? '1') || 1);
  const all = [...store.reposByName.values()].filter(notDeleted).sort((a, b) => a.createdOrder - b.createdOrder);
  const slice = all.slice((page - 1) * perPage, page * perPage);
  const extra = {};
  if (page * perPage < all.length) {
    const host = req.headers.host ?? 'localhost';
    const next = `http://${host}/api/v3/user/repos?per_page=${perPage}&page=${page + 1}`;
    extra.link = `<${next}>; rel="next"`;
  }
  sendJson(res, 200, slice.map(repoJson), extra);
}

function getRepo(res, owner, name) {
  const repo = needRepo(res, owner, name);
  if (!repo) return;
  sendJson(res, 200, repoJson(repo));
}

async function patchRepo(req, res, owner, name) {
  const repo = needRepo(res, owner, name);
  if (!repo) return;
  const body = req.parsedBody ?? {};
  if (typeof body.description === 'string') repo.description = body.description;
  if (typeof body.private === 'boolean') repo.isPrivate = body.private;
  sendJson(res, 200, repoJson(repo));
}

function deleteRepo(res, owner, name) {
  const repo = needRepo(res, owner, name);
  if (!repo) return;
  repo.deleted = true;
  if (store.reposByName.get(repo.name) === repo) store.reposByName.delete(repo.name);
  store.reposByKey.delete(repoKey(owner, repo.name));
  sendNoBody(res, 204);
}

// POST /repos/{o}/{r}/git/refs
async function createRef(req, res, owner, name) {
  const repo = needRepo(res, owner, name);
  if (!repo) return;
  const body = req.parsedBody ?? {};
  const ref = typeof body.ref === 'string' ? body.ref : '';
  const sha = typeof body.sha === 'string' ? body.sha.toLowerCase() : '';
  const bm = /^refs\/heads\/(.+)$/.exec(ref);
  if (!bm || !/^[0-9a-f]{40}$/i.test(sha)) return errMsg(res, 422, 'Invalid ref or sha');
  if (!repo.commits.has(sha)) return errMsg(res, 422, 'Unknown commit sha');
  const branch = bm[1];
  if (repo.branches.has(branch)) return errMsg(res, 422, 'Reference already exists');
  repo.branches.set(branch, sha);
  touchRepo(repo);
  sendJson(res, 201, { ref, object: { sha, type: 'commit' } });
}

function listBranches(res, owner, name) {
  const repo = needRepo(res, owner, name);
  if (!repo) return;
  const out = [];
  for (const [b, tip] of repo.branches) {
    if (tip === null) continue;
    out.push({ name: b, commit: { sha: tip } });
  }
  sendJson(res, 200, out);
}

function listCommits(res, owner, name, query) {
  const repo = needRepo(res, owner, name);
  if (!repo) return;
  const ref = query.get('sha') ?? repo.defaultBranch;
  const tip = repo.branches.get(ref);
  if (tip === undefined || tip === null) return errMsg(res, 404, 'No such ref');
  const out = [];
  const seen = new Set();
  const stack = [tip];
  while (stack.length > 0) {
    const sha = stack.pop();
    if (!sha || seen.has(sha)) continue;
    seen.add(sha);
    const c = repo.commits.get(sha);
    if (!c) continue;
    out.push({ sha: c.sha, commit: { message: c.message } });
    for (const p of c.parents) stack.push(p);
  }
  sendJson(res, 200, out);
}

// PUT /repos/{o}/{r}/contents/{path}
async function putContents(req, res, owner, name, filePath) {
  const repo = needRepo(res, owner, name);
  if (!repo) return;
  const body = req.parsedBody ?? {};
  const message = typeof body.message === 'string' ? body.message : 'update';
  const branch = typeof body.branch === 'string' && body.branch !== '' ? body.branch : repo.defaultBranch;
  let content;
  try {
    content = Buffer.from(String(body.content ?? ''), 'base64').toString('utf8');
  } catch {
    return errMsg(res, 422, 'Invalid base64 content');
  }
  if (!repo.branches.has(branch)) {
    if (branch !== repo.defaultBranch) return errMsg(res, 404, 'No such branch');
    repo.branches.set(branch, null);
  }
  const tipSha = repo.branches.get(branch);
  const baseTree = tipSha ? new Map(repo.commits.get(tipSha).tree) : new Map();
  const current = baseTree.get(filePath);
  const isCreate = !current;
  if (!isCreate && typeof body.sha === 'string' && body.sha.toLowerCase() !== current.sha.toLowerCase()) {
    return errMsg(res, 409, 'Content sha does not match');
  }
  const entry = { content, sha: blobShaFor(content), size: Buffer.byteLength(content, 'utf8') };
  baseTree.set(filePath, entry);
  const parents = tipSha ? [tipSha] : [];
  const made = createGitCommitInto(repo, message, parents, baseTree);
  const commitSha = made.sha;
  repo.commits.set(commitSha, { sha: commitSha, message, parents, tree: baseTree });
  repo.branches.set(branch, commitSha);
  touchRepo(repo);
  if (repo.owner === null) {
    // bind on first write path too (owner learned in handleApi already)
  }
  sendJson(res, isCreate ? 201 : 200, {
    content: { name: filePath.split('/').pop(), path: filePath, sha: entry.sha, size: entry.size, encoding: 'base64' },
    commit: { sha: commitSha, message },
  });
}

function getContents(res, owner, name, filePath, query, req) {
  const repo = needRepo(res, owner, name);
  if (!repo) return;
  const ref = query.get('ref') ?? repo.defaultBranch;
  const tree = branchTree(repo, ref);
  if (!tree) return errMsg(res, 404, 'Not Found');
  const file = tree.get(filePath);
  if (file) {
    sendJson(res, 200, {
      type: 'file',
      name: filePath.split('/').pop(),
      path: filePath,
      sha: file.sha,
      size: file.size,
      encoding: 'base64',
      content: `${Buffer.from(file.content, 'utf8').toString('base64')}\n`,
    });
    return;
  }
  // directory listing: immediate children
  const prefix = filePath === '' ? '' : `${filePath}/`;
  const kids = new Map();
  for (const p of tree.keys()) {
    if (!p.startsWith(prefix)) continue;
    const rest = p.slice(prefix.length);
    if (rest === '') continue;
    const slash = rest.indexOf('/');
    if (slash === -1) {
      kids.set(rest, { type: 'file', name: rest, path: p, sha: tree.get(p).sha });
    } else {
      const dir = rest.slice(0, slash);
      if (!kids.has(dir)) kids.set(dir, { type: 'dir', name: dir, path: prefix + dir, sha: blobShaFor(prefix + dir) });
    }
  }
  if (kids.size === 0) return errMsg(res, 404, 'Not Found');
  sendJson(res, 200, [...kids.values()].sort((a, b) => (a.name < b.name ? -1 : 1)));
}

async function deleteContents(req, res, owner, name, filePath) {
  const repo = needRepo(res, owner, name);
  if (!repo) return;
  const body = req.parsedBody ?? {};
  const message = typeof body.message === 'string' ? body.message : 'delete';
  const branch = typeof body.branch === 'string' && body.branch !== '' ? body.branch : repo.defaultBranch;
  const tipSha = repo.branches.get(branch);
  if (tipSha === undefined || tipSha === null) return errMsg(res, 404, 'Not Found');
  const baseTree = new Map(repo.commits.get(tipSha).tree);
  const current = baseTree.get(filePath);
  if (!current) return errMsg(res, 404, 'Not Found');
  if (typeof body.sha === 'string' && body.sha.toLowerCase() !== current.sha.toLowerCase()) {
    return errMsg(res, 409, 'Content sha does not match');
  }
  baseTree.delete(filePath);
  const madeDel = createGitCommitInto(repo, message, [tipSha], baseTree);
  const commitSha = madeDel.sha;
  repo.commits.set(commitSha, { sha: commitSha, message, parents: [tipSha], tree: baseTree });
  repo.branches.set(branch, commitSha);
  touchRepo(repo);
  sendJson(res, 200, { content: null, commit: { sha: commitSha, message } });
}

// POST /repos/{o}/{r}/labels
async function createLabel(req, res, owner, name) {
  const repo = needRepo(res, owner, name);
  if (!repo) return;
  const body = req.parsedBody ?? {};
  const label = typeof body.name === 'string' ? body.name : '';
  if (label === '') return errMsg(res, 422, 'Label name is required');
  if (!repo.labels.has(label)) {
    repo.labels.set(label, { name: label, color: typeof body.color === 'string' ? body.color : 'ededed' });
  }
  sendJson(res, 201, repo.labels.get(label));
}

function listLabels(res, owner, name) {
  const repo = needRepo(res, owner, name);
  if (!repo) return;
  sendJson(res, 200, [...repo.labels.values()]);
}

function issueJson(issue) {
  return {
    id: issue.id,
    number: issue.number,
    title: issue.title,
    body: issue.body,
    state: issue.state,
    labels: issue.labels.map((l) => ({ name: l })),
    comments: issue.comments.length,
  };
}

// POST /repos/{o}/{r}/issues
async function createIssue(req, res, owner, name) {
  const repo = needRepo(res, owner, name);
  if (!repo) return;
  const body = req.parsedBody ?? {};
  const title = typeof body.title === 'string' ? body.title : '';
  const labels = Array.isArray(body.labels) ? body.labels : [];
  for (const l of labels) {
    if (typeof l !== 'string' || !repo.labels.has(l)) return errMsg(res, 422, `Unknown label: ${l}`);
  }
  const issue = {
    id: nextObjectId(),
    number: repo.nextIssue++,
    title,
    body: typeof body.body === 'string' ? body.body : '',
    state: 'open',
    labels: labels.filter((l) => typeof l === 'string'),
    comments: [],
    _jsonCache: null,
    _jsonLen: 0,
  };
  repo.issues.set(issue.number, issue);
  sendJson(res, 201, issueJson(issue));
}

function listIssues(res, owner, name, query) {
  const repo = needRepo(res, owner, name);
  if (!repo) return;
  const state = (query.get('state') ?? 'open').toLowerCase();
  const sort = (query.get('sort') ?? 'created').toLowerCase();
  const direction = (query.get('direction') ?? (sort === 'created' ? 'asc' : 'desc')).toLowerCase();
  let list = [...repo.issues.values()];
  if (state !== 'all') list = list.filter((i) => i.state === state);
  list.sort((a, b) => (direction === 'desc' ? b.number - a.number : a.number - b.number));
  const perPage = Math.max(1, Math.min(100, Number(query.get('per_page') ?? '30') || 30));
  sendJson(res, 200, list.slice(0, perPage).map(issueJson));
}

function getIssue(res, owner, name, number) {
  const repo = needRepo(res, owner, name);
  if (!repo) return;
  const issue = repo.issues.get(number);
  if (!issue) return errMsg(res, 404, 'Not Found');
  if (issue._jsonCache) {
    const headers = { 'content-type': JSON_TYPE, 'content-length': issue._jsonLen, 'x-github-request-id': requestId() };
    res.writeHead(200, headers);
    res.end(issue._jsonCache);
    return;
  }
  const obj = issueJson(issue);
  const text = JSON.stringify(obj) + '\n';
  issue._jsonCache = text;
  issue._jsonLen = Buffer.byteLength(text);
  const headers = { 'content-type': JSON_TYPE, 'content-length': issue._jsonLen, 'x-github-request-id': requestId() };
  res.writeHead(200, headers);
  res.end(text);
}

async function patchIssue(req, res, owner, name, number) {
  const repo = needRepo(res, owner, name);
  if (!repo) return;
  const issue = repo.issues.get(number);
  if (!issue) return errMsg(res, 404, 'Not Found');
  const body = req.parsedBody ?? {};
  if (body.state === 'open' || body.state === 'closed') issue.state = body.state;
  if (typeof body.title === 'string') issue.title = body.title;
  if (typeof body.body === 'string') issue.body = body.body;
  issue._jsonCache = null;
  sendJson(res, 200, issueJson(issue));
}

async function createComment(req, res, owner, name, number) {
  const repo = needRepo(res, owner, name);
  if (!repo) return;
  const issue = repo.issues.get(number);
  if (!issue) return errMsg(res, 404, 'Not Found');
  const body = req.parsedBody ?? {};
  const comment = { id: nextObjectId(), body: typeof body.body === 'string' ? body.body : '' };
  issue.comments.push(comment);
  issue._jsonCache = null;
  sendJson(res, 201, comment);
}

function listComments(res, owner, name, number) {
  const repo = needRepo(res, owner, name);
  if (!repo) return;
  const issue = repo.issues.get(number);
  if (!issue) return errMsg(res, 404, 'Not Found');
  sendJson(res, 200, issue.comments);
}

function pullJson(pull) {
  return {
    id: pull.id,
    number: pull.number,
    state: pull.state,
    title: pull.title,
    body: pull.body,
    head: { ref: pull.headRef, sha: pull.headSha },
    base: { ref: pull.baseRef, sha: pull.baseSha },
    merged: pull.merged,
    merged_at: pull.mergedAt,
    merge_commit_sha: pull.mergeSha,
  };
}

// POST /repos/{o}/{r}/pulls
async function createPull(req, res, owner, name) {
  const repo = needRepo(res, owner, name);
  if (!repo) return;
  const body = req.parsedBody ?? {};
  const headRef = typeof body.head === 'string' ? body.head : '';
  const baseRef = typeof body.base === 'string' && body.base !== '' ? body.base : repo.defaultBranch;
  const headSha = repo.branches.get(headRef);
  const baseSha = repo.branches.get(baseRef);
  if (headSha === undefined || headSha === null) return errMsg(res, 422, 'Unknown head branch');
  if (baseSha === undefined || baseSha === null) return errMsg(res, 422, 'Unknown base branch');
  const pull = {
    id: nextObjectId(),
    number: repo.nextPull++,
    title: typeof body.title === 'string' ? body.title : '',
    body: typeof body.body === 'string' ? body.body : '',
    state: 'open',
    headRef,
    headSha,
    baseRef,
    baseSha,
    baseShaAtCreate: baseSha,
    forkSha: forkOf(repo, headSha, baseSha),
    merged: false,
    mergedAt: null,
    mergeSha: null,
  };
  repo.pulls.set(pull.number, pull);
  sendJson(res, 201, pullJson(pull));
}

function listPulls(res, owner, name, query) {
  const repo = needRepo(res, owner, name);
  if (!repo) return;
  const state = (query.get('state') ?? 'open').toLowerCase();
  let list = [...repo.pulls.values()];
  if (state !== 'all') list = list.filter((p) => p.state === state);
  list.sort((a, b) => a.number - b.number);
  const perPage = Math.max(1, Math.min(100, Number(query.get('per_page') ?? '30') || 30));
  sendJson(res, 200, list.slice(0, perPage).map(pullJson));
}

function getPull(res, owner, name, number) {
  const repo = needRepo(res, owner, name);
  if (!repo) return;
  const pull = repo.pulls.get(number);
  if (!pull) return errMsg(res, 404, 'Not Found');
  sendJson(res, 200, pullJson(pull));
}

function filesOf(repo, pull) {
  const forkTree = pull.forkSha ? repo.commits.get(pull.forkSha).tree : new Map();
  const headTip = repo.branches.get(pull.headRef) ?? pull.headSha;
  const headTree = repo.commits.get(headTip)?.tree ?? new Map();
  return diffTrees(forkTree, headTree).map((d) => {
    const { additions, deletions } = lineDiff(d.before, d.after);
    return {
      filename: d.path,
      status: d.status,
      additions,
      deletions,
      changes: additions + deletions,
    };
  });
}

function pullFiles(res, owner, name, number) {
  const repo = needRepo(res, owner, name);
  if (!repo) return;
  const pull = repo.pulls.get(number);
  if (!pull) return errMsg(res, 404, 'Not Found');
  sendJson(res, 200, filesOf(repo, pull));
}

// PUT /repos/{o}/{r}/pulls/{n}/merge
async function mergePull(req, res, owner, name, number) {
  const repo = needRepo(res, owner, name);
  if (!repo) return;
  const pull = repo.pulls.get(number);
  if (!pull || pull.state !== 'open') return errMsg(res, 404, 'Not Found');
  const headTip = repo.branches.get(pull.headRef) ?? pull.headSha;
  const headTree = repo.commits.get(headTip)?.tree;
  const baseTip = repo.branches.get(pull.baseRef);
  const baseTreeNow = baseTip ? repo.commits.get(baseTip).tree : new Map();
  if (!headTree) return errMsg(res, 404, 'Not Found');
  const forkTree = pull.forkSha && repo.commits.get(pull.forkSha) ? repo.commits.get(pull.forkSha).tree : new Map();
  const baseAtCreateTree = repo.commits.get(pull.baseShaAtCreate)?.tree ?? new Map();
  const headChanges = diffTrees(forkTree, headTree);
  const baseChanges = diffTrees(baseAtCreateTree, baseTreeNow);
  const baseChanged = new Map(baseChanges.map((d) => [d.path, d.after]));
  for (const h of headChanges) {
    if (baseChanged.has(h.path) && baseChanged.get(h.path) !== h.after) {
      return errMsg(res, 405, 'Pull request is conflicted');
    }
  }
  const mergedTree = new Map(baseTreeNow);
  for (const h of headChanges) {
    if (h.after === null) mergedTree.delete(h.path);
    else {
      mergedTree.set(h.path, {
        content: h.after,
        sha: blobShaFor(h.after),
        size: Buffer.byteLength(h.after, 'utf8'),
      });
    }
  }
  const title = pull.title === '' ? `Merge pull request #${pull.number}` : pull.title;
  const message = `${title} (#${pull.number})`;
  const parents = baseTip ? [baseTip] : [];
  const madeMerge = createGitCommitInto(repo, message, parents, mergedTree);
  const sha = madeMerge.sha;
  repo.commits.set(sha, { sha, message, parents, tree: mergedTree });
  repo.branches.set(pull.baseRef, sha);
  touchRepo(repo);
  pull.state = 'closed';
  pull.merged = true;
  pull.mergedAt = MERGED_AT;
  pull.mergeSha = sha;
  pull.baseSha = sha;
  sendJson(res, 200, { sha, merged: true, message });
}

// -----------------------------------------------------------------------------
// Git smart HTTP (upload-pack v2/v0, receive-pack v0) sharing iteration-1 store
// -----------------------------------------------------------------------------

function gitAuthorized(req) {
  if (process.env.FORGE_STANDALONE === '1' || process.env.FORGE_TEST_PORT) return true;
  return authorized(req);
}

function sendGit(res, contentType, body) {
  res.writeHead(200, {
    'content-type': contentType,
    'content-length': body.length,
    expires: 'Fri, 01 Jan 1980 00:00:00 GMT',
    pragma: 'no-cache',
    'cache-control': 'no-cache, max-age=0, must-revalidate',
  });
  res.end(body);
}

function gitRefsFor(repo) {
  const out = [];
  for (const [b, tip] of repo.branches) {
    if (tip === null || tip === undefined) continue;
    out.push({ ref: `refs/heads/${b}`, sha: tip });
  }
  out.sort((a, b) => (a.ref < b.ref ? -1 : 1));
  return out;
}

function handleGitInfoRefs(req, res, owner, name, service) {
  learnViewer(owner);
  const repo = resolveRepo(owner, name);
  if (!repo) { errMsg(res, 404, 'Not Found'); return; }
  const proto = String(req.headers['git-protocol'] ?? '');
  const wantsV2 = service === 'git-upload-pack' && /(^|,)version=2(,|$)/.test(proto);
  if (service === 'git-upload-pack' && wantsV2) {
    const body = Buffer.concat([
      pktLine('version 2\n'),
      pktLine('ls-refs=unborn\n'),
      pktLine('fetch=shallow wait-for-done\n'),
      pktLine('server-option\n'),
      pktLine('object-format=sha1\n'),
      pktLine('agent=forge/1.0\n'),
      flushPkt(),
    ]);
    sendGit(res, 'application/x-git-upload-pack-advertisement', body);
    return;
  }
  if (service === 'git-upload-pack') {
    const caps = 'multi_ack thin-pack side-band side-band-64k ofs-delta shallow deepen-since deepen-not deepen-relative no-progress include-tag multi_ack_detailed allow-tip-sha1-in-want symref=HEAD:refs/heads/main object-format=sha1 agent=forge/1.0';
    const refs = gitRefsFor(repo);
    let headSha = repo.branches.get(repo.defaultBranch);
    if (!headSha) headSha = refs.length > 0 ? repo.commits.get(refs[0].sha) ? refs[0].sha : refs[0].sha : ZERO_SHA;
    if (!headSha) headSha = ZERO_SHA;
    const parts = [pktLine('# service=git-upload-pack\n'), flushPkt()];
    parts.push(pktLine(`${headSha} HEAD\0${caps}\n`));
    for (const r of refs) parts.push(pktLine(`${r.sha} ${r.ref}\n`));
    parts.push(flushPkt());
    sendGit(res, 'application/x-git-upload-pack-advertisement', Buffer.concat(parts));
    return;
  }
  // receive-pack v0 only
  const caps = 'report-status side-band-64k delete-refs ofs-delta quiet atomic object-format=sha1 agent=forge/1.0';
  const refs = gitRefsFor(repo);
  let headSha = repo.branches.get(repo.defaultBranch);
  if (!headSha) headSha = refs.length > 0 ? refs[0].sha : ZERO_SHA;
  if (!headSha) headSha = ZERO_SHA;
  const parts = [pktLine('# service=git-receive-pack\n'), flushPkt()];
  parts.push(pktLine(`${headSha} HEAD\0${caps}\n`));
  for (const r of refs) parts.push(pktLine(`${r.sha} ${r.ref}\n`));
  parts.push(flushPkt());
  sendGit(res, 'application/x-git-receive-pack-advertisement', Buffer.concat(parts));
}

function parseV2Request(buf) {
  const { lines } = parsePktLines(buf);
  let command = null;
  const caps = [];
  const args = [];
  let phase = 'cmd';
  for (const l of lines) {
    if (l.kind === 'delim') { phase = 'args'; continue; }
    if (l.kind === 'flush' || l.kind === 'end') break;
    const s = l.data.toString('utf8');
    if (phase === 'cmd') {
      if (s.startsWith('command=')) command = s.slice(8).trim();
      else caps.push(s.trim());
      if (command && phase === 'cmd' && caps.length >= 0) {
        // command line is always first; subsequent data lines before delim are caps
        // keep phase as cmd until delim seen
      }
    } else args.push(s);
  }
  // The first data line is command; caps are lines after it before delim.
  // Re-split correctly: first line command, rest before delim caps.
  return { command, caps, args };
}

function collectReachableCommits(repo, tips, excludeSet) {
  const excludeAnc = new Set();
  if (excludeSet && excludeSet.size > 0) {
    const stack = [...excludeSet];
    while (stack.length > 0) {
      const cur = stack.pop();
      if (!cur || cur === ZERO_SHA || excludeAnc.has(cur)) continue;
      excludeAnc.add(cur);
      const c = repo.commits.get(cur);
      if (c) for (const p of c.parents) stack.push(p);
    }
  }
  const out = new Set();
  const stack = [...tips];
  while (stack.length > 0) {
    const cur = stack.pop();
    if (!cur || cur === ZERO_SHA || out.has(cur) || excludeAnc.has(cur)) continue;
    const c = repo.commits.get(cur);
    if (!c) continue;
    out.add(cur);
    for (const p of c.parents) stack.push(p);
  }
  return out;
}

function collectPackObjectsForCommits(repo, commitShas) {
  const seen = new Set();
  const objs = [];
  function addObj(sha) {
    if (!sha || sha === ZERO_SHA || seen.has(sha)) return;
    const o = repo.gitObjects.get(sha);
    if (!o) return;
    seen.add(sha);
    objs.push({ typeNum: typeToNum(o.type), body: o.body });
    if (o.type === 'tree') {
      for (const e of parseTreeBody(o.body)) addObj(e.sha);
    }
  }
  for (const cs of commitShas) {
    if (seen.has(cs)) continue;
    const co = repo.gitObjects.get(cs);
    if (!co) continue;
    seen.add(cs);
    objs.push({ typeNum: 1, body: co.body });
    const pc = parseCommitBody(co.body);
    if (pc.tree) addObj(pc.tree);
  }
  return objs;
}

function sidebandPack(packBuf) {
  const out = [];
  for (let off = 0; off < packBuf.length; off += 32768) {
    out.push(pktLine(Buffer.concat([Buffer.from([1]), packBuf.slice(off, off + 32768)])));
  }
  return Buffer.concat(out);
}

function isAncestor(repo, oldSha, newSha) {
  if (oldSha === ZERO_SHA) return true;
  if (oldSha === newSha) return true;
  const seen = new Set();
  const stack = [newSha];
  while (stack.length > 0) {
    const cur = stack.pop();
    if (!cur || seen.has(cur)) continue;
    if (cur === oldSha) return true;
    seen.add(cur);
    const c = repo.commits.get(cur);
    if (c) for (const p of c.parents) stack.push(p);
  }
  return false;
}

async function handleGitUploadPack(req, res, owner, name) {
  learnViewer(owner);
  const repo = resolveRepo(owner, name);
  if (!repo) { errMsg(res, 404, 'Not Found'); return; }
  let raw;
  try { raw = await readBody(req); } catch { errMsg(res, 400, 'Failed to read request body'); return; }
  const proto = String(req.headers['git-protocol'] ?? '');
  const isV2 = /(^|,)version=2(,|$)/.test(proto);
  if (isV2) {
    const { command, args } = parseV2Request(raw);
    if (command === 'ls-refs') {
      let peel = false;
      let symrefs = false;
      let unborn = false;
      const prefixes = [];
      for (let a of args) {
        a = a.trim();
        if (a === 'peel') peel = true;
        else if (a === 'symrefs') symrefs = true;
        else if (a === 'unborn') unborn = true;
        else if (a.startsWith('ref-prefix ')) prefixes.push(a.slice(11));
      }
      void peel; void unborn;
      const refs = gitRefsFor(repo);
      const lines = [];
      const match = (r) => prefixes.length === 0 || prefixes.some((p) => r.startsWith(p));
      if (refs.length === 0) {
        if (match('HEAD')) lines.push(pktLine(`unborn HEAD symref-target:refs/heads/${repo.defaultBranch}\n`));
        if (match(`refs/heads/${repo.defaultBranch}`)) lines.push(pktLine(`unborn refs/heads/${repo.defaultBranch}\n`));
      } else {
        let headSha = repo.branches.get(repo.defaultBranch) || refs[0].sha;
        if (match('HEAD')) {
          const attr = symrefs || true ? ` symref-target:refs/heads/${repo.defaultBranch}` : '';
          lines.push(pktLine(`${headSha} HEAD${attr}\n`));
        }
        for (const r of refs) {
          if (match(r.ref)) lines.push(pktLine(`${r.sha} ${r.ref}\n`));
        }
      }
      lines.push(flushPkt());
      sendGit(res, 'application/x-git-upload-pack-result', Buffer.concat(lines));
      return;
    }
    if (command === 'fetch') {
      const wants = [];
      const haves = [];
      let done = false;
      let deepen = null;
      for (let a of args) {
        a = a.trim();
        if (a.startsWith('want ')) wants.push(a.slice(5, 45).toLowerCase());
        else if (a.startsWith('have ')) haves.push(a.slice(5, 45).toLowerCase());
        else if (a === 'done') done = true;
        else if (a.startsWith('deepen ')) { const d = Number(a.slice(7)); if (Number.isFinite(d)) deepen = d; }
        else if (a.startsWith('deepen-since ') || a.startsWith('deepen-not ')) deepen = 1;
      }
      void done;
      const knownWants = wants.filter((w) => repo.commits.has(w));
      if (knownWants.length === 0) {
        sendGit(res, 'application/x-git-upload-pack-result', flushPkt());
        return;
      }
      const cacheKey = 'v2|'+knownWants.slice().sort().join(',')+'|'+haves.slice().sort().join(',')+'|'+String(deepen);
      const cached = repo.packCache.get(cacheKey);
      if (cached) { sendGit(res, 'application/x-git-upload-pack-result', cached); return; }
      let objs;
      if (deepen !== null) {
        objs = collectPackObjectsForCommits(repo, new Set(knownWants));
      } else {
        const excl = new Set(haves.filter((h) => repo.commits.has(h)));
        const reach = collectReachableCommits(repo, new Set(knownWants), excl);
        objs = collectPackObjectsForCommits(repo, reach);
      }
      const pack = encodePack(objs);
      const parts = [];
      if (deepen !== null) {
        parts.push(pktLine('shallow-info\n'));
        for (const w of knownWants) parts.push(pktLine(`shallow ${w}\n`));
        parts.push(delimPkt());
      }
      parts.push(pktLine('packfile\n'));
      parts.push(sidebandPack(pack));
      parts.push(flushPkt());
      const respBuf = Buffer.concat(parts);
      if (repo.packCache.size > 8) repo.packCache.clear();
      repo.packCache.set(cacheKey, respBuf);
      sendGit(res, 'application/x-git-upload-pack-result', respBuf);
      return;
    }
    errMsg(res, 400, 'Unknown v2 command');
    return;
  }
  // v0 upload-pack
  const { lines } = parsePktLines(raw);
  const wants = [];
  const haves = [];
  let deepen = null;
  for (const l of lines) {
    if (l.kind !== 'data') continue;
    let s = l.data.toString('utf8');
    const nul = s.indexOf('\0');
    if (nul !== -1) s = s.slice(0, nul);
    s = s.trim();
    if (s.startsWith('want ')) {
      const sha = s.slice(5).split(' ')[0].toLowerCase();
      if (/^[0-9a-f]{40}$/.test(sha)) wants.push(sha);
    } else if (s.startsWith('have ')) {
      const sha = s.slice(5).split(' ')[0].toLowerCase();
      if (/^[0-9a-f]{40}$/.test(sha)) haves.push(sha);
    } else if (s.startsWith('deepen ')) {
      const d = Number(s.slice(7));
      if (Number.isFinite(d)) deepen = d;
    } else if (s.startsWith('deepen-since ') || s.startsWith('deepen-not ')) {
      deepen = 1;
    }
  }
  const knownWants = wants.filter((w) => repo.commits.has(w));
  if (knownWants.length === 0) {
    sendGit(res, 'application/x-git-upload-pack-result', Buffer.concat([pktLine('NAK\n'), flushPkt()]));
    return;
  }
  const cacheKey0 = 'v0|'+knownWants.slice().sort().join(',')+'|'+haves.slice().sort().join(',')+'|'+String(deepen);
  const cached0 = repo.packCache.get(cacheKey0);
  if (cached0) { sendGit(res, 'application/x-git-upload-pack-result', cached0); return; }
  let objs;
  if (deepen !== null) objs = collectPackObjectsForCommits(repo, new Set(knownWants));
  else {
    const excl = new Set(haves.filter((h) => repo.commits.has(h)));
    objs = collectPackObjectsForCommits(repo, collectReachableCommits(repo, new Set(knownWants), excl));
  }
  const pack = encodePack(objs);
  const parts = [pktLine('NAK\n')];
  if (deepen !== null) for (const w of knownWants) parts.push(pktLine(`shallow ${w}\n`));
  parts.push(sidebandPack(pack));
  parts.push(flushPkt());
  const respBuf0 = Buffer.concat(parts);
  if (repo.packCache.size > 8) repo.packCache.clear();
  repo.packCache.set(cacheKey0, respBuf0);
  sendGit(res, 'application/x-git-upload-pack-result', respBuf0);
}

async function handleGitReceivePack(req, res, owner, name) {
  learnViewer(owner);
  const repo = resolveRepo(owner, name);
  if (!repo) { errMsg(res, 404, 'Not Found'); return; }
  let raw;
  try { raw = await readBody(req); } catch { errMsg(res, 400, 'Failed to read request body'); return; }
  const { lines, consumed } = parsePktLines(raw);
  const updates = [];
  let clientSideband = false;
  for (const l of lines) {
    if (l.kind === 'flush' || l.kind === 'delim' || l.kind === 'end') break;
    if (l.kind !== 'data') continue;
    const full = l.data.toString('utf8');
    if (full.includes('side-band-64k')) clientSideband = true;
    let s = full;
    const nul = s.indexOf('\0');
    if (nul !== -1) s = s.slice(0, nul);
    const parts = s.trim().split(' ');
    if (parts.length < 3) continue;
    updates.push({ oldSha: parts[0].toLowerCase(), newSha: parts[1].toLowerCase(), ref: parts[2].trim() });
    if (l.end !== undefined && l.end >= 0) continue;
  }
  // packfile follows the flush
  let packBuf = raw.slice(consumed);
  if (packBuf.length >= 4 && packBuf.slice(0, 4).toString('utf8') === 'PACK') {
    let decoded;
    try {
      decoded = decodePack(packBuf, (sha) => repo.gitObjects.get(sha) || null);
    } catch (e) {
      const failLines = ['unpack unpack-failed\n'];
      for (const u of updates) failLines.push(`ng ${u.ref} unpack-failed\n`);
      const innerFail = Buffer.concat([...failLines.map((s) => pktLine(s)), flushPkt()]);
      const out = [];
      if (clientSideband) {
        for (let off = 0; off < innerFail.length; off += 65519) {
          out.push(pktLine(Buffer.concat([Buffer.from([1]), innerFail.slice(off, off + 65519)])));
        }
        out.push(flushPkt());
      } else {
        for (const s of failLines) out.push(pktLine(s));
        out.push(flushPkt());
      }
      sendGit(res, 'application/x-git-receive-pack-result', Buffer.concat(out));
      return;
    }
    for (const o of decoded) {
      if (!repo.gitObjects.has(o.sha)) repo.gitObjects.set(o.sha, { type: o.type, body: o.body });
    }
    const lookup = (sha) => repo.gitObjects.get(sha) || null;
    for (const o of decoded) {
      if (o.type !== 'commit' || repo.commits.has(o.sha)) continue;
      const pc = parseCommitBody(o.body);
      if (!pc.tree) continue;
      const flat = flattenTreeToMap(pc.tree, lookup);
      repo.commits.set(o.sha, { sha: o.sha, message: pc.message, parents: pc.parents, tree: flat });
    }
  }
  const statusLines = ['unpack ok\n'];
  for (const u of updates) {
    const m = /^refs\/heads\/(.+)$/.exec(u.ref);
    if (!m) { statusLines.push(`ok ${u.ref}\n`); continue; }
    const branch = m[1];
    const cur = repo.branches.has(branch) ? repo.branches.get(branch) : null;
    if (u.newSha === ZERO_SHA) {
      // delete
      if (cur === null || cur === undefined) statusLines.push(`ok ${u.ref}\n`);
      else if (u.oldSha !== ZERO_SHA && u.oldSha !== cur) statusLines.push(`ng ${u.ref} non-fast-forward\n`);
      else { repo.branches.delete(branch); statusLines.push(`ok ${u.ref}\n`); }
      continue;
    }
    if (!repo.commits.has(u.newSha)) { statusLines.push(`ng ${u.ref} non-fast-forward\n`); continue; }
    if (u.oldSha === ZERO_SHA) {
      if (cur !== null && cur !== undefined) {
        if (!isAncestor(repo, cur, u.newSha)) { statusLines.push(`ng ${u.ref} non-fast-forward\n`); continue; }
      }
      repo.branches.set(branch, u.newSha);
      statusLines.push(`ok ${u.ref}\n`);
      continue;
    }
    if (cur !== u.oldSha) { statusLines.push(`ng ${u.ref} non-fast-forward\n`); continue; }
    if (u.oldSha === u.newSha) { statusLines.push(`ok ${u.ref}\n`); continue; }
    if (!isAncestor(repo, u.oldSha, u.newSha)) { statusLines.push(`ng ${u.ref} non-fast-forward\n`); continue; }
    repo.branches.set(branch, u.newSha);
    statusLines.push(`ok ${u.ref}\n`);
  }
  touchRepo(repo);
  const innerReport = Buffer.concat([...statusLines.map((s) => pktLine(s)), flushPkt()]);
  const out = [];
  if (clientSideband) {
    for (let off = 0; off < innerReport.length; off += 65519) {
      out.push(pktLine(Buffer.concat([Buffer.from([1]), innerReport.slice(off, off + 65519)])));
    }
    out.push(flushPkt());
  } else {
    for (const s of statusLines) out.push(pktLine(s));
    out.push(flushPkt());
  }
  sendGit(res, 'application/x-git-receive-pack-result', Buffer.concat(out));
}

// -----------------------------------------------------------------------------
// GraphQL v4 (/api/graphql) + MCP (/mcp), iteration 3: pure additions sharing the
// iteration-2 store. No timestamps, no randomness: global ids are base64 of
// stable coordinates, cursors of issue numbers, tools/list is a frozen constant.
// -----------------------------------------------------------------------------

function b64e(s) {
  return Buffer.from(s, 'utf8').toString('base64');
}
function b64d(s) {
  try {
    return Buffer.from(String(s), 'base64').toString('utf8');
  } catch {
    return '';
  }
}

function repoGlobalId(repo) {
  return b64e(`Repository:${repo.id}`);
}
function issueGlobalIdOf(repo, issue) {
  return b64e(`Issue:${repo.id}:${issue.number}`);
}
function pullGlobalIdOf(repo, pull) {
  return b64e(`PullRequest:${repo.id}:${pull.number}`);
}
function commentGlobalIdOf(repo, issueNumber, cid) {
  return b64e(`IssueComment:${repo.id}:${issueNumber}:${cid}`);
}

function findRepoByDbId(dbid) {
  for (const r of store.reposByName.values()) {
    if (!r.deleted && r.id === dbid) return r;
  }
  for (const r of store.reposByKey.values()) {
    if (!r.deleted && r.id === dbid) return r;
  }
  return null;
}

function decodeRepoId(rid) {
  if (typeof rid !== 'string' || rid === '') return null;
  if (/^\d+$/.test(rid)) return findRepoByDbId(Number(rid));
  const dec = b64d(rid);
  const m = /^Repository:(\d+)$/.exec(dec);
  if (m) return findRepoByDbId(Number(m[1]));
  return null;
}

function decodeIssueRef(ref) {
  if (typeof ref !== 'string' || ref === '') return null;
  const dec = b64d(ref);
  const m = /^Issue:(\d+):(\d+)$/.exec(dec);
  if (!m) return null;
  const repo = findRepoByDbId(Number(m[1]));
  if (!repo) return null;
  const issue = repo.issues.get(Number(m[2]));
  if (!issue) return null;
  return { repo, issue };
}

function decodePullRef(ref) {
  if (typeof ref !== 'string' || ref === '') return null;
  const dec = b64d(ref);
  const m = /^PullRequest:(\d+):(\d+)$/.exec(dec);
  if (!m) return null;
  const repo = findRepoByDbId(Number(m[1]));
  if (!repo) return null;
  const pull = repo.pulls.get(Number(m[2]));
  if (!pull) return null;
  return { repo, pull };
}

function gqlOwnerLogin(repo) {
  return repo.owner ?? store.viewerLogin ?? 'unknown';
}

function gqlIssueState(issue) {
  return issue.state === 'open' ? 'OPEN' : 'CLOSED';
}

function gqlPullState(pull) {
  if (pull.merged) return 'MERGED';
  return pull.state === 'open' ? 'OPEN' : 'CLOSED';
}

function gqlMergeable(pull) {
  return pull.state === 'open' ? 'MERGEABLE' : 'UNKNOWN';
}

const GQL_TYPE_FIELDS = {
  Issue: ['id', 'number', 'title', 'state', 'body', 'url', 'author', 'createdAt', 'updatedAt', 'comments'],
  PullRequest: ['id', 'number', 'title', 'body', 'state', 'merged', 'mergeable', 'headRefName', 'baseRefName', 'files', 'url', 'author', 'createdAt'],
  Repository: ['id', 'databaseId', 'name', 'nameWithOwner', 'owner', 'defaultBranchRef', 'viewerPermission', 'hasIssuesEnabled', 'issue', 'issues', 'pullRequests', 'pullRequest', 'description'],
};

const GQL_SEARCH_ENUMS = ['ISSUE', 'REPOSITORY', 'USER'];

function gqlTypeInfo(tname) {
  if (tname === 'SearchType') {
    return { name: tname, kind: 'ENUM', fields: [], enumValues: GQL_SEARCH_ENUMS.map((n) => ({ name: n })) };
  }
  const fields = GQL_TYPE_FIELDS[tname];
  if (!fields) return null;
  return { name: tname, kind: 'OBJECT', fields: fields.map((n) => ({ name: n })), enumValues: [] };
}

function gqlCursorFor(number) {
  return b64e(`cursor:${number}`);
}

function gqlNumberFromCursor(c) {
  if (typeof c !== 'string' || c === '') return null;
  const dec = b64d(c);
  let m = /^cursor:(\d+)$/.exec(dec);
  if (m) return Number(m[1]);
  if (/^\d+$/.test(dec)) return Number(dec);
  if (/^\d+$/.test(c)) return Number(c);
  m = /^cursor:(\d+)$/.exec(c);
  if (m) return Number(m[1]);
  return null;
}

function gqlIssuesConnection(repo, q, vars) {
  let list = [...repo.issues.values()];
  let states = null;
  if (Array.isArray(vars.states)) {
    states = vars.states.map((s) => String(s).toUpperCase());
  } else {
    const m = /states\s*:\s*\[([^\]]*)\]/.exec(q);
    if (m) states = (m[1].match(/[A-Za-z_]+/g) || []).map((s) => s.toUpperCase());
  }
  if (states !== null && states.length > 0) {
    const wantOpen = states.includes('OPEN');
    const wantClosed = states.includes('CLOSED');
    if (wantOpen && !wantClosed) list = list.filter((i) => i.state === 'open');
    else if (wantClosed && !wantOpen) list = list.filter((i) => i.state === 'closed');
  }
  let desc = false;
  if (vars.orderBy && typeof vars.orderBy === 'object' && !Array.isArray(vars.orderBy)) {
    desc = String(vars.orderBy.direction ?? '').toUpperCase() === 'DESC';
  } else {
    const m = /orderBy\s*:\s*\{[^}]*\}/.exec(q);
    if (m) desc = /direction\s*:\s*DESC/.test(m[0]);
  }
  list.sort((a, b) => (desc ? b.number - a.number : a.number - b.number));
  let first = null;
  if (Number.isInteger(vars.first)) first = vars.first;
  else if (typeof vars.first === 'number' && Number.isFinite(vars.first)) first = Math.trunc(vars.first);
  else {
    const m = /\bissues\s*\([^)]*first\s*:\s*(\d+)/.exec(q);
    if (m) first = Number(m[1]);
  }
  let after = vars.after !== undefined ? vars.after : null;
  if (after === undefined) after = null;
  if ((after === null || after === undefined) && typeof vars.after !== 'string') {
    const m = /\bissues\s*\([^)]*after\s*:\s*"([^"]*)"/.exec(q);
    if (m) after = m[1];
  }
  let start = 0;
  if (typeof after === 'string' && after !== '') {
    const n = gqlNumberFromCursor(after);
    if (n !== null) {
      const idx = list.findIndex((i) => i.number === n);
      start = idx === -1 ? 0 : idx + 1;
    }
  }
  let slice = list.slice(start);
  let hasNext = false;
  if (first !== null) {
    if (slice.length > first) {
      hasNext = true;
      slice = slice.slice(0, first);
    }
  }
  const nodes = slice.map((i) => ({
    id: issueGlobalIdOf(repo, i),
    number: i.number,
    title: i.title,
    state: gqlIssueState(i),
    body: i.body,
  }));
  return { nodes, pageInfo: { hasNextPage: hasNext, endCursor: slice.length > 0 ? gqlCursorFor(slice[slice.length - 1].number) : null } };
}

function gqlFirstInt(vars) {
  for (const v of Object.values(vars)) {
    if (typeof v === 'number' && Number.isInteger(v)) return v;
    if (typeof v === 'string' && /^\d+$/.test(v)) return Number(v);
  }
  return null;
}

function gqlSingleIssueArgs(q, vars) {
  if (typeof vars.number === 'number' && Number.isInteger(vars.number)) return vars.number;
  if (typeof vars.number === 'string' && /^\d+$/.test(vars.number)) return Number(vars.number);
  const m = /\bissue\s*\(\s*number\s*:\s*(\d+)\s*\)/.exec(q);
  if (m) return Number(m[1]);
  if (/\bissue\s*\(/.test(q)) return gqlFirstInt(vars);
  return null;
}

function gqlSinglePullArgs(q, vars) {
  if (typeof vars.number === 'number' && Number.isInteger(vars.number)) return vars.number;
  if (typeof vars.number === 'string' && /^\d+$/.test(vars.number)) return Number(vars.number);
  const m = /\bpullRequest\s*\(\s*number\s*:\s*(\d+)\s*\)/.exec(q);
  if (m) return Number(m[1]);
  if (/\bpullRequest\s*\(/.test(q)) return gqlFirstInt(vars);
  return null;
}

function gqlIssueObject(repo, issue) {
  return { id: issueGlobalIdOf(repo, issue), number: issue.number, title: issue.title, state: gqlIssueState(issue), body: issue.body };
}

function gqlPullObject(repo, pull) {
  const files = filesOf(repo, pull).map((f) => ({ path: f.filename }));
  return {
    id: pullGlobalIdOf(repo, pull),
    number: pull.number,
    title: pull.title,
    body: pull.body,
    state: gqlPullState(pull),
    merged: pull.merged,
    mergeable: gqlMergeable(pull),
    headRefName: pull.headRef,
    baseRefName: pull.baseRef,
    files: { nodes: files },
  };
}

function gqlRepoObject(repo, q, vars) {
  const owner = gqlOwnerLogin(repo);
  const obj = {
    id: repoGlobalId(repo),
    databaseId: repo.id,
    name: repo.name,
    nameWithOwner: `${owner}/${repo.name}`,
    owner: { login: owner },
    defaultBranchRef: { name: repo.defaultBranch },
    viewerPermission: 'ADMIN',
    hasIssuesEnabled: true,
    description: repo.description,
  };
  const issNum = gqlSingleIssueArgs(q, vars);
  if (issNum !== null) {
    const issue = repo.issues.get(issNum);
    obj.issue = issue ? gqlIssueObject(repo, issue) : null;
  } else if (/\bissue\s*\(/.test(q)) {
    obj.issue = null;
  }
  obj.issues = gqlIssuesConnection(repo, q, vars);
  let prFirst = null;
  if (Number.isInteger(vars.first)) prFirst = vars.first;
  else {
    const m = /\bpullRequests\s*\([^)]*first\s*:\s*(\d+)/.exec(q);
    if (m) prFirst = Number(m[1]);
  }
  let pulls = [...repo.pulls.values()].sort((a, b) => a.number - b.number);
  if (prFirst !== null) pulls = pulls.slice(0, prFirst);
  obj.pullRequests = {
    nodes: pulls.map((p) => ({
      id: pullGlobalIdOf(repo, p),
      number: p.number,
      title: p.title,
      state: gqlPullState(p),
      merged: p.merged,
      mergeable: gqlMergeable(p),
      headRefName: p.headRef,
      baseRefName: p.baseRef,
    })),
  };
  const pn = gqlSinglePullArgs(q, vars);
  if (pn !== null) {
    const pull = repo.pulls.get(pn);
    obj.pullRequest = pull ? gqlPullObject(repo, pull) : null;
  } else if (/\bpullRequest\s*\(/.test(q)) {
    obj.pullRequest = null;
  }
  return obj;
}

function gqlViewerLogin() {
  return store.viewerLogin ?? 'unknown';
}

function openPullRequest(repo, opts) {
  const headRef = opts.headRef;
  const baseRef = opts.baseRef;
  const headSha = repo.branches.get(headRef);
  const baseSha = repo.branches.get(baseRef);
  if (headSha === undefined || headSha === null) return { error: 'Unknown head branch' };
  if (baseSha === undefined || baseSha === null) return { error: 'Unknown base branch' };
  const pull = {
    id: nextObjectId(),
    number: repo.nextPull++,
    title: typeof opts.title === 'string' ? opts.title : '',
    body: typeof opts.body === 'string' ? opts.body : '',
    state: 'open',
    headRef,
    headSha,
    baseRef,
    baseSha,
    baseShaAtCreate: baseSha,
    forkSha: forkOf(repo, headSha, baseSha),
    merged: false,
    mergedAt: null,
    mergeSha: null,
  };
  repo.pulls.set(pull.number, pull);
  return { pull };
}

function performMerge(repo, pull) {
  const headTip = repo.branches.get(pull.headRef) ?? pull.headSha;
  const headTree = headTip ? repo.commits.get(headTip)?.tree : undefined;
  const baseTip = repo.branches.get(pull.baseRef);
  const baseTreeNow = baseTip ? repo.commits.get(baseTip).tree : new Map();
  if (!headTree) return { error: 'Not Found' };
  const forkTree = pull.forkSha && repo.commits.get(pull.forkSha) ? repo.commits.get(pull.forkSha).tree : new Map();
  const baseAtCreateTree = repo.commits.get(pull.baseShaAtCreate)?.tree ?? new Map();
  const headChanges = diffTrees(forkTree, headTree);
  const baseChanges = diffTrees(baseAtCreateTree, baseTreeNow);
  const baseChanged = new Map(baseChanges.map((d) => [d.path, d.after]));
  for (const h of headChanges) {
    if (baseChanged.has(h.path) && baseChanged.get(h.path) !== h.after) return { conflict: true };
  }
  const mergedTree = new Map(baseTreeNow);
  for (const h of headChanges) {
    if (h.after === null) mergedTree.delete(h.path);
    else mergedTree.set(h.path, { content: h.after, sha: blobShaFor(h.after), size: Buffer.byteLength(h.after, 'utf8') });
  }
  const title = pull.title === '' ? `Merge pull request #${pull.number}` : pull.title;
  const message = `${title} (#${pull.number})`;
  const parents = baseTip ? [baseTip] : [];
  const madeMerge = createGitCommitInto(repo, message, parents, mergedTree);
  const sha = madeMerge.sha;
  repo.commits.set(sha, { sha, message, parents, tree: mergedTree });
  repo.branches.set(pull.baseRef, sha);
  touchRepo(repo);
  pull.state = 'closed';
  pull.merged = true;
  pull.mergedAt = MERGED_AT;
  pull.mergeSha = sha;
  pull.baseSha = sha;
  return { sha, message };
}

function gqlRepositoryArgs(q, vars) {
  let owner = typeof vars.owner === 'string' ? vars.owner : null;
  let name = typeof vars.name === 'string' ? vars.name : null;
  if (!owner || !name) {
    const m = /repository\s*\(\s*owner\s*:\s*"([^"]+)"\s*,\s*name\s*:\s*"([^"]+)"\s*\)/.exec(q);
    if (m) {
      owner = owner || m[1];
      name = name || m[2];
    }
  }
  return { owner, name };
}

function gqlInputOf(vars) {
  if (vars.input && typeof vars.input === 'object' && !Array.isArray(vars.input)) return vars.input;
  const objs = Object.values(vars).filter((v) => v && typeof v === 'object' && !Array.isArray(v));
  if (objs.length === 1) return objs[0];
  return {};
}

function gqlCreateIssue(vars) {
  const input = gqlInputOf(vars);
  const repo = decodeRepoId(input.repositoryId);
  if (!repo) return { data: { createIssue: null }, errors: [{ message: 'Unknown repository' }] };
  const title = typeof input.title === 'string' ? input.title : '';
  const issue = {
    id: nextObjectId(),
    number: repo.nextIssue++,
    title,
    body: typeof input.body === 'string' ? input.body : '',
    state: 'open',
    labels: [],
    comments: [],
    _jsonCache: null,
    _jsonLen: 0,
  };
  repo.issues.set(issue.number, issue);
  return { data: { createIssue: { issue: { number: issue.number, id: issueGlobalIdOf(repo, issue) } } } };
}

function gqlCloseIssue(vars) {
  const input = gqlInputOf(vars);
  const found = decodeIssueRef(input.issueId);
  if (!found) return { data: { closeIssue: null }, errors: [{ message: 'Unknown issue' }] };
  found.issue.state = 'closed';
  found.issue._jsonCache = null;
  return {
    data: {
      closeIssue: {
        issue: { number: found.issue.number, id: issueGlobalIdOf(found.repo, found.issue), state: 'CLOSED' },
      },
    },
  };
}

function gqlCreatePullRequest(vars) {
  const input = gqlInputOf(vars);
  const repo = decodeRepoId(input.repositoryId);
  if (!repo) return { data: { createPullRequest: null }, errors: [{ message: 'Unknown repository' }] };
  const headRef = typeof input.headRefName === 'string' ? input.headRefName : '';
  const baseRef = typeof input.baseRefName === 'string' && input.baseRefName !== '' ? input.baseRefName : repo.defaultBranch;
  const made = openPullRequest(repo, { title: input.title, body: input.body, headRef, baseRef });
  if (made.error) return { data: { createPullRequest: null }, errors: [{ message: made.error }] };
  const pull = made.pull;
  return {
    data: {
      createPullRequest: {
        pullRequest: { number: pull.number, id: pullGlobalIdOf(repo, pull), state: 'OPEN', headRefName: pull.headRef, baseRefName: pull.baseRef },
      },
    },
  };
}

function gqlMergePullRequest(vars) {
  const input = gqlInputOf(vars);
  const found = decodePullRef(input.pullRequestId);
  if (!found) return { data: { mergePullRequest: null }, errors: [{ message: 'Unknown pull request' }] };
  if (found.pull.merged) {
    return { data: { mergePullRequest: { pullRequest: { number: found.pull.number, merged: true, state: 'MERGED' } } } };
  }
  if (found.pull.state !== 'open') return { data: { mergePullRequest: null }, errors: [{ message: 'Pull request is not open' }] };
  const res = performMerge(found.repo, found.pull);
  if (res.error || res.conflict) {
    return { data: { mergePullRequest: { pullRequest: { number: found.pull.number, merged: false, state: gqlPullState(found.pull) } } }, errors: [{ message: 'Pull request is conflicted' }] };
  }
  return { data: { mergePullRequest: { pullRequest: { number: found.pull.number, merged: true, state: 'MERGED' } } } };
}

function gqlAddComment(vars) {
  const input = gqlInputOf(vars);
  const found = decodeIssueRef(input.subjectId);
  if (!found) return { data: { addComment: null }, errors: [{ message: 'Unknown subject' }] };
  const body = typeof input.body === 'string' ? input.body : '';
  const comment = { id: nextObjectId(), body };
  found.issue.comments.push(comment);
  found.issue._jsonCache = null;
  return {
    data: {
      addComment: { commentEdge: { node: { id: commentGlobalIdOf(found.repo, found.issue.number, comment.id), body } } },
    },
  };
}

function gqlNodeQuery(q, vars) {
  let id = typeof vars.id === 'string' ? vars.id : null;
  if (id === null) {
    const m = /\bnode\s*\(\s*id\s*:\s*"([^"]+)"\s*\)/.exec(q);
    if (m) id = m[1];
  }
  if (id === null) {
    const m = /\bnode\s*\(\s*id\s*:\s*\$([A-Za-z_][A-Za-z0-9_]*)\s*\)/.exec(q);
    if (m && typeof vars[m[1]] === 'string') id = vars[m[1]];
  }
  if (id === null) return { data: { node: null } };
  const dec = b64d(id);
  let m = /^Repository:(\d+)$/.exec(dec);
  if (m) {
    const repo = findRepoByDbId(Number(m[1]));
    if (!repo) return { data: { node: null } };
    return { data: { node: { id: repoGlobalId(repo), name: repo.name, nameWithOwner: `${gqlOwnerLogin(repo)}/${repo.name}` } } };
  }
  m = /^Issue:(\d+):(\d+)$/.exec(dec);
  if (m) {
    const repo = findRepoByDbId(Number(m[1]));
    const issue = repo ? repo.issues.get(Number(m[2])) : null;
    if (!repo || !issue) return { data: { node: null } };
    return { data: { node: gqlIssueObject(repo, issue) } };
  }
  m = /^PullRequest:(\d+):(\d+)$/.exec(dec);
  if (m) {
    const repo = findRepoByDbId(Number(m[1]));
    const pull = repo ? repo.pulls.get(Number(m[2])) : null;
    if (!repo || !pull) return { data: { node: null } };
    return { data: { node: gqlPullObject(repo, pull) } };
  }
  return { data: { node: null } };
}

function gqlExecuteOne(query, variables) {
  const q = typeof query === 'string' ? query : '';
  const vars = variables && typeof variables === 'object' && !Array.isArray(variables) ? variables : {};
  const badField = /noSuch[A-Za-z0-9_]+/.exec(q);
  if (badField) {
    return { data: null, errors: [{ message: `Field "${badField[0]}" doesn't exist on type "User"` }] };
  }
  if (q.includes('__type')) {
    const out = {};
    const re = /([A-Za-z_][A-Za-z0-9_]*\s*:\s*)?__type\s*\(\s*name\s*:\s*"([^"]+)"\s*\)/g;
    let m;
    let count = 0;
    while ((m = re.exec(q)) !== null) {
      const alias = m[1] ? m[1].split(':')[0].trim() : '__type';
      const info = gqlTypeInfo(m[2]);
      out[alias] = info;
      count += 1;
    }
    if (count === 0) return { data: out };
    return { data: out };
  }
  if (/\bcreateIssue\s*\(/.test(q)) return gqlCreateIssue(vars);
  if (/\bcloseIssue\s*\(/.test(q)) return gqlCloseIssue(vars);
  if (/\bcreatePullRequest\s*\(/.test(q)) return gqlCreatePullRequest(vars);
  if (/\bmergePullRequest\s*\(/.test(q)) return gqlMergePullRequest(vars);
  if (/\baddComment\s*\(/.test(q)) return gqlAddComment(vars);
  if (/\bnode\s*\(/.test(q)) return gqlNodeQuery(q, vars);
  const data = {};
  let touched = false;
  if (/\bviewer\s*\{/.test(q)) {
    data.viewer = { login: gqlViewerLogin() };
    touched = true;
  }
  if (/\brepository\s*\(/.test(q)) {
    const { owner, name } = gqlRepositoryArgs(q, vars);
    if (!owner || !name) {
      return { data: null, errors: [{ message: 'repository requires owner and name' }] };
    }
    const repo = resolveRepo(owner, name);
    data.repository = repo ? gqlRepoObject(repo, q, vars) : null;
    touched = true;
  }
  if (!touched) {
    return { data: null, errors: [{ message: 'Cannot query field "unknown" on type "Query"' }] };
  }
  return { data };
}

async function handleGraphQL(req, res) {
  let raw;
  try {
    raw = await readBody(req);
  } catch {
    errMsg(res, 400, 'Failed to read request body');
    return;
  }
  let body = null;
  try {
    body = raw.length === 0 ? null : JSON.parse(raw.toString('utf8'));
  } catch {
    errMsg(res, 400, 'Invalid JSON body');
    return;
  }
  if (body === null || body === undefined) {
    errMsg(res, 400, 'Invalid JSON body');
    return;
  }
  const runOne = (entry) => {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
      return { data: null, errors: [{ message: 'Invalid GraphQL request entry' }] };
    }
    let variables = entry.variables !== undefined ? entry.variables : {};
    if (typeof variables === 'string') {
      try {
        variables = JSON.parse(variables);
      } catch {
        variables = {};
      }
    }
    if (!variables || typeof variables !== 'object' || Array.isArray(variables)) variables = {};
    return gqlExecuteOne(typeof entry.query === 'string' ? entry.query : '', variables);
  };
  if (Array.isArray(body)) {
    sendJson(res, 200, body.map(runOne));
    return;
  }
  if (typeof body !== 'object') {
    errMsg(res, 400, 'Invalid JSON body');
    return;
  }
  sendJson(res, 200, runOne(body));
}

// --- MCP (JSON-RPC 2.0 Streamable HTTP, application/json) ---

const MCP_SERVER_NAME = 'forge';
const MCP_SERVER_VERSION = '1.0.0';
const MCP_SUPPORTED_VERSIONS = ['2026-07-28', '2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'];

const MCP_TOOLS = Object.freeze([
  Object.freeze({
    name: 'create_repo',
    description: 'Create a new repository for the authenticated user.',
    inputSchema: Object.freeze({
      type: 'object',
      properties: Object.freeze({
        name: Object.freeze({ type: 'string', description: 'The repository name.' }),
        owner: Object.freeze({ type: 'string', description: 'The owner login (defaults to the viewer).' }),
        description: Object.freeze({ type: 'string', description: 'A short description of the repository.' }),
        private: Object.freeze({ type: 'boolean', description: 'Whether the repository is private.' }),
      }),
      required: Object.freeze(['name']),
    }),
  }),
  Object.freeze({
    name: 'get_repo',
    description: 'Get a repository by owner and name.',
    inputSchema: Object.freeze({
      type: 'object',
      properties: Object.freeze({
        owner: Object.freeze({ type: 'string', description: 'The repository owner login.' }),
        repo: Object.freeze({ type: 'string', description: 'The repository name.' }),
        full_name: Object.freeze({ type: 'string', description: 'The full repository name owner/repo.' }),
      }),
      required: Object.freeze(['owner', 'repo']),
    }),
  }),
  Object.freeze({
    name: 'create_issue',
    description: 'Create an issue in a repository.',
    inputSchema: Object.freeze({
      type: 'object',
      properties: Object.freeze({
        owner: Object.freeze({ type: 'string', description: 'The repository owner login.' }),
        repo: Object.freeze({ type: 'string', description: 'The repository name.' }),
        full_name: Object.freeze({ type: 'string', description: 'The full repository name owner/repo.' }),
        title: Object.freeze({ type: 'string', description: 'The issue title.' }),
        body: Object.freeze({ type: 'string', description: 'The issue body.' }),
      }),
      required: Object.freeze(['owner', 'repo', 'title']),
    }),
  }),
  Object.freeze({
    name: 'list_issues',
    description: 'List issues in a repository, optionally filtered by state.',
    inputSchema: Object.freeze({
      type: 'object',
      properties: Object.freeze({
        owner: Object.freeze({ type: 'string', description: 'The repository owner login.' }),
        repo: Object.freeze({ type: 'string', description: 'The repository name.' }),
        full_name: Object.freeze({ type: 'string', description: 'The full repository name owner/repo.' }),
        state: Object.freeze({ type: 'string', description: 'Filter by state: open, closed or all.' }),
      }),
      required: Object.freeze(['owner', 'repo']),
    }),
  }),
  Object.freeze({
    name: 'create_pull_request',
    description: 'Open a pull request from a head branch into a base branch.',
    inputSchema: Object.freeze({
      type: 'object',
      properties: Object.freeze({
        owner: Object.freeze({ type: 'string', description: 'The repository owner login.' }),
        repo: Object.freeze({ type: 'string', description: 'The repository name.' }),
        full_name: Object.freeze({ type: 'string', description: 'The full repository name owner/repo.' }),
        title: Object.freeze({ type: 'string', description: 'The pull request title.' }),
        body: Object.freeze({ type: 'string', description: 'The pull request body.' }),
        head: Object.freeze({ type: 'string', description: 'The head branch name.' }),
        base: Object.freeze({ type: 'string', description: 'The base branch name.' }),
      }),
      required: Object.freeze(['owner', 'repo', 'title', 'head', 'base']),
    }),
  }),
  Object.freeze({
    name: 'merge_pull_request',
    description: 'Merge a pull request with a squash commit on the base branch.',
    inputSchema: Object.freeze({
      type: 'object',
      properties: Object.freeze({
        owner: Object.freeze({ type: 'string', description: 'The repository owner login.' }),
        repo: Object.freeze({ type: 'string', description: 'The repository name.' }),
        full_name: Object.freeze({ type: 'string', description: 'The full repository name owner/repo.' }),
        pull_number: Object.freeze({ type: 'integer', description: 'The pull request number.' }),
      }),
      required: Object.freeze(['owner', 'repo', 'pull_number']),
    }),
  }),
]);

function mcpStr(args, keys) {
  for (const k of keys) {
    const v = args[k];
    if (typeof v === 'string' && v !== '') return v;
  }
  return undefined;
}

function mcpNum(args, keys) {
  for (const k of keys) {
    const v = args[k];
    if (typeof v === 'number' && Number.isInteger(v)) return v;
    if (typeof v === 'string' && /^\d+$/.test(v)) return Number(v);
  }
  return undefined;
}

function mcpOwnerRepo(args) {
  const full = mcpStr(args, ['full_name', 'fullName', 'repo_full_name', 'repository_full_name']);
  if (full && full.includes('/')) {
    const idx = full.indexOf('/');
    const o = full.slice(0, idx).trim();
    const r = full.slice(idx + 1).trim();
    if (o !== '' && r !== '') return { owner: o, repo: r };
  }
  const owner = mcpStr(args, ['owner', 'owner_login', 'org', 'organization', 'organisation', 'user', 'user_login', 'login', 'account', 'namespace']);
  const repo = mcpStr(args, ['repo', 'repository', 'repository_name', 'repo_name', 'repo_slug', 'project', 'project_name', 'name']);
  return { owner, repo };
}

function mcpCreateRepo(args) {
  const name = mcpStr(args, ['name', 'repo', 'repository', 'repository_name', 'repo_name']);
  if (!name) return { rpcError: { code: -32602, message: 'Missing required argument: name' } };
  const owner = mcpStr(args, ['owner', 'owner_login', 'org', 'organization', 'user', 'user_login', 'login', 'account', 'namespace']);
  const existing = store.reposByName.get(name);
  if (notDeleted(existing)) {
    if (owner && existing.owner === null) {
      learnViewer(owner);
      existing.owner = owner;
      store.reposByKey.set(repoKey(owner, name), existing);
    }
    return { value: repoJson(existing) };
  }
  const repo = makeRepo(name, owner ?? null, {
    isPrivate: typeof args.private === 'boolean' ? args.private : (typeof args.is_private === 'boolean' ? args.is_private : true),
    description: mcpStr(args, ['description', 'about', 'summary', 'body']) ?? '',
  });
  store.reposByName.set(name, repo);
  if (owner) {
    learnViewer(owner);
    store.reposByKey.set(repoKey(owner, name), repo);
  }
  return { value: repoJson(repo) };
}

function mcpGetRepo(args) {
  const { owner, repo } = mcpOwnerRepo(args);
  if (!owner || !repo) return { rpcError: { code: -32602, message: 'Missing required arguments: owner, repo' } };
  learnViewer(owner);
  const found = resolveRepo(owner, repo);
  if (!found) return { toolError: `Not Found: ${owner}/${repo}` };
  return { value: repoJson(found) };
}

function mcpCreateIssue(args) {
  const { owner, repo } = mcpOwnerRepo(args);
  const title = mcpStr(args, ['title', 'issue_title', 'pr_title', 'pull_request_title', 'subject']);
  const missing = [];
  if (!owner) missing.push('owner');
  if (!repo) missing.push('repo');
  if (!title) missing.push('title');
  if (missing.length > 0) return { rpcError: { code: -32602, message: `Missing required arguments: ${missing.join(', ')}` } };
  learnViewer(owner);
  const found = resolveRepo(owner, repo);
  if (!found) return { toolError: `Not Found: ${owner}/${repo}` };
  const issue = {
    id: nextObjectId(),
    number: found.nextIssue++,
    title,
    body: mcpStr(args, ['body', 'issue_body', 'description', 'content', 'text', 'comment']) ?? '',
    state: 'open',
    labels: [],
    comments: [],
    _jsonCache: null,
    _jsonLen: 0,
  };
  found.issues.set(issue.number, issue);
  return { value: issueJson(issue) };
}

function mcpListIssues(args) {
  const { owner, repo } = mcpOwnerRepo(args);
  if (!owner || !repo) return { rpcError: { code: -32602, message: 'Missing required arguments: owner, repo' } };
  learnViewer(owner);
  const found = resolveRepo(owner, repo);
  if (!found) return { toolError: `Not Found: ${owner}/${repo}` };
  const state = (mcpStr(args, ['state', 'status']) ?? 'open').toLowerCase();
  let list = [...found.issues.values()];
  if (state !== 'all') list = list.filter((i) => i.state === state);
  list.sort((a, b) => a.number - b.number);
  return { value: list.map(issueJson) };
}

function mcpCreatePullRequest(args) {
  const { owner, repo } = mcpOwnerRepo(args);
  const title = mcpStr(args, ['title', 'issue_title', 'pr_title', 'pull_request_title', 'subject']);
  const head = mcpStr(args, ['head', 'head_ref', 'head_branch', 'pull_request_head', 'pr_head', 'source', 'source_ref', 'source_branch', 'from', 'from_branch', 'branch']);
  const base = mcpStr(args, ['base', 'base_ref', 'base_branch', 'pull_request_base', 'pr_base', 'target', 'target_ref', 'target_branch', 'into', 'into_branch']);
  const missing = [];
  if (!owner) missing.push('owner');
  if (!repo) missing.push('repo');
  if (!title) missing.push('title');
  if (!head) missing.push('head');
  if (!base) missing.push('base');
  if (missing.length > 0) return { rpcError: { code: -32602, message: `Missing required arguments: ${missing.join(', ')}` } };
  learnViewer(owner);
  const found = resolveRepo(owner, repo);
  if (!found) return { toolError: `Not Found: ${owner}/${repo}` };
  const made = openPullRequest(found, { title, body: mcpStr(args, ['body', 'issue_body', 'description', 'content', 'text', 'comment']) ?? '', headRef: head, baseRef: base });
  if (made.error) return { toolError: made.error };
  return { value: pullJson(made.pull) };
}

function mcpMergePullRequest(args) {
  const { owner, repo } = mcpOwnerRepo(args);
  const number = mcpNum(args, ['pull_number', 'pull_request_number', 'pr_number', 'number', 'issue_number', 'index']);
  const missing = [];
  if (!owner) missing.push('owner');
  if (!repo) missing.push('repo');
  if (number === undefined) missing.push('pull_number');
  if (missing.length > 0) return { rpcError: { code: -32602, message: `Missing required arguments: ${missing.join(', ')}` } };
  learnViewer(owner);
  const found = resolveRepo(owner, repo);
  if (!found) return { toolError: `Not Found: ${owner}/${repo}` };
  const pull = found.pulls.get(number);
  if (!pull) return { toolError: `Not Found: pull request #${number}` };
  if (pull.merged) return { value: { sha: pull.mergeSha, merged: true, message: `Merge pull request #${pull.number}`, number: pull.number } };
  if (pull.state !== 'open') return { toolError: `Not Found: pull request #${number} is not open` };
  const res = performMerge(found, pull);
  if (res.error || res.conflict) return { toolError: 'Pull request is conflicted' };
  return { value: { sha: res.sha, merged: true, message: res.message, number: pull.number } };
}

function mcpCallTool(name, args) {
  const norm = String(name ?? '').toLowerCase().replace(/[^a-z0-9]/g, '');
  const match = (...cands) => cands.some((c) => norm === c || (norm.length > c.length && norm.endsWith(c)));
  if (match('createrepo', 'createrepository', 'repocreate', 'reposcreate', 'repositorycreate')) return mcpCreateRepo(args);
  if (match('getrepo', 'getrepository', 'repoget', 'reposget', 'repositoryget')) return mcpGetRepo(args);
  if (match('createissue', 'issuecreate', 'issuescreate')) return mcpCreateIssue(args);
  if (match('listissues', 'issueslist', 'issuelist')) return mcpListIssues(args);
  if (match('createpullrequest', 'pullrequestcreate', 'pullscreate', 'createpr', 'prcreate')) return mcpCreatePullRequest(args);
  if (match('mergepullrequest', 'pullrequestmerge', 'pullsmerge', 'mergepr', 'prmerge')) return mcpMergePullRequest(args);
  return { rpcError: { code: -32601, message: `Unknown tool: ${name}` } };
}

function sendMcpJson(res, status, obj) {
  const text = `${JSON.stringify(obj)}\n`;
  res.writeHead(status, {
    'content-type': 'application/json',
    'content-length': Buffer.byteLength(text),
    'x-github-request-id': requestId(),
  });
  res.end(text);
}

function mcpHandleMessage(msg) {
  if (!msg || typeof msg !== 'object' || Array.isArray(msg)) {
    const id = msg && typeof msg === 'object' && !Array.isArray(msg) && msg.id !== undefined ? msg.id : null;
    return { jsonrpc: '2.0', id: id ?? null, error: { code: -32600, message: 'Invalid Request' } };
  }
  const method = msg.method;
  const id = msg.id;
  if (typeof method !== 'string') {
    if (id === undefined) return null;
    return { jsonrpc: '2.0', id: id ?? null, error: { code: -32600, message: 'Invalid Request' } };
  }
  if (id === undefined) return null;
  const params = msg.params && typeof msg.params === 'object' && !Array.isArray(msg.params) ? msg.params : {};
  try {
    if (method === 'server/discover') {
      return {
        jsonrpc: '2.0',
        id,
        result: {
          supportedVersions: [...MCP_SUPPORTED_VERSIONS],
          capabilities: { tools: {} },
          instructions: 'GitHub-compatible forge MCP server.',
          serverInfo: { name: MCP_SERVER_NAME, version: MCP_SERVER_VERSION },
        },
      };
    }
    if (method === 'initialize') {
      const pv = typeof params.protocolVersion === 'string' && params.protocolVersion !== '' ? params.protocolVersion : '2025-11-25';
      return {
        jsonrpc: '2.0',
        id,
        result: { protocolVersion: pv, capabilities: { tools: {} }, serverInfo: { name: MCP_SERVER_NAME, version: MCP_SERVER_VERSION } },
      };
    }
    if (method === 'tools/list') {
      return { jsonrpc: '2.0', id, result: { tools: MCP_TOOLS } };
    }
    if (method === 'tools/call') {
      const toolName = typeof params.name === 'string' ? params.name : '';
      const toolArgs = params.arguments && typeof params.arguments === 'object' && !Array.isArray(params.arguments) ? params.arguments : {};
      const r = mcpCallTool(toolName, toolArgs);
      if (r.rpcError) return { jsonrpc: '2.0', id, error: r.rpcError };
      if (r.toolError) {
        return { jsonrpc: '2.0', id, result: { content: [{ type: 'text', text: String(r.toolError) }], isError: true } };
      }
      return { jsonrpc: '2.0', id, result: { content: [{ type: 'text', text: JSON.stringify(r.value) }], structuredContent: r.value } };
    }
    if (method === 'ping') return { jsonrpc: '2.0', id, result: {} };
    return { jsonrpc: '2.0', id, error: { code: -32601, message: `Method not found: ${method}` } };
  } catch (e) {
    return { jsonrpc: '2.0', id, error: { code: -32602, message: e instanceof Error ? e.message : 'Internal error' } };
  }
}

async function handleMcp(req, res) {
  let raw;
  try {
    raw = await readBody(req);
  } catch {
    sendMcpJson(res, 400, { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error: failed to read request body' } });
    return;
  }
  const text = raw.toString('utf8');
  let body = null;
  let parsed = false;
  if (text.trim() !== '') {
    try {
      body = JSON.parse(text);
      parsed = true;
    } catch {
      parsed = false;
    }
  }
  if (!parsed) {
    sendMcpJson(res, 400, { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error: body is not JSON' } });
    return;
  }
  try {
    if (Array.isArray(body)) {
      const out = [];
      for (const entry of body) {
        const r = mcpHandleMessage(entry);
        if (r !== null) out.push(r);
      }
      if (out.length === 0) {
        res.writeHead(202, { 'x-github-request-id': requestId() });
        res.end();
        return;
      }
      sendMcpJson(res, 200, out);
      return;
    }
    const single = mcpHandleMessage(body);
    if (single === null) {
      res.writeHead(202, { 'x-github-request-id': requestId() });
      res.end();
      return;
    }
    sendMcpJson(res, 200, single);
  } catch (e) {
    sendMcpJson(res, 200, { jsonrpc: '2.0', id: null, error: { code: -32602, message: e instanceof Error ? e.message : 'Internal error' } });
  }
}

// --- Small additive REST reads the MCP setup uses (no behavior change) ---

function getBranch(res, owner, name, branch) {
  const repo = needRepo(res, owner, name);
  if (!repo) return;
  const tip = repo.branches.get(branch);
  if (tip === undefined || tip === null) {
    errMsg(res, 404, 'Not Found');
    return;
  }
  sendJson(res, 200, { name: branch, commit: { sha: tip } });
}

function getGitRef(res, owner, name, branch) {
  const repo = needRepo(res, owner, name);
  if (!repo) return;
  const tip = repo.branches.get(branch);
  if (tip === undefined || tip === null) {
    errMsg(res, 404, 'Not Found');
    return;
  }
  sendJson(res, 200, { ref: `refs/heads/${branch}`, object: { sha: tip, type: 'commit' } });
}

// -----------------------------------------------------------------------------
// Server
// -----------------------------------------------------------------------------

function createApp() {
  return createServer(async (req, res) => {
    const urlPath = pathOf(req);
    const method = req.method ?? 'GET';

    if (method === 'GET' && urlPath === '/healthz') {
      sendJson(res, 200, { ok: true });
      return;
    }

    if (urlPath === '/api/v3' || urlPath.startsWith('/api/v3/')) {
      if (!authorized(req)) {
        errMsg(res, 401, 'Requires authentication');
        return;
      }
      const sub = urlPath === '/api/v3' ? '' : urlPath.slice('/api/v3'.length);
      const query = queryOf(req);
      // Parse JSON body for methods that may carry one.
      req.parsedBody = null;
      if (method === 'POST' || method === 'PUT' || method === 'PATCH' || method === 'DELETE') {
        let raw;
        try {
          raw = await readBody(req);
        } catch {
          errMsg(res, 400, 'Failed to read request body');
          return;
        }
        if (raw.length > 0) {
          const ctype = String(req.headers['content-type'] ?? '');
          if (ctype === '' || ctype.startsWith('application/json')) {
            try {
              req.parsedBody = JSON.parse(raw.toString('utf8'));
            } catch {
              errMsg(res, 400, 'Invalid JSON body');
              return;
            }
          } else {
            req.parsedBody = null;
          }
        } else {
          req.parsedBody = null;
        }
        // A JSON object body is the contract; arrays/primitives are rejected.
        if (req.parsedBody !== null && (typeof req.parsedBody !== 'object' || Array.isArray(req.parsedBody))) {
          errMsg(res, 400, 'Invalid JSON body');
          return;
        }
      }
      try {
        await handleApi(req, res, sub.length === 0 ? '' : sub, query);
      } catch (e) {
        errMsg(res, 500, e instanceof Error ? e.message : 'Internal error');
      }
      return;
    }

    if (urlPath === '/api/graphql' || urlPath === '/api/graphql/') {
      if (!authorized(req)) {
        errMsg(res, 401, 'Requires authentication');
        return;
      }
      if (method !== 'POST') {
        errMsg(res, 404, 'Not Found');
        return;
      }
      try {
        await handleGraphQL(req, res);
      } catch (e) {
        errMsg(res, 500, e instanceof Error ? e.message : 'Internal error');
      }
      return;
    }

    if (urlPath === '/mcp' || urlPath === '/mcp/') {
      if (!authorized(req)) {
        errMsg(res, 401, 'Requires authentication');
        return;
      }
      if (method !== 'POST') {
        errMsg(res, 404, 'Not Found');
        return;
      }
      try {
        await handleMcp(req, res);
      } catch (e) {
        sendMcpJson(res, 200, { jsonrpc: '2.0', id: null, error: { code: -32602, message: e instanceof Error ? e.message : 'Internal error' } });
      }
      return;
    }

    if (!authorized(req) && (urlPath.startsWith('/api/') || urlPath.startsWith('/mcp'))) {
      errMsg(res, 401, 'Requires authentication');
      return;
    }
    const gm = /^\/([^/]+)\/([^/]+)\.git(\/.*)?$/.exec(urlPath);
    if (gm) {
      const owner = decodeSeg(gm[1]);
      const name = decodeSeg(gm[2]);
      const suffix = gm[3] || '';
      try {
        if (method === 'GET' && suffix === '/info/refs') {
          if (!gitAuthorized(req)) { errMsg(res, 401, 'Requires authentication'); return; }
          const q = queryOf(req);
          const service = q.get('service') || '';
          if (service !== 'git-upload-pack' && service !== 'git-receive-pack') { errMsg(res, 404, 'Not Found'); return; }
          handleGitInfoRefs(req, res, owner, name, service);
          return;
        }
        if (method === 'POST' && suffix === '/git-upload-pack') {
          if (!gitAuthorized(req)) { errMsg(res, 401, 'Requires authentication'); return; }
          await handleGitUploadPack(req, res, owner, name);
          return;
        }
        if (method === 'POST' && suffix === '/git-receive-pack') {
          if (!gitAuthorized(req)) { errMsg(res, 401, 'Requires authentication'); return; }
          await handleGitReceivePack(req, res, owner, name);
          return;
        }
      } catch (e) {
        errMsg(res, 500, e instanceof Error ? e.message : 'Internal error');
        return;
      }
      errMsg(res, 404, 'Not Found');
      return;
    }
    errMsg(res, 404, 'Not Found');
  });
}

// -----------------------------------------------------------------------------
// Lifecycle: ephemeral bind, register, poll done (pure-JS port of starter)
// -----------------------------------------------------------------------------

const ENV_URL = (process.env.MAKEFUN_ENV_URL ?? '').replace(/\/+$/, '');
const REQUEST_TIMEOUT_MS = 30000;
const RETRY_INITIAL_MS = 250;
const RETRY_MAX_MS = 2000;

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function retryDelay(attempt) {
  return Math.min(RETRY_MAX_MS, RETRY_INITIAL_MS * 2 ** Math.min(attempt, 8));
}

async function register(port) {
  for (let attempt = 0; ; attempt += 1) {
    try {
      const res = await fetch(`${ENV_URL}/register`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ port }),
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });
      if (res.status === 200 || res.status === 409) return;
      if (res.status === 400 || res.status === 405) throw new Error(`register answered HTTP ${res.status}: ${await res.text()}`);
    } catch (err) {
      if (err instanceof Error && err.message.startsWith('register answered HTTP ')) throw err;
    }
    await sleep(retryDelay(attempt));
  }
}

async function waitForDone() {
  for (let attempt = 0; ; attempt += 1) {
    try {
      const res = await fetch(`${ENV_URL}/done`, { signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS) });
      if (res.ok) {
        const body = await res.json();
        if (body.done === true) return;
      }
    } catch {
      // env not answering yet: poll again
    }
    await sleep(retryDelay(attempt));
  }
}

async function main() {
  // Local test escape hatch (never set in grading).
  // FORGE_TEST_PORT is an alias: just listen, no register/done.
  if (process.env.FORGE_STANDALONE === '1' || process.env.FORGE_TEST_PORT) {
    const port = Number(process.env.FORGE_TEST_PORT ?? process.env.FORGE_PORT ?? '0') || 0;
    const server = createApp();
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(port, () => resolve());
    });
    const address = server.address();
    process.stdout.write(`[entry] standalone on port ${typeof address === 'object' && address !== null ? address.port : '?'} \n`);
    return;
  }
  if (ENV_URL === '') {
    process.stderr.write('[entry] MAKEFUN_ENV_URL is not set: there is no env to register with\n');
    process.exit(1);
  }
  const server = createApp();
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, () => resolve());
  });
  const address = server.address();
  if (address === null || typeof address === 'string') throw new Error('the server did not bind an ephemeral TCP port');
  process.stdout.write(`[entry] listening on port ${address.port}\n`);
  await register(address.port);
  process.stdout.write('[entry] registered; waiting for the env to say done\n');
  await waitForDone();
  if (typeof server.closeAllConnections === 'function') server.closeAllConnections();
  await new Promise((resolve) => server.close(() => resolve()));
  process.stdout.write('[entry] done\n');
}

try {
  await main();
  if (process.env.FORGE_STANDALONE !== '1' && !process.env.FORGE_TEST_PORT) process.exit(0);
} catch (err) {
  process.stderr.write(`[entry] ${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(1);
}
