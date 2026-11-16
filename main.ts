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
  function lookupSha(sha) {
    for (const [, v] of resolved) if (v.sha === sha) return v;
    if (knownLookup) return knownLookup(sha);
    return null;
  }
  let progress = true;
  const pending = new Set(raw.map((_, i) => i));
  while (pending.size > 0 && progress) {
    progress = false;
    for (const i of [...pending]) {
      const e = raw[i];
      if (e.typeNum !== 6 && e.typeNum !== 7) {
        const type = numToType(e.typeNum);
        const sha = hashObject(type, e.data);
        resolved.set(e.offset, { type, body: e.data, sha });
        pending.delete(i);
        progress = true;
      } else {
        let base = null;
        if (e.typeNum === 7) {
          base = lookupSha(e.refBase);
          if (!base) {
            for (const [, v] of resolved) if (v.sha === e.refBase) base = v;
          }
        } else {
          base = resolved.get(e.ofsBase) || byOffset.get(e.ofsBase) && resolved.get(e.ofsBase);
          if (!base && byOffset.has(e.ofsBase)) base = resolved.get(e.ofsBase);
        }
        if (base) {
          const body = applyDelta(base.body, e.data);
          resolved.set(e.offset, { type: base.type, body, sha: hashObject(base.type, body) });
          pending.delete(i);
          progress = true;
        }
      }
    }
  }
  if (pending.size > 0) throw new Error('unresolved deltas (thin pack base missing?)');
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
function resolveRepo(owner, name) {
  const direct = store.reposByKey.get(repoKey(owner, name));
  if (notDeleted(direct)) return direct;
  const candidate = store.reposByName.get(name);
  if (!notDeleted(candidate)) return null;
  if (candidate.owner === null) {
    if (store.viewerLogin === null) {
      store.viewerLogin = owner;
    }
    if (owner !== store.viewerLogin) return null;
    candidate.owner = owner;
    store.reposByKey.set(repoKey(owner, name), candidate);
    return candidate;
  }
  if (candidate.owner !== owner) return null;
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
  };
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
  try {
    return new URL(req.url ?? '/', 'http://entry').pathname;
  } catch {
    return '/';
  }
}

function queryOf(req) {
  try {
    return new URL(req.url ?? '/', 'http://entry').searchParams;
  } catch {
    return new URLSearchParams();
  }
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
  sendJson(res, 200, issueJson(issue));
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
      sendGit(res, 'application/x-git-upload-pack-result', Buffer.concat(parts));
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
  sendGit(res, 'application/x-git-upload-pack-result', Buffer.concat(parts));
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
      const out = [];
      if (clientSideband) for (const s of failLines) out.push(pktLine(Buffer.concat([Buffer.from([1]), pktLine(s)])));
      else for (const s of failLines) out.push(pktLine(s));
      out.push(flushPkt());
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
  const out = [];
  if (clientSideband) {
    for (const s of statusLines) {
      const inner = pktLine(s);
      out.push(pktLine(Buffer.concat([Buffer.from([1]), inner])));
    }
  } else {
    for (const s of statusLines) out.push(pktLine(s));
  }
  out.push(flushPkt());
  sendGit(res, 'application/x-git-receive-pack-result', Buffer.concat(out));
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
