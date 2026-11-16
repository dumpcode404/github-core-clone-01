// forge iteration 1: REST core (Node 22 stdlib only, pure-JS ESM in a .ts file).
// Serves: lifecycle (ephemeral bind, register, poll done) + in-memory GitHub REST v3
// under /api/v3. No timestamps or randomness in persisted state: ids/shas come from
// counters and sha1 hashes only.
// Standalone test mode (local only, inert in grading):
//   FORGE_STANDALONE=1 FORGE_PORT=18081 node main.ts

import { createServer } from 'node:http';
import { createHash } from 'node:crypto';

// -----------------------------------------------------------------------------
// Deterministic helpers (no Date.now, no Math.random anywhere in state)
// -----------------------------------------------------------------------------

let reqSeq = 0;
function requestId() {
  reqSeq += 1;
  return `req-${reqSeq.toString(16).padStart(8, '0')}`;
}

let commitSeq = 0;
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

function newCommitSha(message, parents, tree) {
  commitSeq += 1;
  const entries = [...tree.keys()].sort().map((p) => `${p}:${tree.get(p).sha}`).join(',');
  return sha1Hex(`commit:${commitSeq}\n${message}\n${parents.join(',')}\n${entries}`);
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
  const commitSha = newCommitSha(message, parents, baseTree);
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
  const commitSha = newCommitSha(message, [tipSha], baseTree);
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
  const sha = newCommitSha(message, parents, mergedTree);
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
  if (process.env.FORGE_STANDALONE === '1') {
    const port = Number(process.env.FORGE_PORT ?? '0') || 0;
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
  if (process.env.FORGE_STANDALONE !== '1') process.exit(0);
} catch (err) {
  process.stderr.write(`[entry] ${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(1);
}
