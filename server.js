/* ==========================================================================
   NOVA Coach Studio API  ·  Shopify App Proxy server  (v2 — robust)
   Endpoints (storefront calls the /apps/coach/* proxy):
     POST /proxy/coach/save         → update the "coach" metaobject
     POST /proxy/coach/member-save  → create/update "member_profile"
     POST /proxy/coach/post         → create a "village_post" (community board)
     GET  /proxy/coach/posts        → list recent village_post entries (JSON)
     POST /proxy/coach/comment         → create a "village_comment" on a post
     POST /proxy/coach/comment-delete  → delete your OWN comment
     POST /proxy/coach/library-add     → add a "library_item"  (COACHES ONLY)
     GET  /proxy/coach/library         → list library items (all members)
     POST /proxy/coach/library-delete  → delete your OWN library item (coaches)
     GET  /proxy/coach/courses            → courses + this member's lesson state
     POST /proxy/coach/lesson-complete    → mark a lesson done (or undo)
     GET  /proxy/coach/lesson-comments    → discussion for a lesson
     POST /proxy/coach/lesson-comment     → post to a lesson discussion
     POST /proxy/coach/lesson-comment-delete → delete your OWN lesson comment
     GET  /proxy/coach/course-report      → member progress table (COACHES ONLY)
     GET  /proxy/coach/my-courses         → a coach's own courses + lessons
     POST /proxy/coach/course-save        → create/update own course (COACHES)
     POST /proxy/coach/course-delete      → delete own course + its lessons
     POST /proxy/coach/lesson-save        → create/update a lesson in own course
     POST /proxy/coach/lesson-delete      → delete a lesson in own course
   v2 changes:
     • Finds records by fetching + filtering in code (no fragile search query
       on a GID, which was silently matching nothing).
     • Returns the REAL error message so the storefront can show it.
     • Adds the community board (village_post).
   ========================================================================== */

const express = require('express');
const crypto  = require('crypto');

const app = express();
app.use(express.json({ limit: '15mb' }));  // base64 image uploads

// ---- Config ---------------------------------------------------------------
const SHOP          = process.env.SHOP || 'nova-essenceio.myshopify.com';
const CLIENT_ID     = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;
const API_VERSION   = '2026-07';
const API_URL   = `https://${SHOP}/admin/api/${API_VERSION}/graphql.json`;
const TOKEN_URL = `https://${SHOP}/admin/oauth/access_token`;

if (!CLIENT_ID || !CLIENT_SECRET) {
  console.warn('[warn] CLIENT_ID and/or CLIENT_SECRET not set — requests will fail until they are.');
}

// ---- Access token (client-credentials grant) ------------------------------
// NOTE: caching disabled while debugging scope propagation — always fetch fresh.
let _lastTokenScopes = null;
async function getToken() {
  const r = await fetch(TOKEN_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ client_id: CLIENT_ID, client_secret: CLIENT_SECRET, grant_type: 'client_credentials' })
  });
  const j = await r.json();
  if (!j.access_token) throw new Error('token exchange failed: ' + JSON.stringify(j));
  _lastTokenScopes = j.scope || null;
  return j.access_token;
}

// ---- Signed App-Proxy verification ----------------------------------------
function verifyProxy(query) {
  const { signature, ...rest } = query;
  if (!signature) return false;
  const message = Object.keys(rest).sort()
    .map(k => `${k}=${Array.isArray(rest[k]) ? rest[k].join(',') : rest[k]}`)
    .join('');
  const digest = crypto.createHmac('sha256', CLIENT_SECRET).update(message).digest('hex');
  try { return crypto.timingSafeEqual(Buffer.from(digest), Buffer.from(signature)); }
  catch (_) { return false; }
}

// ---- Admin GraphQL helper -------------------------------------------------
async function admin(query, variables) {
  const token = await getToken();
  const r = await fetch(API_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Shopify-Access-Token': token },
    body: JSON.stringify({ query, variables })
  });
  return r.json();
}

// ---- Fetch ALL metaobjects of a type, return [{id, fields:{key:value}}] ---
// Reliable: no search query on GIDs. Fine for village-scale volumes.
async function listMetaobjects(type) {
  const out = [];
  let cursor = null;
  do {
    const j = await admin(
      `query($type:String!, $after:String){
         metaobjects(type:$type, first:100, after:$after){
           edges{ node{ id fields{ key value } } }
           pageInfo{ hasNextPage endCursor }
         } }`,
      { type, after: cursor }
    );
    const conn = j.data?.metaobjects;
    if (!conn) break;
    conn.edges.forEach(e => {
      const f = {};
      e.node.fields.forEach(x => { f[x.key] = x.value; });
      out.push({ id: e.node.id, fields: f });
    });
    cursor = conn.pageInfo.hasNextPage ? conn.pageInfo.endCursor : null;
  } while (cursor);
  return out;
}

async function findByCustomer(type, gid) {
  const all = await listMetaobjects(type);
  const numericId = String(gid).split('/').pop();
  return all.find(m => m.fields.customer === gid || m.fields.customer_id === numericId) || null;
}

async function getCustomerName(gid) {
  const j = await admin(
    `query($id:ID!){ customer(id:$id){ firstName lastName displayName } }`,
    { id: gid }
  );
  const c = j.data?.customer;
  if (!c) return 'Villager';
  return (c.displayName || [c.firstName, c.lastName].filter(Boolean).join(' ') || 'Villager').trim();
}

async function updateMetaobject(id, fields) {
  const j = await admin(
    `mutation($id:ID!, $fields:[MetaobjectFieldInput!]!){
       metaobjectUpdate(id:$id, metaobject:{fields:$fields}){ userErrors{field message} } }`,
    { id, fields }
  );
  return j.data?.metaobjectUpdate?.userErrors || [{ message: 'unexpected: ' + JSON.stringify(j) }].filter(() => !j.data);
}

async function createMetaobject(type, fields) {
  const j = await admin(
    `mutation($type:String!, $fields:[MetaobjectFieldInput!]!){
       metaobjectCreate(metaobject:{type:$type, fields:$fields, capabilities:{publishable:{status:ACTIVE}}}){
         userErrors{field message} } }`,
    { type, fields }
  );
  return j.data?.metaobjectCreate?.userErrors || [{ message: 'unexpected: ' + JSON.stringify(j) }].filter(() => !j.data);
}

// ---- Guard ----------------------------------------------------------------
function guard(req, res) {
  if (!verifyProxy(req.query)) { res.status(401).json({ error: 'bad signature' }); return null; }
  const customerId = req.query.logged_in_customer_id;
  if (!customerId) { res.status(401).json({ error: 'not logged in' }); return null; }
  return `gid://shopify/Customer/${customerId}`;
}

// ==========================================================================
//  COACH SAVE
// ==========================================================================
app.post('/proxy/coach/save', async (req, res) => {
  const gid = guard(req, res); if (!gid) return;
  try {
    const node = await findByCustomer('coach', gid);
    if (!node) return res.status(403).json({ error: 'no coach record linked to your account. In Shopify admin → Custom data → coach, set the entry\'s customer field to you.' });

    const allowed = ['name', 'title', 'photo_url', 'bio', 'booking_url'];
    const fields = allowed.filter(k => k in req.body)
      .map(k => ({ key: k, value: String(req.body[k] ?? '').slice(0, 4000) }));
    ['pillars', 'resource_titles', 'resource_urls', 'link_labels', 'link_urls']
      .forEach(k => { if (Array.isArray(req.body[k])) fields.push({ key: k, value: JSON.stringify(req.body[k]) }); });

    const errs = await updateMetaobject(node.id, fields);
    if (errs.length) return res.status(400).json({ error: errs.map(e => e.message).join('; ') });
    res.json({ ok: true });
  } catch (e) { console.error(e); res.status(500).json({ error: String(e.message || e) }); }
});

// ==========================================================================
//  MEMBER SAVE  (create on first save)
// ==========================================================================
app.post('/proxy/coach/member-save', async (req, res) => {
  const gid = guard(req, res); if (!gid) return;
  try {
    const existing = await findByCustomer('member_profile', gid);
    const allowed = ['display_name', 'pronouns', 'tagline', 'bio', 'photo_url', 'location', 'visible'];
    const fields = allowed.filter(k => k in req.body)
      .map(k => ({ key: k, value: String(req.body[k] ?? '').slice(0, 4000) }));
    if (Array.isArray(req.body.pillars)) fields.push({ key: 'pillars', value: JSON.stringify(req.body.pillars) });

    let errs;
    if (existing) {
      errs = await updateMetaobject(existing.id, fields);
    } else {
      fields.push({ key: 'customer', value: gid });
      fields.push({ key: 'customer_id', value: String(gid).split('/').pop() });
      errs = await createMetaobject('member_profile', fields);
    }
    if (errs.length) return res.status(400).json({ error: errs.map(e => e.message).join('; ') });
    res.json({ ok: true });
  } catch (e) { console.error(e); res.status(500).json({ error: String(e.message || e) }); }
});

// ==========================================================================
//  COMMUNITY BOARD  —  create a post
// ==========================================================================
app.post('/proxy/coach/post', async (req, res) => {
  const gid = guard(req, res); if (!gid) return;
  try {
    const body = String(req.body.body ?? '').trim().slice(0, 2000);
    if (!body) return res.status(400).json({ error: 'empty post' });
    const authorName = await getCustomerName(gid);
    const fields = [
      { key: 'author',      value: gid },
      { key: 'author_name', value: authorName },
      { key: 'body',        value: body },
      { key: 'created_at',  value: new Date().toISOString() }
    ];
    const errs = await createMetaobject('village_post', fields);
    if (errs.length) return res.status(400).json({ error: errs.map(e => e.message).join('; ') });
    res.json({ ok: true, author_name: authorName });
  } catch (e) { console.error(e); res.status(500).json({ error: String(e.message || e) }); }
});

// ==========================================================================
//  COMMUNITY BOARD  —  list recent posts (newest first)
// ==========================================================================
app.get('/proxy/coach/posts', async (req, res) => {
  // read-only; still require the signed proxy so it can't be hammered directly
  if (!verifyProxy(req.query)) return res.status(401).json({ error: 'bad signature' });
  const me = req.query.logged_in_customer_id ? `gid://shopify/Customer/${req.query.logged_in_customer_id}` : null;
  try {
    const all = await listMetaobjects('village_post');
    all.sort((a, b) => String(b.fields.created_at || '').localeCompare(String(a.fields.created_at || '')));
    // group comments by their parent post, oldest first
    const comments = await listMetaobjects('village_comment');
    comments.sort((a, b) => String(a.fields.created_at || '').localeCompare(String(b.fields.created_at || '')));
    const byPost = {};
    comments.forEach(c => {
      const key = c.fields.post;
      if (!key) return;
      (byPost[key] = byPost[key] || []).push(c);
    });
    res.json({ ok: true, posts: all.slice(0, 50).map(p => ({
      id: p.id,
      author_name: p.fields.author_name || 'Villager',
      body: p.fields.body || '',
      created_at: p.fields.created_at || '',
      mine: !!me && p.fields.author === me,
      comments: (byPost[p.id] || []).map(c => ({
        id: c.id,
        author_name: c.fields.author_name || 'Villager',
        body: c.fields.body || '',
        created_at: c.fields.created_at || '',
        mine: !!me && c.fields.author === me
      }))
    })) });
  } catch (e) { console.error(e); res.status(500).json({ error: String(e.message || e) }); }
});

// ==========================================================================
//  COMMUNITY BOARD  —  add a comment to a post
// ==========================================================================
app.post('/proxy/coach/comment', async (req, res) => {
  const gid = guard(req, res); if (!gid) return;
  try {
    const postId = String(req.body.post || '');
    if (!postId.startsWith('gid://shopify/Metaobject/')) return res.status(400).json({ error: 'bad post id' });
    const body = String(req.body.body ?? '').trim().slice(0, 1000);
    if (!body) return res.status(400).json({ error: 'empty comment' });
    const authorName = await getCustomerName(gid);
    const errs = await createMetaobject('village_comment', [
      { key: 'post',        value: postId },
      { key: 'author',      value: gid },
      { key: 'author_name', value: authorName },
      { key: 'body',        value: body },
      { key: 'created_at',  value: new Date().toISOString() }
    ]);
    if (errs.length) return res.status(400).json({ error: errs.map(e => e.message).join('; ') });
    res.json({ ok: true, author_name: authorName });
  } catch (e) { console.error(e); res.status(500).json({ error: String(e.message || e) }); }
});

// ==========================================================================
//  COMMUNITY BOARD  —  delete your OWN comment
// ==========================================================================
app.post('/proxy/coach/comment-delete', async (req, res) => {
  const gid = guard(req, res); if (!gid) return;
  try {
    const id = String(req.body.id || '');
    if (!id.startsWith('gid://shopify/Metaobject/')) return res.status(400).json({ error: 'bad id' });
    const all = await listMetaobjects('village_comment');
    const c = all.find(x => x.id === id);
    if (!c) return res.status(404).json({ error: 'comment not found' });
    if (c.fields.author !== gid) return res.status(403).json({ error: 'not your comment' });
    const j = await admin(
      `mutation($id:ID!){ metaobjectDelete(id:$id){ deletedId userErrors{message} } }`,
      { id }
    );
    const errs = j.data?.metaobjectDelete?.userErrors;
    if (errs?.length) return res.status(400).json({ error: errs.map(e => e.message).join('; ') });
    res.json({ ok: true });
  } catch (e) { console.error(e); res.status(500).json({ error: String(e.message || e) }); }
});

// ==========================================================================
//  COMMUNITY BOARD  —  delete your OWN post
// ==========================================================================
app.post('/proxy/coach/post-delete', async (req, res) => {
  const gid = guard(req, res); if (!gid) return;
  try {
    const id = String(req.body.id || '');
    if (!id.startsWith('gid://shopify/Metaobject/')) return res.status(400).json({ error: 'bad id' });
    // confirm ownership before deleting
    const posts = await listMetaobjects('village_post');
    const post = posts.find(p => p.id === id);
    if (!post) return res.status(404).json({ error: 'post not found' });
    if (post.fields.author !== gid) return res.status(403).json({ error: 'not your post' });
    const j = await admin(
      `mutation($id:ID!){ metaobjectDelete(id:$id){ deletedId userErrors{message} } }`,
      { id }
    );
    const errs = j.data?.metaobjectDelete?.userErrors;
    if (errs?.length) return res.status(400).json({ error: errs.map(e => e.message).join('; ') });
    res.json({ ok: true });
  } catch (e) { console.error(e); res.status(500).json({ error: String(e.message || e) }); }
});

// ==========================================================================
//  FILE UPLOAD  →  POST /proxy/coach/upload
//  Body: { filename, mimeType, dataBase64, kind }
//  kind "image" (default) → profile photos, anyone signed in.
//  kind "file"            → PDFs / audio / docs for the Library, COACHES ONLY.
//  Returns { ok, url } — a permanent cdn.shopify.com URL.
//  Requires app scopes: write_files, read_files.
// ==========================================================================
app.post('/proxy/coach/upload', async (req, res) => {
  const gid = guard(req, res); if (!gid) return;
  try {
    const { filename, mimeType, dataBase64 } = req.body || {};
    const kind = req.body?.kind === 'file' ? 'file' : 'image';
    if (!dataBase64 || !mimeType) return res.status(400).json({ error: 'missing file data' });

    if (kind === 'image') {
      if (!/^image\//.test(mimeType)) return res.status(400).json({ error: 'images only' });
    } else {
      const coach = await findByCustomer('coach', gid);
      if (!coach) return res.status(403).json({ error: 'coaches only' });
    }

    const buf = Buffer.from(dataBase64, 'base64');
    const cap = kind === 'file' ? 20 : 12;
    if (buf.length > cap * 1024 * 1024) return res.status(400).json({ error: 'file too large (max ' + cap + 'MB)' });
    const name = (filename || (kind === 'file' ? 'upload.pdf' : 'upload.jpg')).replace(/[^\w.\-]/g, '_');
    const resource = kind === 'file' ? 'FILE' : 'IMAGE';

    // 1) staged target
    const staged = await admin(
      `mutation($input:[StagedUploadInput!]!){
         stagedUploadsCreate(input:$input){
           stagedTargets{ url resourceUrl parameters{ name value } }
           userErrors{ message } } }`,
      { input: [{ filename: name, mimeType, resource, httpMethod: 'POST' }] }
    );
    const t = staged.data?.stagedUploadsCreate?.stagedTargets?.[0];
    if (!t) return res.status(400).json({ error: 'staged upload failed: ' + JSON.stringify(staged.data?.stagedUploadsCreate?.userErrors || staged) });

    // 2) POST the bytes to the staged target
    const form = new FormData();
    t.parameters.forEach(p => form.append(p.name, p.value));
    form.append('file', new Blob([buf], { type: mimeType }), name);
    const up = await fetch(t.url, { method: 'POST', body: form });
    if (!up.ok) return res.status(400).json({ error: 'upload POST failed (' + up.status + ')' });

    // 3) register the file in Shopify
    const created = await admin(
      `mutation($files:[FileCreateInput!]!){
         fileCreate(files:$files){
           files{ id fileStatus
             ... on MediaImage { image { url } }
             ... on GenericFile { url } }
           userErrors{ message } } }`,
      { files: [{ originalSource: t.resourceUrl, contentType: resource }] }
    );
    const fileNode = created.data?.fileCreate?.files?.[0];
    const cErr = created.data?.fileCreate?.userErrors;
    if (cErr?.length) return res.status(400).json({ error: cErr.map(e => e.message).join('; ') });
    if (!fileNode) return res.status(400).json({ error: 'fileCreate failed' });

    // 4) poll until the CDN URL is ready (processing is async)
    let url = fileNode.image?.url || fileNode.url || null;
    for (let i = 0; i < 10 && !url; i++) {
      await new Promise(r => setTimeout(r, 700));
      const q = await admin(
        `query($id:ID!){ node(id:$id){
           ... on MediaImage { fileStatus image { url } }
           ... on GenericFile { fileStatus url } } }`,
        { id: fileNode.id }
      );
      url = q.data?.node?.image?.url || q.data?.node?.url || null;
    }
    if (!url) return res.status(202).json({ error: 'file still processing — try again in a moment' });
    res.json({ ok: true, url });
  } catch (e) { console.error(e); res.status(500).json({ error: String(e.message || e) }); }
});

// ==========================================================================
//  LIBRARY  —  coaches add / delete items;  members just read them
//  Metaobject "library_item": title, description, pillar, format, file_url,
//  author_name, author, created_at
// ==========================================================================
app.post('/proxy/coach/library-add', async (req, res) => {
  const gid = guard(req, res); if (!gid) return;
  try {
    const coach = await findByCustomer('coach', gid);
    if (!coach) return res.status(403).json({ error: 'coaches only' });

    const title = String(req.body.title ?? '').trim().slice(0, 200);
    const fileUrl = String(req.body.file_url ?? '').trim().slice(0, 1000);
    if (!title) return res.status(400).json({ error: 'title required' });
    if (!fileUrl) return res.status(400).json({ error: 'upload a file first' });

    const authorName = await getCustomerName(gid);
    const errs = await createMetaobject('library_item', [
      { key: 'title',       value: title },
      { key: 'description', value: String(req.body.description ?? '').trim().slice(0, 2000) },
      { key: 'pillar',      value: String(req.body.pillar ?? '').trim().slice(0, 60) },
      { key: 'format',      value: String(req.body.format ?? '').trim().slice(0, 20) },
      { key: 'file_url',    value: fileUrl },
      { key: 'author',      value: gid },
      { key: 'author_name', value: authorName },
      { key: 'created_at',  value: new Date().toISOString() }
    ]);
    if (errs.length) return res.status(400).json({ error: errs.map(e => e.message).join('; ') });
    res.json({ ok: true });
  } catch (e) { console.error(e); res.status(500).json({ error: String(e.message || e) }); }
});

app.get('/proxy/coach/library', async (req, res) => {
  if (!verifyProxy(req.query)) return res.status(401).json({ error: 'bad signature' });
  const me = req.query.logged_in_customer_id ? `gid://shopify/Customer/${req.query.logged_in_customer_id}` : null;
  try {
    const all = await listMetaobjects('library_item');
    all.sort((a, b) => String(b.fields.created_at || '').localeCompare(String(a.fields.created_at || '')));
    res.json({ ok: true, items: all.map(i => ({
      id: i.id,
      title: i.fields.title || 'Untitled',
      description: i.fields.description || '',
      pillar: i.fields.pillar || '',
      format: i.fields.format || '',
      file_url: i.fields.file_url || '',
      author_name: i.fields.author_name || '',
      created_at: i.fields.created_at || '',
      mine: !!me && i.fields.author === me
    })) });
  } catch (e) { console.error(e); res.status(500).json({ error: String(e.message || e) }); }
});

app.post('/proxy/coach/library-delete', async (req, res) => {
  const gid = guard(req, res); if (!gid) return;
  try {
    const id = String(req.body.id || '');
    if (!id.startsWith('gid://shopify/Metaobject/')) return res.status(400).json({ error: 'bad id' });
    const all = await listMetaobjects('library_item');
    const item = all.find(x => x.id === id);
    if (!item) return res.status(404).json({ error: 'item not found' });
    if (item.fields.author !== gid) return res.status(403).json({ error: 'not your item' });
    const j = await admin(
      `mutation($id:ID!){ metaobjectDelete(id:$id){ deletedId userErrors{message} } }`,
      { id }
    );
    const errs = j.data?.metaobjectDelete?.userErrors;
    if (errs?.length) return res.status(400).json({ error: errs.map(e => e.message).join('; ') });
    res.json({ ok: true });
  } catch (e) { console.error(e); res.status(500).json({ error: String(e.message || e) }); }
});

// ==========================================================================
//  COURSES  —  Skool-style sequential lessons with progress + gating
//  Metaobjects: course, course_lesson, course_progress, lesson_comment
// ==========================================================================

// Which courses can this customer open?
//   course.access      = comma list of tier names that include it, e.g.
//                        "Empowered,Nourished"  (blank = not tier-included)
//   course.required_tag = customer tag granted on purchase, e.g. "course_pop"
function courseUnlocked(course, tagsLower, tierLower) {
  const access = String(course.fields.access || '').toLowerCase();
  if (access) {
    const tiers = access.split(',').map(s => s.trim()).filter(Boolean);
    if (tiers.some(t => tierLower && tierLower.includes(t))) return true;
    if (tiers.some(t => tagsLower.includes(t))) return true;
  }
  const need = String(course.fields.required_tag || '').toLowerCase().trim();
  if (need && tagsLower.includes(need)) return true;
  return false;
}

// name of the coach who owns a course (course.coach holds the coach gid)
function coachNameFor(course, coachById) {
  const c = coachById[course.fields.coach];
  return c ? (c.fields.name || '') : '';
}

async function getCustomerTags(gid) {
  const j = await admin(`query($id:ID!){ customer(id:$id){ tags } }`, { id: gid });
  return (j.data?.customer?.tags || []).map(t => String(t).toLowerCase());
}

function num(v, d) { const n = parseInt(v, 10); return isNaN(n) ? d : n; }

// ---- GET /proxy/coach/courses  → every course + this member's lesson state
app.get('/proxy/coach/courses', async (req, res) => {
  if (!verifyProxy(req.query)) return res.status(401).json({ error: 'bad signature' });
  const cid = req.query.logged_in_customer_id;
  if (!cid) return res.status(401).json({ error: 'not logged in' });
  const gid = `gid://shopify/Customer/${cid}`;
  try {
    const [courses, lessons, progress, tags, coaches] = await Promise.all([
      listMetaobjects('course'),
      listMetaobjects('course_lesson'),
      listMetaobjects('course_progress'),
      getCustomerTags(gid),
      listMetaobjects('coach')
    ]);
    const coachById = {};
    coaches.forEach(c => { coachById[c.id] = c; });
    const tierLower = tags.join(',');
    const minePr = progress.filter(p => p.fields.member === gid);
    const doneSet = new Set(minePr.filter(p => p.fields.lesson !== 'enrolled').map(p => p.fields.lesson));
    // enrollment stamps live in course_progress with lesson === 'enrolled'
    const enrolledAt = {};
    minePr.filter(p => p.fields.lesson === 'enrolled')
          .forEach(p => { enrolledAt[p.fields.course] = p.fields.completed_at; });
    const DAY = 86400000;
    const now = Date.now();

    // pass 1 — which courses has this member finished? (the curriculum
    // pathway lets a course require another course first)
    const lessonsByCourse = {};
    lessons.forEach(l => {
      const k = l.fields.course;
      if (!k) return;
      (lessonsByCourse[k] = lessonsByCourse[k] || []).push(l);
    });
    const courseComplete = {};
    Object.keys(lessonsByCourse).forEach(k => {
      const ls = lessonsByCourse[k];
      courseComplete[k] = ls.length > 0 && ls.every(l => doneSet.has(l.id));
    });

    const out = courses
      .filter(c => String(c.fields.status || '').toLowerCase() === 'published')
      .sort((a, b) => num(a.fields.journey_position, num(a.fields.position, 99))
                    - num(b.fields.journey_position, num(b.fields.position, 99)))
      .map(c => {
        const prereq = String(c.fields.prerequisite || '').trim();
        const prereqMet = !prereq || !!courseComplete[prereq];
        const entitled = courseUnlocked(c, tags, tierLower);
        const unlocked = entitled && prereqMet;
        const drip = num(c.fields.drip_days, 0);   // 0 = no date gate
        const start = enrolledAt[c.id] ? Date.parse(enrolledAt[c.id]) : (unlocked ? now : null);
        const mine = (lessonsByCourse[c.id] || [])
          .slice()
          .sort((a, b) => num(a.fields.position, 99) - num(b.fields.position, 99));
        let priorDone = true;
        const ls = mine.map((l, idx) => {
          const complete = doneSet.has(l.id);
          // date gate: lesson N opens drip*(N-1) days after enrollment
          let dateOpen = true, availableOn = '';
          if (drip > 0 && start) {
            const opensAt = start + (idx * drip * DAY);
            dateOpen = now >= opensAt;
            if (!dateOpen) availableOn = new Date(opensAt).toISOString();
          }
          const open = unlocked && priorDone && dateOpen;
          const row = {
            id: l.id,
            position: idx + 1,
            title: l.fields.title || 'Lesson ' + (idx + 1),
            summary: l.fields.summary || '',
            minutes: l.fields.minutes || '',
            complete,
            locked: !open,
            locked_by_date: unlocked && priorDone && !dateOpen,
            available_on: availableOn,
            // content only travels when the lesson is actually open
            body:      open ? (l.fields.body || '') : '',
            video_url: open ? (l.fields.video_url || '') : '',
            file_url:  open ? (l.fields.file_url || '') : ''
          };
          if (!complete) priorDone = false;
          return row;
        });
        const doneCount = ls.filter(l => l.complete).length;
        const next = ls.find(l => !l.complete && !l.locked) || null;
        return {
          id: c.id,
          title: c.fields.title || 'Course',
          description: c.fields.description || '',
          cover_url: c.fields.cover_url || '',
          pillar: c.fields.pillar || '',
          product_url: c.fields.product_url || '',
          drip_days: drip,
          coach_name: coachNameFor(c, coachById),
          journey_position: num(c.fields.journey_position, num(c.fields.position, 0)),
          entitled,
          prereq_met: prereqMet,
          prereq_title: (prereq && !prereqMet)
            ? ((courses.find(x => x.id === prereq) || { fields: {} }).fields.title || 'the previous course')
            : '',
          unlocked,
          lessons: ls,
          total: ls.length,
          done: doneCount,
          percent: ls.length ? Math.round(doneCount * 100 / ls.length) : 0,
          completed: ls.length > 0 && doneCount === ls.length,
          next_lesson: next ? { id: next.id, title: next.title, position: next.position } : null
        };
      });

    // stamp enrollment the first time a member opens a drip course they can access
    const needStamp = courses.filter(c =>
      courseUnlocked(c, tags, tierLower) && num(c.fields.drip_days, 0) > 0 && !enrolledAt[c.id]
    );
    for (const c of needStamp) {
      await createMetaobject('course_progress', [
        { key: 'member',       value: gid },
        { key: 'lesson',       value: 'enrolled' },
        { key: 'course',       value: c.id },
        { key: 'completed_at', value: new Date().toISOString() }
      ]);
    }

    res.json({ ok: true, courses: out });
  } catch (e) { console.error(e); res.status(500).json({ error: String(e.message || e) }); }
});

// ---- POST /proxy/coach/lesson-complete  { lesson, course, undo? }
app.post('/proxy/coach/lesson-complete', async (req, res) => {
  const gid = guard(req, res); if (!gid) return;
  try {
    const lesson = String(req.body.lesson || '');
    const course = String(req.body.course || '');
    if (!lesson.startsWith('gid://shopify/Metaobject/')) return res.status(400).json({ error: 'bad lesson id' });

    const all = await listMetaobjects('course_progress');
    const existing = all.find(p => p.fields.member === gid && p.fields.lesson === lesson);

    if (req.body.undo) {
      if (!existing) return res.json({ ok: true });
      const j = await admin(`mutation($id:ID!){ metaobjectDelete(id:$id){ deletedId userErrors{message} } }`, { id: existing.id });
      const errs = j.data?.metaobjectDelete?.userErrors;
      if (errs?.length) return res.status(400).json({ error: errs.map(e => e.message).join('; ') });
      return res.json({ ok: true });
    }

    if (existing) return res.json({ ok: true });  // already complete
    const errs = await createMetaobject('course_progress', [
      { key: 'member',       value: gid },
      { key: 'lesson',       value: lesson },
      { key: 'course',       value: course },
      { key: 'completed_at', value: new Date().toISOString() }
    ]);
    if (errs.length) return res.status(400).json({ error: errs.map(e => e.message).join('; ') });
    res.json({ ok: true });
  } catch (e) { console.error(e); res.status(500).json({ error: String(e.message || e) }); }
});

// ---- Lesson discussion -----------------------------------------------------
app.get('/proxy/coach/lesson-comments', async (req, res) => {
  if (!verifyProxy(req.query)) return res.status(401).json({ error: 'bad signature' });
  const cid = req.query.logged_in_customer_id;
  const me = cid ? `gid://shopify/Customer/${cid}` : null;
  const lesson = String(req.query.lesson || '');
  try {
    const all = await listMetaobjects('lesson_comment');
    const rows = all
      .filter(c => !lesson || c.fields.lesson === lesson)
      .sort((a, b) => String(a.fields.created_at || '').localeCompare(String(b.fields.created_at || '')))
      .map(c => ({
        id: c.id,
        lesson: c.fields.lesson || '',
        author_name: c.fields.author_name || 'Villager',
        body: c.fields.body || '',
        created_at: c.fields.created_at || '',
        mine: !!me && c.fields.author === me
      }));
    res.json({ ok: true, comments: rows });
  } catch (e) { console.error(e); res.status(500).json({ error: String(e.message || e) }); }
});

app.post('/proxy/coach/lesson-comment', async (req, res) => {
  const gid = guard(req, res); if (!gid) return;
  try {
    const lesson = String(req.body.lesson || '');
    if (!lesson.startsWith('gid://shopify/Metaobject/')) return res.status(400).json({ error: 'bad lesson id' });
    const body = String(req.body.body ?? '').trim().slice(0, 1000);
    if (!body) return res.status(400).json({ error: 'empty comment' });
    const authorName = await getCustomerName(gid);
    const errs = await createMetaobject('lesson_comment', [
      { key: 'lesson',      value: lesson },
      { key: 'author',      value: gid },
      { key: 'author_name', value: authorName },
      { key: 'body',        value: body },
      { key: 'created_at',  value: new Date().toISOString() }
    ]);
    if (errs.length) return res.status(400).json({ error: errs.map(e => e.message).join('; ') });
    res.json({ ok: true });
  } catch (e) { console.error(e); res.status(500).json({ error: String(e.message || e) }); }
});

app.post('/proxy/coach/lesson-comment-delete', async (req, res) => {
  const gid = guard(req, res); if (!gid) return;
  try {
    const id = String(req.body.id || '');
    if (!id.startsWith('gid://shopify/Metaobject/')) return res.status(400).json({ error: 'bad id' });
    const all = await listMetaobjects('lesson_comment');
    const c = all.find(x => x.id === id);
    if (!c) return res.status(404).json({ error: 'comment not found' });
    if (c.fields.author !== gid) return res.status(403).json({ error: 'not your comment' });
    const j = await admin(`mutation($id:ID!){ metaobjectDelete(id:$id){ deletedId userErrors{message} } }`, { id });
    const errs = j.data?.metaobjectDelete?.userErrors;
    if (errs?.length) return res.status(400).json({ error: errs.map(e => e.message).join('; ') });
    res.json({ ok: true });
  } catch (e) { console.error(e); res.status(500).json({ error: String(e.message || e) }); }
});

// ---- COACH VIEW: how far along is everyone? (coaches only) -----------------
app.get('/proxy/coach/course-report', async (req, res) => {
  if (!verifyProxy(req.query)) return res.status(401).json({ error: 'bad signature' });
  const cid = req.query.logged_in_customer_id;
  if (!cid) return res.status(401).json({ error: 'not logged in' });
  const gid = `gid://shopify/Customer/${cid}`;
  try {
    const coach = await findByCustomer('coach', gid);
    if (!coach) return res.status(403).json({ error: 'coaches only' });

    const [courses, lessons, progress, profiles] = await Promise.all([
      listMetaobjects('course'),
      listMetaobjects('course_lesson'),
      listMetaobjects('course_progress'),
      listMetaobjects('member_profile')
    ]);
    const nameOf = {};
    profiles.forEach(p => { if (p.fields.customer) nameOf[p.fields.customer] = p.fields.display_name || ''; });
    const totals = {};
    courses.forEach(c => { totals[c.id] = lessons.filter(l => l.fields.course === c.id).length; });
    const titleOf = {};
    courses.forEach(c => { titleOf[c.id] = c.fields.title || 'Course'; });

    const byMember = {};
    progress.filter(p => p.fields.lesson !== 'enrolled').forEach(p => {
      const m = p.fields.member, c = p.fields.course;
      if (!m) return;
      byMember[m] = byMember[m] || {};
      byMember[m][c] = (byMember[m][c] || 0) + 1;
    });

    const rows = [];
    Object.keys(byMember).forEach(m => {
      Object.keys(byMember[m]).forEach(c => {
        const total = totals[c] || 0;
        rows.push({
          member: nameOf[m] || 'Villager',
          course: titleOf[c] || 'Course',
          done: byMember[m][c],
          total,
          percent: total ? Math.round(byMember[m][c] * 100 / total) : 0
        });
      });
    });
    rows.sort((a, b) => b.percent - a.percent);
    res.json({ ok: true, rows });
  } catch (e) { console.error(e); res.status(500).json({ error: String(e.message || e) }); }
});

// ==========================================================================
//  COURSE BUILDER  —  coaches create and edit their OWN courses
//  A coach may only touch a course whose "coach" field is their coach record.
// ==========================================================================

async function requireCoach(gid, res) {
  const coach = await findByCustomer('coach', gid);
  if (!coach) { res.status(403).json({ error: 'coaches only' }); return null; }
  return coach;
}

// ---- GET /proxy/coach/my-courses → this coach's courses WITH full lessons
app.get('/proxy/coach/my-courses', async (req, res) => {
  if (!verifyProxy(req.query)) return res.status(401).json({ error: 'bad signature' });
  const cid = req.query.logged_in_customer_id;
  if (!cid) return res.status(401).json({ error: 'not logged in' });
  const gid = `gid://shopify/Customer/${cid}`;
  try {
    const coach = await requireCoach(gid, res); if (!coach) return;
    const [courses, lessons] = await Promise.all([
      listMetaobjects('course'), listMetaobjects('course_lesson')
    ]);
    const mine = courses
      .filter(c => c.fields.coach === coach.id)
      .sort((a, b) => num(a.fields.journey_position, 99) - num(b.fields.journey_position, 99));
    res.json({ ok: true,
      all_courses: courses.map(c => ({ id: c.id, title: c.fields.title || 'Course' })),
      courses: mine.map(c => ({
        id: c.id,
        title: c.fields.title || '',
        description: c.fields.description || '',
        pillar: c.fields.pillar || '',
        access: c.fields.access || '',
        required_tag: c.fields.required_tag || '',
        product_url: c.fields.product_url || '',
        drip_days: c.fields.drip_days || '',
        status: c.fields.status || 'draft',
        prerequisite: c.fields.prerequisite || '',
        journey_position: c.fields.journey_position || '',
        lessons: lessons.filter(l => l.fields.course === c.id)
          .sort((a, b) => num(a.fields.position, 99) - num(b.fields.position, 99))
          .map(l => ({
            id: l.id,
            position: l.fields.position || '',
            title: l.fields.title || '',
            summary: l.fields.summary || '',
            minutes: l.fields.minutes || '',
            body: l.fields.body || '',
            video_url: l.fields.video_url || '',
            file_url: l.fields.file_url || ''
          }))
      })) });
  } catch (e) { console.error(e); res.status(500).json({ error: String(e.message || e) }); }
});

const COURSE_KEYS = ['title','description','pillar','access','required_tag',
                     'product_url','drip_days','prerequisite','journey_position','cover_url'];
// 'status' is deliberately NOT in COURSE_KEYS — only the shop owner publishes
// a course (in Shopify admin). Anything a coach saves stays a draft.

// ---- POST /proxy/coach/course-save  { id?, ...fields }
app.post('/proxy/coach/course-save', async (req, res) => {
  const gid = guard(req, res); if (!gid) return;
  try {
    const coach = await requireCoach(gid, res); if (!coach) return;
    const title = String(req.body.title ?? '').trim();
    if (!title) return res.status(400).json({ error: 'title required' });

    const fields = COURSE_KEYS.filter(k => k in req.body)
      .map(k => ({ key: k, value: String(req.body[k] ?? '').slice(0, 4000) }));

    const id = String(req.body.id || '');
    if (id) {
      const all = await listMetaobjects('course');
      const c = all.find(x => x.id === id);
      if (!c) return res.status(404).json({ error: 'course not found' });
      if (c.fields.coach !== coach.id) return res.status(403).json({ error: 'not your course' });
      const errs = await updateMetaobject(id, fields);
      if (errs.length) return res.status(400).json({ error: errs.map(e => e.message).join('; ') });
      return res.json({ ok: true, id });
    }

    fields.push({ key: 'coach', value: coach.id });
    fields.push({ key: 'status', value: 'draft' });   // owner publishes it
    const j = await admin(
      `mutation($fields:[MetaobjectFieldInput!]!){
         metaobjectCreate(metaobject:{type:"course", fields:$fields, capabilities:{publishable:{status:ACTIVE}}}){
           metaobject{ id } userErrors{ field message } } }`,
      { fields }
    );
    const errs = j.data?.metaobjectCreate?.userErrors;
    if (errs?.length) return res.status(400).json({ error: errs.map(e => e.message).join('; ') });
    res.json({ ok: true, id: j.data?.metaobjectCreate?.metaobject?.id || '' });
  } catch (e) { console.error(e); res.status(500).json({ error: String(e.message || e) }); }
});

// ---- POST /proxy/coach/course-delete  { id }   (also removes its lessons)
app.post('/proxy/coach/course-delete', async (req, res) => {
  const gid = guard(req, res); if (!gid) return;
  try {
    const coach = await requireCoach(gid, res); if (!coach) return;
    const id = String(req.body.id || '');
    const all = await listMetaobjects('course');
    const c = all.find(x => x.id === id);
    if (!c) return res.status(404).json({ error: 'course not found' });
    if (c.fields.coach !== coach.id) return res.status(403).json({ error: 'not your course' });

    const lessons = await listMetaobjects('course_lesson');
    for (const l of lessons.filter(l => l.fields.course === id)) {
      await admin(`mutation($id:ID!){ metaobjectDelete(id:$id){ deletedId } }`, { id: l.id });
    }
    await admin(`mutation($id:ID!){ metaobjectDelete(id:$id){ deletedId } }`, { id });
    res.json({ ok: true });
  } catch (e) { console.error(e); res.status(500).json({ error: String(e.message || e) }); }
});

const LESSON_KEYS = ['position','title','summary','minutes','body','video_url','file_url'];

// ---- POST /proxy/coach/lesson-save  { id?, course, ...fields }
app.post('/proxy/coach/lesson-save', async (req, res) => {
  const gid = guard(req, res); if (!gid) return;
  try {
    const coach = await requireCoach(gid, res); if (!coach) return;
    const courseId = String(req.body.course || '');
    const courses = await listMetaobjects('course');
    const c = courses.find(x => x.id === courseId);
    if (!c) return res.status(404).json({ error: 'course not found' });
    if (c.fields.coach !== coach.id) return res.status(403).json({ error: 'not your course' });

    const title = String(req.body.title ?? '').trim();
    if (!title) return res.status(400).json({ error: 'lesson title required' });
    const fields = LESSON_KEYS.filter(k => k in req.body)
      .map(k => ({ key: k, value: String(req.body[k] ?? '').slice(0, 20000) }));

    const id = String(req.body.id || '');
    if (id) {
      const lessons = await listMetaobjects('course_lesson');
      const l = lessons.find(x => x.id === id);
      if (!l) return res.status(404).json({ error: 'lesson not found' });
      if (l.fields.course !== courseId) return res.status(403).json({ error: 'lesson/course mismatch' });
      const errs = await updateMetaobject(id, fields);
      if (errs.length) return res.status(400).json({ error: errs.map(e => e.message).join('; ') });
      return res.json({ ok: true, id });
    }

    fields.push({ key: 'course', value: courseId });
    const errs = await createMetaobject('course_lesson', fields);
    if (errs.length) return res.status(400).json({ error: errs.map(e => e.message).join('; ') });
    res.json({ ok: true });
  } catch (e) { console.error(e); res.status(500).json({ error: String(e.message || e) }); }
});

// ---- POST /proxy/coach/lesson-delete  { id }
app.post('/proxy/coach/lesson-delete', async (req, res) => {
  const gid = guard(req, res); if (!gid) return;
  try {
    const coach = await requireCoach(gid, res); if (!coach) return;
    const id = String(req.body.id || '');
    const [lessons, courses] = await Promise.all([
      listMetaobjects('course_lesson'), listMetaobjects('course')
    ]);
    const l = lessons.find(x => x.id === id);
    if (!l) return res.status(404).json({ error: 'lesson not found' });
    const c = courses.find(x => x.id === l.fields.course);
    if (!c || c.fields.coach !== coach.id) return res.status(403).json({ error: 'not your lesson' });
    const j = await admin(`mutation($id:ID!){ metaobjectDelete(id:$id){ deletedId userErrors{message} } }`, { id });
    const errs = j.data?.metaobjectDelete?.userErrors;
    if (errs?.length) return res.status(400).json({ error: errs.map(e => e.message).join('; ') });
    res.json({ ok: true });
  } catch (e) { console.error(e); res.status(500).json({ error: String(e.message || e) }); }
});

// ---- health check ---------------------------------------------------------
app.get('/', (_req, res) => res.send('NOVA Coach Studio API is running.'));

// ---- DEBUG: what scopes does the live token actually have? -----------------
// Visit through the proxy while signed in: /apps/coach/whoami
app.get('/proxy/coach/whoami', async (req, res) => {
  if (!verifyProxy(req.query)) return res.status(401).json({ error: 'bad signature' });
  try {
    await getToken(); // refreshes _lastTokenScopes
    const j = await admin(`{ currentAppInstallation { accessScopes { handle } } }`, {});
    const granted = (j.data?.currentAppInstallation?.accessScopes || []).map(s => s.handle);
    res.json({ ok: true, token_scope: _lastTokenScopes, installation_scopes: granted });
  } catch (e) { res.status(500).json({ error: String(e.message || e) }); }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`NOVA Coach Studio API v2 listening on :${PORT}`));
