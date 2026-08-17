/* ==========================================================================
   NOVA Coach Studio API  ·  Shopify App Proxy server  (v2 — robust)
   Endpoints (storefront calls the /apps/coach/* proxy):
     POST /proxy/coach/save         → update the "coach" metaobject
     POST /proxy/coach/member-save  → create/update "member_profile"
     POST /proxy/coach/post         → create a "village_post" (community board)
     GET  /proxy/coach/posts        → list recent village_post entries (JSON)
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

// ---- Access token (client-credentials grant, cached) ----------------------
let _token = null, _tokenExp = 0;
async function getToken() {
  if (_token && Date.now() < _tokenExp - 60000) return _token;
  const r = await fetch(TOKEN_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ client_id: CLIENT_ID, client_secret: CLIENT_SECRET, grant_type: 'client_credentials' })
  });
  const j = await r.json();
  if (!j.access_token) throw new Error('token exchange failed: ' + JSON.stringify(j));
  _token = j.access_token;
  _tokenExp = Date.now() + ((j.expires_in || 86400) * 1000);
  return _token;
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
  return all.find(m => m.fields.customer === gid) || null;
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
    res.json({ ok: true, posts: all.slice(0, 50).map(p => ({
      id: p.id,
      author_name: p.fields.author_name || 'Villager',
      body: p.fields.body || '',
      created_at: p.fields.created_at || '',
      mine: !!me && p.fields.author === me
    })) });
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
//  Body: { filename, mimeType, dataBase64 }  → uploads to Shopify Files,
//  returns { ok, url } (a permanent cdn.shopify.com image URL).
//  Requires app scopes: write_files, read_files.
// ==========================================================================
app.post('/proxy/coach/upload', async (req, res) => {
  const gid = guard(req, res); if (!gid) return;
  try {
    const { filename, mimeType, dataBase64 } = req.body || {};
    if (!dataBase64 || !mimeType) return res.status(400).json({ error: 'missing file data' });
    if (!/^image\//.test(mimeType)) return res.status(400).json({ error: 'images only' });
    const buf = Buffer.from(dataBase64, 'base64');
    if (buf.length > 12 * 1024 * 1024) return res.status(400).json({ error: 'image too large (max 12MB)' });
    const name = (filename || 'upload.jpg').replace(/[^\w.\-]/g, '_');

    // 1) staged target
    const staged = await admin(
      `mutation($input:[StagedUploadInput!]!){
         stagedUploadsCreate(input:$input){
           stagedTargets{ url resourceUrl parameters{ name value } }
           userErrors{ message } } }`,
      { input: [{ filename: name, mimeType, resource: 'IMAGE', httpMethod: 'POST' }] }
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
         fileCreate(files:$files){ files{ id fileStatus ... on MediaImage { image { url } } } userErrors{ message } } }`,
      { files: [{ originalSource: t.resourceUrl, contentType: 'IMAGE' }] }
    );
    const fileNode = created.data?.fileCreate?.files?.[0];
    const cErr = created.data?.fileCreate?.userErrors;
    if (cErr?.length) return res.status(400).json({ error: cErr.map(e => e.message).join('; ') });
    if (!fileNode) return res.status(400).json({ error: 'fileCreate failed' });

    // 4) poll until the CDN URL is ready (image processing is async)
    let url = fileNode.image?.url || null;
    for (let i = 0; i < 10 && !url; i++) {
      await new Promise(r => setTimeout(r, 700));
      const q = await admin(
        `query($id:ID!){ node(id:$id){ ... on MediaImage { fileStatus image { url } } } }`,
        { id: fileNode.id }
      );
      url = q.data?.node?.image?.url || null;
    }
    if (!url) return res.status(202).json({ error: 'image still processing — try saving again in a moment' });
    res.json({ ok: true, url });
  } catch (e) { console.error(e); res.status(500).json({ error: String(e.message || e) }); }
});

// ---- health check ---------------------------------------------------------
app.get('/', (_req, res) => res.send('NOVA Coach Studio API is running.'));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`NOVA Coach Studio API v2 listening on :${PORT}`));
