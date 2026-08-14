/* ==========================================================================
   NOVA Coach Studio API  ·  Shopify App Proxy server
   Handles self-service profile edits from the storefront:
     POST /proxy/coach/save    → updates the "coach" metaobject for the coach
     POST /proxy/member/save   → creates/updates "member_profile" for the member
   Storefront calls /apps/coach/save and /apps/member/save; the App Proxy
   forwards them here (signed by Shopify).
   ========================================================================== */

const express = require('express');
const crypto  = require('crypto');

const app = express();
app.use(express.json());

// ---- Config (set these as environment variables on your host) -------------
const SHOP   = process.env.SHOP || 'nova-essenceio.myshopify.com';
const CLIENT_ID     = process.env.CLIENT_ID;      // Dev Dashboard → Settings → Client ID
const CLIENT_SECRET = process.env.CLIENT_SECRET;  // Dev Dashboard → Settings → Secret
const API_VERSION = '2026-07';
const API_URL   = `https://${SHOP}/admin/api/${API_VERSION}/graphql.json`;
const TOKEN_URL = `https://${SHOP}/admin/oauth/access_token`;

if (!CLIENT_ID || !CLIENT_SECRET) {
  console.warn('[warn] CLIENT_ID and/or CLIENT_SECRET not set — requests will fail until they are.');
}

// ---- Access token via client-credentials grant (cached, auto-refresh) -----
// Dev Dashboard apps don't expose a static shpat_ token; we exchange the
// client id/secret for a short-lived token (valid ~24h) and cache it.
let _token = null, _tokenExp = 0;
async function getToken() {
  if (_token && Date.now() < _tokenExp - 60000) return _token;   // 1-min safety margin
  const r = await fetch(TOKEN_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      grant_type: 'client_credentials'
    })
  });
  const j = await r.json();
  if (!j.access_token) throw new Error('token exchange failed: ' + JSON.stringify(j));
  _token = j.access_token;
  _tokenExp = Date.now() + ((j.expires_in || 86400) * 1000);
  return _token;
}

// ---- Verify the request truly came through Shopify's signed App Proxy ------
function verifyProxy(query) {
  const { signature, ...rest } = query;
  if (!signature) return false;
  const message = Object.keys(rest).sort()
    .map(k => `${k}=${Array.isArray(rest[k]) ? rest[k].join(',') : rest[k]}`)
    .join('');
  const digest = crypto.createHmac('sha256', CLIENT_SECRET).update(message).digest('hex');
  try {
    return crypto.timingSafeEqual(Buffer.from(digest), Buffer.from(signature));
  } catch (_) {
    return false;
  }
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

// ---- Guard shared by both routes ------------------------------------------
function guard(req, res) {
  if (!verifyProxy(req.query)) { res.status(401).json({ error: 'bad signature' }); return null; }
  const customerId = req.query.logged_in_customer_id;
  if (!customerId) { res.status(401).json({ error: 'not logged in' }); return null; }
  return `gid://shopify/Customer/${customerId}`;
}

// ==========================================================================
//  COACH SAVE  →  POST /proxy/coach/save
// ==========================================================================
app.post('/proxy/coach/save', async (req, res) => {
  const gid = guard(req, res); if (!gid) return;
  try {
    const find = await admin(
      `query($q:String!){ metaobjects(type:"coach", first:1, query:$q){ edges{ node{ id } } } }`,
      { q: `fields.customer:${gid}` }
    );
    const node = find.data?.metaobjects?.edges?.[0]?.node;
    if (!node) return res.status(403).json({ error: 'no coach record for this customer' });

    const allowed = ['name', 'title', 'photo_url', 'bio', 'booking_url'];
    const fields = allowed.filter(k => k in req.body)
      .map(k => ({ key: k, value: String(req.body[k]).slice(0, 4000) }));
    ['pillars', 'resource_titles', 'resource_urls', 'link_labels', 'link_urls']
      .forEach(k => { if (Array.isArray(req.body[k])) fields.push({ key: k, value: JSON.stringify(req.body[k]) }); });

    const upd = await admin(
      `mutation($id:ID!, $fields:[MetaobjectFieldInput!]!){
         metaobjectUpdate(id:$id, metaobject:{fields:$fields}){ userErrors{field message} } }`,
      { id: node.id, fields }
    );
    const errs = upd.data?.metaobjectUpdate?.userErrors;
    if (errs?.length) return res.status(400).json({ error: errs });
    res.json({ ok: true });
  } catch (e) {
    console.error(e); res.status(500).json({ error: 'server error' });
  }
});

// ==========================================================================
//  MEMBER SAVE  →  POST /proxy/member/save   (creates on first save)
// ==========================================================================
app.post('/proxy/member/save', async (req, res) => {
  const gid = guard(req, res); if (!gid) return;
  try {
    const find = await admin(
      `query($q:String!){ metaobjects(type:"member_profile", first:1, query:$q){ edges{ node{ id } } } }`,
      { q: `fields.customer:${gid}` }
    );
    const existing = find.data?.metaobjects?.edges?.[0]?.node;

    const allowed = ['display_name', 'pronouns', 'tagline', 'bio', 'photo_url', 'location', 'visible'];
    const fields = allowed.filter(k => k in req.body)
      .map(k => ({ key: k, value: String(req.body[k]).slice(0, 4000) }));
    if (Array.isArray(req.body.pillars)) fields.push({ key: 'pillars', value: JSON.stringify(req.body.pillars) });

    let out, errs;
    if (existing) {
      out = await admin(
        `mutation($id:ID!, $fields:[MetaobjectFieldInput!]!){
           metaobjectUpdate(id:$id, metaobject:{fields:$fields}){ userErrors{field message} } }`,
        { id: existing.id, fields }
      );
      errs = out.data?.metaobjectUpdate?.userErrors;
    } else {
      fields.push({ key: 'customer', value: gid });
      out = await admin(
        `mutation($fields:[MetaobjectFieldInput!]!){
           metaobjectCreate(metaobject:{type:"member_profile", fields:$fields, capabilities:{publishable:{status:ACTIVE}}}){ userErrors{field message} } }`,
        { fields }
      );
      errs = out.data?.metaobjectCreate?.userErrors;
    }
    if (errs?.length) return res.status(400).json({ error: errs });
    res.json({ ok: true });
  } catch (e) {
    console.error(e); res.status(500).json({ error: 'server error' });
  }
});

// ---- health check ---------------------------------------------------------
app.get('/', (_req, res) => res.send('NOVA Coach Studio API is running.'));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`NOVA Coach Studio API listening on :${PORT}`));
