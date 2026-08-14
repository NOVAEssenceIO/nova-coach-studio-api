# NOVA Coach Studio API

Tiny Shopify **App Proxy** server that lets coaches and members edit their own
profiles from the storefront. Liquid can only *read* Metaobjects; this server
does the *writes* via the Admin API.

Two endpoints (called from the storefront through the App Proxy):

| Storefront calls        | Proxy forwards to          | What it does |
|-------------------------|----------------------------|--------------|
| `/apps/coach/save`      | `POST /proxy/coach/save`   | Updates the `coach` metaobject linked to the logged-in coach |
| `/apps/member/save`     | `POST /proxy/member/save`  | Creates/updates the `member_profile` for the logged-in member |

Each request is verified against Shopify's proxy **signature**, and a user can
only edit the record whose `customer` field matches their own login. Editable
fields are whitelisted.

---

## 1. Create the custom app (once)

Shopify admin → **Settings → Apps and sales channels → Develop apps → Create an app**
(name: *Coach Studio API*).

**Admin API scopes:** `read_metaobjects`, `write_metaobjects`, `read_customers`

Install → reveal the **Admin API access token** (`shpat_…`).
Under **API credentials**, copy the **API secret key**.

## 2. Add the App Proxy

App → **Configuration → App proxy**:

- Subpath prefix: `apps`
- Subpath: (leave blank or `coach` — see note below)
- Proxy URL: `https://YOUR-SERVER.com/proxy`

> **Routing note.** The storefront calls `/apps/coach/save` and
> `/apps/member/save`. With prefix `apps` and **no** subpath, Shopify forwards
> the remaining path (`/coach/save`, `/member/save`) to `PROXY_URL + path`, so
> Proxy URL `https://YOUR-SERVER.com/proxy` maps them to `/proxy/coach/save`
> and `/proxy/member/save` — exactly the routes in `server.js`. If your proxy
> config forces a single subpath, create two proxies (`coach`, `member`) both
> pointing at `/proxy`.

## 3. Deploy

Any Node 18+ host (Render, Railway, Fly, Vercel). Example (Render):

1. Push this folder to a GitHub repo.
2. New **Web Service** → build `npm install`, start `npm start`.
3. Set environment variables:

```
SHOP=nova-essenceio.myshopify.com
ADMIN_API_TOKEN=shpat_xxxxxxxxxxxxxxxx
APP_PROXY_SECRET=xxxxxxxxxxxxxxxx
```

4. Put the service's public URL into the App Proxy **Proxy URL** (step 2).

Local test: `npm install && npm start` → http://localhost:3000/ shows a health message.

## 4. Wire the storefront

Add the coach edit form/JS from `coach-studio-self-service-editing.txt` and the
member profile form/JS from `member-self-service-profiles.txt` into
`sections/support-village.liquid`. They POST to `/apps/coach/save` and
`/apps/member/save`.

## Security notes

- Requests missing/failing the Shopify proxy **signature** are rejected (401).
- `logged_in_customer_id` comes from Shopify (not the browser), so identity
  can't be spoofed.
- Coaches can only edit their own `coach` record; members only their own
  `member_profile`. The `customer` link and `id` are never client-editable.
- Field values are length-capped. Add rate limiting if abuse is a concern.
