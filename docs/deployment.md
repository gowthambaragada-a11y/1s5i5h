# Deploying NETGUARD-AI

Two halves that deploy independently:

| Piece | Where | Needs a database? |
|---|---|---|
| Frontend (React/Vite) | GitHub Pages, auto-deploys from `main` | no |
| Backend (FastAPI) | Render, manually created | yes, for a useful fleet view |

The frontend **probes** the backend on load. If the backend answers, the app
asks the operator to sign in and everything is live. If it does not, the app
falls back to the bundled snapshot (`frontend/public/demo-data.json`) so the
Pages link still demonstrates the pipeline. That is why a static-only deployment
is a valid fallback state and not a broken one.

---

## 1. Backend on Render

### 1a. Get a Postgres URL first

Render's bundled free Postgres expires after 30 days, which silently wipes the
demo's history. Use a provider with a permanent free tier instead:

- **Neon** — console.neon.tech, create a project, copy the **pooled** connection
  string.
- **Supabase** — project settings → Database, copy the URI.

Rewrite the scheme to the SQLAlchemy driver name:

```
postgresql://user:pass@host/db?sslmode=require     <- what the provider shows
postgresql+psycopg://user:pass@host/db?sslmode=require   <- what the app needs
```

The `+psycopg` part is not optional. Without it SQLAlchemy looks for a `psycopg2`
driver, fails to import, and `session_scope` yields `None` — the API still starts
and then returns `503` from every database-backed endpoint.

### 1b. Create the service

Render dashboard → **New → Blueprint** → select this repository. `render.yaml`
declares the service; Render will prompt for the three `sync: false` values
(`POSTGRES_DSN`, and the optional `NEO4J_*` / `LLM_API_KEY`).

Prefer the manual path (**New → Web Service**), which takes the same values:

| Setting | Value |
|---|---|
| Root directory | `backend` |
| Runtime | Python 3.11+ |
| Build command | `pip install --upgrade pip && pip install .` |
| Start command | `uvicorn app.main:app --host 0.0.0.0 --port $PORT --timeout-keep-alive 65` |
| Health check path | `/api/v1/healthz` |

The start command must bind `0.0.0.0` and read `$PORT` from the environment.
A hardcoded `8000` is the most common reason Render reports a service as
unhealthy immediately after deploy.

### 1c. Environment variables

Set these in the service's **Environment** tab. `backend/.env.example` documents
all of them.

| Variable | Value | Notes |
|---|---|---|
| `ENVIRONMENT` | `prod` | Exactly `prod`. The field is a `Literal`, so `production` fails validation and the service crash-loops. |
| `SECRET_KEY` | 48+ random bytes | `python -c "import secrets; print(secrets.token_urlsafe(48))"` |
| `ALLOW_DEMO_ACCOUNTS` | `false` | Required in prod |
| `POSTGRES_DSN` | `postgresql+psycopg://…` | From 1a |
| `CORS_ORIGINS` | `["https://gowthambaragada-a11y.github.io"]` | JSON array — see below |
| `ACCESS_TOKEN_TTL_MINUTES` | `60` | |
| `NEO4J_URI` / `NEO4J_USER` / `NEO4J_PASSWORD` | omit | Optional; only `/graph/exposed-services` needs them |
| `LLM_API_KEY` | omit | Optional; the pipeline runs on rules and templates without it |

Two of these fail the deploy loudly rather than silently, which is intentional:
startup raises if `ENVIRONMENT=prod` with either the placeholder `SECRET_KEY`
or `ALLOW_DEMO_ACCOUNTS=true`. The built-in `admin/admin123!`,
`analyst/analyst123!` and `viewer/viewer123!` passwords are printed in this
repository's README, so a deployment that enables them is a public admin account.

**`CORS_ORIGINS` must be a JSON array.** `CORS_ORIGINS=a,b` looks friendlier and
crashes at startup: pydantic-settings decodes list-typed fields with
`json.loads` *before* any validator runs, so the comma-splitting validator in
`Settings` never sees the string. Origins must match exactly — no trailing slash
— and there is no wildcard, because browsers reject `*` when credentials are
allowed.

### 1d. Create the first operator account

With `ALLOW_DEMO_ACCOUNTS=false` there is no way in until an account exists.
There is deliberately no admin HTTP endpoint: a route that can mint an
administrator token has to be reachable before anyone is authenticated.

Open a shell on the service (**Render → Shell**) or run it anywhere with the same
`POSTGRES_DSN`:

```
cd backend
export OPERATOR_PASSWORD='a-real-password'
python -m scripts.create_operator --username operator --role admin
```

Notes:

- The password goes through `OPERATOR_PASSWORD`, never `--password`. `argv` is
  visible to every other process on the machine and lands in shell history.
- Minimum 12 characters, which also rules out the three demo passwords.
- `--rotate` resets an existing account's password and role instead of failing.
  Tokens already issued stay valid until they expire; there is no revocation list.
- The script creates the schema on first run, so there is no separate migration
  step.

---

## 2. Frontend on GitHub Pages

`.github/workflows/deploy-pages.yml` builds and publishes on every push to
`main`. Nothing to click, once Pages is set to the **GitHub Actions** source.

Add repository secrets under **Settings → Pages → Code and automation →
Actions** (they are build-time variables, not Pages config):

| Secret | Value |
|---|---|
| `VITE_API_BASE_URL` | `https://netguard-ai.onrender.com` — origin only |
| `VITE_ENABLE_DEMO_FALLBACK` | `false` |
| `VITE_API_TIMEOUT_MS` | `30000` (see the note below) |

`VITE_API_BASE_URL` must **not** include `/api/v1`. `frontend/src/api/client.ts`
appends the prefix itself, so a value that already contains it produces
`/api/v1/api/v1/...` and every request 404s.

Anything prefixed `VITE_` is compiled into the JavaScript bundle and is readable
by anyone who loads the page. That is fine for a backend URL and fatal for a
token — there is no server to hold a secret here.

### Timeout vs. free-tier cold starts

Render's free instances sleep after 15 minutes idle and take roughly 30 seconds
to wake. A frontend timeout longer than the wake-up time would let a request
hang for a minute and a half before failing.

`VITE_API_TIMEOUT_MS=30000` inverts that deliberately: the first request after a
lull fails fast, the client retries, and the retry lands on a warm instance. A
visible error beats a spinner that never resolves.

---

## 3. Verify

```powershell
$api = "https://netguard-ai.onrender.com"

# 1. Liveness. Must answer without a token and without touching a database --
#    this is what Render's health check polls.
curl "$api/api/v1/healthz"

# 2. Readiness. Reports what is actually degraded, including Postgres.
curl "$api/api/v1/readyz"               # -> {"postgres": {"available": true, ...}, ...}

# 3. Demo accounts must be off.
curl "$api/api/v1/auth/auth-status"      # -> {"demo_accounts": false, ...}

# 4. CORS preflight from the Pages origin. The allow-origin header must come back.
curl -i -X OPTIONS "$api/api/v1/dashboard" `
  -H "Origin: https://gowthambaragada-a11y.github.io" `
  -H "Access-Control-Request-Method: GET" `
  -H "Access-Control-Request-Headers: authorization"

# 5. Log in, then use the token.
$login = Invoke-RestMethod "$api/api/v1/auth/login" -Method Post `
  -Body (@{ username = "operator"; password = $env:OPERATOR_PASSWORD } | ConvertTo-Json)
$headers = @{ Authorization = "Bearer $($login.access_token)" }

curl "$api/api/v1/dashboard" -Headers $headers
```

Then upload each file in `backend/samples/configs/` through the UI and confirm
findings appear on `/findings` and `/devices`, and proposals on `/remediation`.
Cisco IOS, Fortinet FortiOS, Juniper Junos and Palo Alto PAN-OS are covered, so
all four detectors should produce output.

Checklist before calling it done:

- [ ] `/readyz` reports `postgres.available: true`
- [ ] `admin/admin123!` returns `401`
- [ ] The Pages origin appears in `access-control-allow-origin`
- [ ] An upload survives a page reload (it came from Postgres, not the snapshot)
- [ ] A signed-out reload shows the login form, not the sidebar

---

## Local development

Two terminals, with the database optional.

```powershell
# terminal 1
cd backend
pip install -e ".[dev]"
uvicorn app.main:app --reload

# terminal 2
cd frontend
npm install
npm run dev
```

Leave `frontend/.env.local` with `VITE_API_BASE_URL=` empty. The Vite dev server
proxies `/api` to `http://localhost:8000` (see `frontend/vite.config.ts`), so
there is no CORS to configure locally.

Without Postgres the API still serves `/healthz` and `/analyze`, and the built-in
demo accounts work — that is the fastest way to evaluate the parsing and rule
stages. `/dashboard`, `/findings`, `/devices` and `/remediations` return `503`
with an explanation rather than an empty fleet, which is deliberate: "nothing
persisted" and "nothing found" are different answers and the API should not
conflate them.