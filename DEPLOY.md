# Scanner API — production deploy (MIRA integration)

Deploy this service to **`https://api.syntrix.solutions`** so MIRA can sync findings, mark remediations resolved, and download/update the desktop app.

## Prerequisites

- Render (or equivalent) web service pointing at `scanner/` with `uvicorn app.main:app`
- **Persistent disk** mounted at `/data` (SQLite + MIRA release artifacts)
- Database / storage backing `app/storage.py` (same as existing Syntrix scanner)
- Auth tokens issued by Syntrix login flow (MIRA stores encrypted bearer tokens)

## Endpoints MIRA depends on

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/v1/health` | Connection test + plan tier |
| GET | `/api/v1/findings` | Open findings sync |
| POST | `/api/v1/scans` | Queue a scan (MIRA monitor automation) |
| GET | `/api/v1/scans/{scan_id}` | Poll scan status |
| POST | `/api/v1/findings/{id}/resolved` | Close finding after validated remediation (`evidence_scan_id` required) |
| POST | `/api/v1/findings/{id}/remediation_failed` | Record failed remediation attempt |

### Desktop download + auto-update (entitlement-gated)

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| GET | `/api/mira/desktop/status` | public | Feed readiness (no filenames dump) |
| GET | `/api/mira/desktop/entitlement` | JWT | `{ entitled, reason }` for marketing UI |
| GET | `/api/mira/desktop/download` | JWT + **admin \| paid** | Stream latest installer (`?platform=mac\|win`) |
| GET | `/api/mira/desktop/releases/{file}` | JWT + **admin \| paid** | electron-updater generic feed (Mac + Windows) |

**Who is entitled**

- Sole admin email (`SYNTRIX_SOLE_ADMIN_EMAIL`, default `chandler@syntrix.solutions`)
- Stripe subscription `status` in `{active, trialing}`

Gate is controlled by `SYNTRIX_MIRA_DESKTOP_GATE` (default **true**), independent of `SYNTRIX_BILLING_REQUIRED`.

**Where to upload artifacts**

Set `MIRA_RELEASES_DIR` (default `/data/mira-releases` on Render when `/data` exists):

```text
/data/mira-releases/
  latest-mac.yml              # electron-builder (macOS)
  MIRA-<version>-mac.zip      # required for macOS auto-update
  MIRA-<version>.dmg          # website Download (macOS)
  latest.yml                  # electron-builder (Windows)
  MIRA-<version>-setup.exe    # website Download + Windows auto-update
  MIRA-<version>-setup.exe.blockmap   # optional
  MIRA-<version>-portable.exe         # optional
```

```bash
# From your Mac after npm run build:dmg
scp dist/electron/latest-mac.yml \
    dist/electron/MIRA-*-mac.zip \
    dist/electron/*.dmg \
    render-shell:/data/mira-releases/

# From Windows after npm run build:win
scp dist/electron/latest.yml \
    dist/electron/MIRA-*-setup.exe \
    dist/electron/MIRA-*-setup.exe.blockmap \
    dist/electron/MIRA-*-portable.exe \
    render-shell:/data/mira-releases/
```

Create the directory once on the Render disk (`mkdir -p /data/mira-releases`).

**Optional DNS:** point `releases.syntrix.solutions/mira` →
`https://api.syntrix.solutions/api/mira/desktop/releases` (Cloudflare reverse proxy or redirect)
so the historical bake-time URL still works. Canonical feed is the API path above.

Verify locally:

```bash
cd scanner
python -m pytest tests/test_integrations_v1.py tests/test_mira_desktop.py -q
```

Smoke against production (replace `$TOKEN`):

```bash
curl -sS -H "Authorization: Bearer $TOKEN" https://api.syntrix.solutions/api/v1/health
curl -sS -H "Authorization: Bearer $TOKEN" "https://api.syntrix.solutions/api/v1/findings?status=open&limit=5"
curl -sS https://api.syntrix.solutions/api/mira/desktop/status
curl -sS -H "Authorization: Bearer $TOKEN" \
  -OJ "https://api.syntrix.solutions/api/mira/desktop/download?platform=mac"
curl -sS -H "Authorization: Bearer $TOKEN" \
  -OJ "https://api.syntrix.solutions/api/mira/desktop/download?platform=win"
```

## Deploy steps (Render)

1. Merge scanner changes to the branch Render tracks (usually `main`).
2. Confirm **Root directory** is `scanner` and start command runs `app.main:app`.
3. Confirm a **Disk** is mounted at `/data` (SQLite + `mira-releases`).
4. **Manual deploy** or push to trigger auto-deploy.
5. After deploy, upload release artifacts into `MIRA_RELEASES_DIR`.
6. Run `../scripts/dry-run-mira-syntrix.sh` from repo root with valid credentials.
7. In MIRA → **Settings**, sign in and **Test** connection; **Posture** should show monitor cards after first sync.
8. Marketing: open https://syntrix.solutions/download-mira.html while signed in as admin or subscriber.

## Rollback

Redeploy the previous Render release if `/api/v1/findings/{id}/resolved` returns 404 — MIRA remediation will still sync findings but cannot close them in Syntrix until the route is live.

## Do not change

- Netlify landing rewrites in `landing/netlify.toml` (CoverIQ / ForgEd / marketing paths)
- Existing scanner routes used by the marketing scan UI
