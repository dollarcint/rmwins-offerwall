# RM Wins Offerwall

Independent publisher offerwall built from the RM Wins survey platform. It keeps the existing
survey-provider lifecycle while adding signed publisher sessions, eligible inventory, immutable
click attribution, verified-only rewards, publisher wallets, withdrawal requests and signed
server-to-server postbacks.

Production: `https://offerwall.rmwinsights.com`

## Applications

- `backend/` — Django admin, survey inventory, provider callbacks and the Offerwall application.
- `frontend/` — React/Vite staff login surface.
- `deploy/offerwall-cyberpanel/` — isolated VPS runtime assets for this repository only.

The production Offerwall uses dedicated PostgreSQL databases, Redis instances and loopback
application ports. It does not share application state with the main RM Wins deployment.

## Local development

```powershell
cd backend
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python manage.py migrate
python manage.py runserver
```

```powershell
cd frontend
npm ci
npm run dev
```

Copy `backend/.env.example` to `backend/.env` for local-only values. Never commit real provider,
publisher, encryption or database credentials.

## Publisher setup

1. Open Django Admin and create an **Offerwall publisher**.
2. Copy the one-time signing secret and inventory API key shown after save.
3. Keep all live eligible surveys assigned by default. Add an Offer Override only to exclude,
   feature, rename or change the payout percentage for a particular survey.
4. Generate a test link from the publisher admin page or with:

```powershell
python manage.py generate_offerwall_link publisher-slug external-user-id
python manage.py generate_publisher_portal_link publisher-slug
```

The wall only credits a completion after the existing survey callback flow marks the attempt as
verified. A publisher/user/survey combination can receive one credit. Subsequent saves and callback
retries are idempotent.

The same publisher admin page generates a one-time signed dashboard link. The publisher can view
its available/reserved/paid balance, reward ledger and withdrawal history, then submit a payout
request. Staff approve, process, reject or mark payouts paid from Django Admin; a payment reference
is mandatory for the paid transition.

See [Publisher integration](docs/OFFERWALL_INTEGRATION.md) for the signed URL, inventory API and
postback contract.

## Validation

```powershell
cd backend
python manage.py test
python manage.py check --deploy
python manage.py makemigrations --check --dry-run

cd ..\frontend
npm ci
npm run typecheck
npm run lint
npm run build
npm audit --omit=dev
```

Production releases are immutable snapshots created from an exact Git commit. Do not `git pull`
inside the VPS application directory; use the protected Offerwall deployment wrapper and verify
the public site after migration and service restart.
