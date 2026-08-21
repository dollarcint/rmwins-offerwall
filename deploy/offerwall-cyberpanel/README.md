# Isolated Offerwall deployment

This directory deploys the current RM Wins application as an independent
Offerwall environment. It does not reuse or modify the production RM Wins
databases, Redis instances, app directory, runtime directory, or systemd units.

| Component | Isolated target |
| --- | --- |
| Source | `/home/www.rmwinsights.com/offerwall` |
| PostgreSQL | `rmwins_offerwall_prod` / `rmwins_offerwall_vault` with dedicated roles |
| Celery Redis | `127.0.0.1:6384`, persistent |
| Cache Redis | `127.0.0.1:6385`, rebuildable |
| Django/Gunicorn | `127.0.0.1:8095` |
| React | `127.0.0.1:8096` |
| Public host | `offerwall.rmwinsights.com` |
| Services | `rmwins-offerwall-supervisor.service`, `rmwins-offerwall-frontend.service` |

All provider credentials are blank and scheduled jobs are disabled on the
first deploy. Add integrations only inside the Offerwall admin after each
feature is deliberately enabled.

## Build and snapshot

```bash
cd frontend
VITE_DASHBOARD_URL=https://offerwall.rmwinsights.com npm ci
VITE_DASHBOARD_URL=https://offerwall.rmwinsights.com npm run build
```

Place the generated build at snapshot-root `dist/`. Exclude Git metadata,
environments, virtualenvs, dependencies, caches, SQLite files and private keys.
Install the wrapper and uploaded archive behind the root-owned boundary:

```bash
install -d -m 0750 -o root -g root /var/lib/rmwins-offerwall-deploy
install -m 0700 -o root -g root deploy-private-snapshot.sh \
  /var/lib/rmwins-offerwall-deploy/deploy-private-snapshot.sh
chown root:root /var/tmp/rmwins-offerwall-snapshot.tar.gz
chmod 0600 /var/tmp/rmwins-offerwall-snapshot.tar.gz
SNAPSHOT_ARCHIVE=/var/tmp/rmwins-offerwall-snapshot.tar.gz \
  /var/lib/rmwins-offerwall-deploy/deploy-private-snapshot.sh
```

The wrapper backs up only the Offerwall app/environment/databases, provisions
dedicated least-privilege PostgreSQL roles, migrates both databases, builds
static files, bootstraps `offerwall_admin` privately, installs only the two
Offerwall units, and verifies every private listener. Existing RM Wins and
Alessar service states are checked before and after deployment.

## Public routing

1. Add Namecheap DNS A record `offerwall -> 82.29.166.173`.
2. Install `nginx-offerwall-http.conf`, run `nginx -t`, then reload Nginx.
3. Issue a separate certificate for `offerwall.rmwinsights.com` using the
   existing `/var/www/rmwins-acme` webroot.
4. Install `nginx-offerwall-https.conf`, run `nginx -t`, reload, and only
   then enable Django SSL redirect/HSTS in the protected Offerwall environment.

The public root is the Offerwall landing page. Respondents enter inventory through
signed publisher wall links, and publishers exchange a one-time signed link for a
private wallet session. React serves only the staff login surface; Offerwall pages,
survey callbacks, APIs, admin and workspace pages are served by the isolated Django
backend. The historical `/setup/` route hands off to Django Admin.
