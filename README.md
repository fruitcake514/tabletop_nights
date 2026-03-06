# 🎲 Tabletop Nights

A self-hosted board game night planner. Track your collection, schedule game nights, share a join code with friends — no accounts needed for guests.

---

## Features

- **Collection** — search BoardGameGeek, pull box art automatically, rate 1–10
- **Game Nights** — plan events, share a 6-character code, guests RSVP and rate games
- **Guest view** — no account needed; guests search BGG when adding their game, rate and edit ratings
- **Admin** — admin creates/deletes user accounts, resets passwords
- **Secure** — scrypt password hashing, rate-limited login, signed JWT tokens

---

## Deployment

### Option A — Synology NAS via GitHub Container Registry (no code on NAS)

You only need one file on your NAS: **`docker-compose.nas.yml`**

**Step 1 — Build & push the image** (once, on any machine with Docker)

```bash
git clone https://github.com/YOUR_USERNAME/YOUR_REPO.git
cd YOUR_REPO

docker build -t ghcr.io/YOUR_USERNAME/YOUR_REPO:latest .

# Login to GitHub Container Registry
# Create a token at: github.com/settings/tokens (scope: write:packages)
echo YOUR_TOKEN | docker login ghcr.io -u YOUR_USERNAME --password-stdin

docker push ghcr.io/YOUR_USERNAME/YOUR_REPO:latest
```

**Step 2 — On the Synology NAS**

Copy `docker-compose.nas.yml` to the NAS. Edit the four `CHANGE_ME` values, then:

```bash
# Pull image and start
docker compose -f docker-compose.nas.yml pull
docker compose -f docker-compose.nas.yml up -d

# View logs
docker logs -f tabletop-nights
```

**To update after pushing new image:**
```bash
docker compose -f docker-compose.nas.yml pull
docker compose -f docker-compose.nas.yml up -d
```

---

### Option B — Build on the NAS (Git + Docker available)

```bash
git clone https://github.com/YOUR_USERNAME/YOUR_REPO.git tabletop-nights
cd tabletop-nights
docker compose up -d --build
```

Data stored in `./data/` relative to the compose file.

**To update:**
```bash
git pull
docker compose up -d --build
```

---

### Option C — Local dev

```bash
git clone https://github.com/YOUR_USERNAME/YOUR_REPO.git
cd YOUR_REPO
docker compose up --build
```

Visit http://localhost:5000

---

## Configuration

| Variable | Required | Default | Description |
|---|---|---|---|
| `SECRET_KEY` | **Yes** | random | JWT signing key. Generate: `python3 -c "import secrets; print(secrets.token_hex(32))"` |
| `ADMIN_USERNAME` | No | `admin` | Admin account username |
| `ADMIN_PASSWORD` | No | `changeme` | **Change this before running!** |
| `WORKERS` | No | `2` | Gunicorn worker processes |
| `DATABASE_PATH` | No | `/data/tabletop.db` | SQLite path inside container |

---

## Volume & Port mapping

**Data volume** — map `/data` to a persistent NAS path:

```yaml
volumes:
  - /volume1/docker/tabletop-nights:/data   # Synology DSM
  - /opt/tabletop:/data                     # Linux
  - ./data:/data                            # local relative
```

**Port** — change the left number to use a different host port:

```yaml
ports:
  - "8080:5000"   # → http://NAS_IP:8080
  - "5000:5000"   # → http://NAS_IP:5000
```

---

## Making the ghcr.io image public

So your NAS can pull without a token:

1. `github.com → YOUR_REPO → Packages → tabletop-nights`
2. Package settings → Change visibility → **Public**

---

## First login

Admin account is auto-created on first boot from `ADMIN_USERNAME`/`ADMIN_PASSWORD`.
Use the **Admin** tab to create accounts for other users.
Guests need no account — just share the 6-character event code.
