# HoneyCloud Deployment Guide

HoneyCloud is a unified platform compiled into a single, high-performance **Rust** binary which statically hosts the dashboard UI assets and spins up asynchronous background honeypot listeners. It is fully containerized and ready for cloud deployment.

---

## Deployment Architectures

You can host HoneyCloud using two main approaches:
1. **Virtual Private Server (VPS) - Recommended**: Full port range support. Standard cloud providers (DigitalOcean, Linode, AWS EC2, GCP Compute Engine, Hetzner) let you bind directly to the honeypot ports (22, 21, 80, 23, 25, 3389).
2. **PaaS (Railway / Render)**: Managed deployments that use Docker. PaaS services typically route HTTP traffic on port 80/443 to a single container port, meaning the raw TCP honeypot sockets (SSH, FTP, etc.) may not be accessible publicly unless using raw TCP proxy services.

---

## Option 1: VPS Deployment (Recommended)

To run HoneyCloud with all honeypot services fully accessible, a VPS is highly recommended:

1. **Provision VPS**: Deploy a fresh instance of Debian/Ubuntu.
2. **Install Docker**: Install Docker Engine and Docker Compose.
3. **Clone Repo**:
   ```bash
   git clone https://github.com/your-org/honeycloud.git
   cd honeycloud
   ```
4. **Configure Firewall**: Ensure ports `80`, `8000`, `8080`, `2121`, `2222`, `2323`, `2525`, and `3389` are open on your host firewall.
   * *Security Warning:* If your VPS has SSH running on the default port `22`, make sure to change the host's SSH port (e.g., to `22022`) in `/etc/ssh/sshd_config` before starting the SSH Honeypot, as the honeypot needs to run on port `22` or `2222`.
5. **Run Stack**:
   ```bash
   cp .env.example .env
   # Edit .env and supply a secure SECRET_KEY and DB password
   docker compose up --build -d
   ```

---

## Option 2: Deploying to Railway

Railway natively parses `docker-compose.yml` to provision databases and services.

1. **Sign up**: Create an account on [railway.app](https://railway.app).
2. **Deploy Repository**: Click "New Project" -> "Deploy from GitHub repo" -> Choose your repository.
3. **Set Environment Variables**: In your Railway dashboard, add:
   - `SECRET_KEY` (Generate a secure hex key)
   - `JWT_EXPIRATION_MINUTES=60`
   - `ENVIRONMENT=production`
   - `DEBUG=false`
4. **Database Association**: Railway will automatically provision a PostgreSQL database service if you add a Database service, and output a connection URL. You can map this directly to your backend's `DATABASE_URL` environment variable.
5. **Port Binding**: Ensure Railway routes traffic to container port `8000` (which hosts both REST API/WebSockets and the static dashboard web assets).

---

## Option 3: Deploying to Render

Render builds from the workspace Dockerfile.

1. **Deploy Postgres**: Create a new PostgreSQL instance on Render. Copy the **Internal Database URL**.
2. **Deploy Web Service**:
   - Create a new **Web Service**.
   - Root Directory: `backend-rust`
   - Environment: `Docker`
   - Build Context: `./backend-rust` (Render will build from `backend-rust/Dockerfile`).
3. **Configure Environment variables**:
   - `DATABASE_URL`: (Paste the database URL from Step 1, changing the prefix to `postgres://` format if it contains dynamic SQLAlchemy markers).
   - `SECRET_KEY`: (Secure hex string).
   - `ENVIRONMENT`: `production`
4. **Accessing the Dashboard**: Render will provide a public URL like `https://honeycloud.onrender.com`. All REST services and the analytics UI will load directly from this single domain.

---

## Local Testing Deployment

To run a production-ready container stack locally:

```bash
docker compose up --build -d
```

Verify that the local ports bind correctly:
* **Dashboard / API Router**: `http://localhost/` (redirects to `login.html`)
* **REST API Endpoints**: `http://localhost:8000/api/v1/`
* **HTTP Web Honeypot**: `http://localhost:8080/`
* **SSH Honeypot**: `localhost:2222`
* **FTP Honeypot**: `localhost:2121`
* **Telnet Honeypot**: `localhost:2323`
* **SMTP Honeypot**: `localhost:2525`
* **RDP Honeypot**: `localhost:3389`
