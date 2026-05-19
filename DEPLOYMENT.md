# HoneyCloud Deployment Guide

HoneyCloud is fully containerized and ready to be deployed to the cloud. This guide provides instructions for deploying to free cloud services like **Render** or **Railway**.

## General Prerequisites

1. Ensure your `.env` file is configured correctly. For cloud deployments, you will set these environment variables in the cloud provider's dashboard instead of using a `.env` file.
2. Ensure you have a strong `SECRET_KEY`.

---

## Option 1: Deploying to Railway (Recommended)

Railway is excellent for full-stack Docker projects because it can natively parse your `docker-compose.yml` file.

1. **Create an Account**: Sign up at [railway.app](https://railway.app).
2. **New Project**: Click "New Project" and select "Deploy from GitHub repo".
3. **Select Repository**: Choose your HoneyCloud repository.
4. **Environment Variables**: Once the project is created, go to the "Variables" tab and add all the required variables from your `.env` file (e.g., `SECRET_KEY`, `DATABASE_URL`).
   * *Note: Railway will automatically provision a PostgreSQL database if you add a Database service, and you can map its connection string to `DATABASE_URL`.*
5. **Deploy**: Railway will automatically detect the Dockerfiles and build your backend and frontend.
6. **Networking**: Ensure you expose port `80` for the frontend, `8000` for the backend, and `8080` for the HTTP Honeypot. Railway will assign public domains. You may need to update the `ALLOWED_ORIGINS` variable to include your new frontend domain.

---

## Option 2: Deploying to Render

Render requires you to deploy the backend, frontend, and database as separate Web Services.

### 1. Database
* Create a new "PostgreSQL" instance on Render.
* Copy the "Internal Database URL".

### 2. Backend (FastAPI + Honeypots)
* Create a new "Web Service".
* Connect your GitHub repo.
* Set the Root Directory to `backend`.
* Choose the "Docker" environment.
* In the Advanced settings, add your Environment Variables, including the `DATABASE_URL` you copied from step 1, and your `SECRET_KEY`.
* Expose the necessary ports (Render only exposes one port per Web Service publicly, so you will need to map `8000` for the API and `8080` for the honeypot, which might require a custom `render.yaml` blueprint or deploying the honeypot as a separate Background Worker/Web Service).

### 3. Frontend (Dashboard)
* Create a new "Static Site" (or Web Service if using the Nginx Dockerfile).
* Connect your GitHub repo.
* Set the Root Directory to `frontend`.
* If using Static Site, Render will serve the files. Just ensure the `API` constant in `dashboard.html` points to your deployed Backend URL instead of `/api/v1`.

---

## Local Docker Deployment (Testing)

Before pushing to the cloud, ensure it runs locally:

```bash
docker compose up --build -d
```

* **Dashboard**: `http://localhost:80`
* **API Docs**: `http://localhost:8000/docs`
* **Fake Login Honeypot**: `http://localhost:8080`
