# Honey Cloud - Project Execution Plan

This report outlines the plan to fulfill the goals for the Honey Cloud project, transforming it into a "masterpiece" final year project.

## 1. Project Objectives

The primary objectives are to create:
1.  **A working monitoring dashboard** accessible on a local laptop.
2.  **A realistic fake login page** (honeypot) accessible on multiple devices to capture simulated attacks (passwords, SQL injection, etc.).
3.  **Real-time data visualization** on the dashboard.
4.  **A containerized setup** ready for free cloud deployment.
5.  **A highly professional codebase** with modern practices.

---

## 2. Current State vs. Proposed Plan

| Feature | Current State | Proposed Plan |
| :--- | :--- | :--- |
| **Dashboard** | Exists (`dashboard.html`), uses WebSockets. | Verify functionality, ensure seamless connection. |
| **HTTP Honeypot** | Returns JSON `{"status": "ok"}` on port 8080. | Upgrade to serve a **visual fake login page** (HTML). |
| **Attack Capture** | Logs basic requests. | Add form handling to capture credentials and attack payloads (SQLi). |
| **Deployment** | Dockerfiles exist. | Verify and optimize for cloud deployment. |
| **Code Quality** | Good, but uses synchronous `requests`. | Replace with `httpx` for better async performance. |

---

## 3. Detailed Execution Phases

### Phase 1: Upgrade HTTP Honeypot (The Fake Login Page)
-   **Action**: Modify `backend/app/honeypots/http_honeypot.py`.
-   **Details**:
    -   Create a beautiful, convincing HTML login page (as a string or served file).
    -   Serve this page on `GET /` and `GET /login` on port 8080.
    -   Implement a `POST /login` handler to extract form data.
    -   Log extracted data as attack events with appropriate severity (e.g., SQLi patterns as CRITICAL).
-   **Goal**: Allow devices on the same network to access the page and simulate attacks.

### Phase 2: Verify Real-Time Dashboard
-   **Action**: Test `dashboard.html` with the upgraded honeypot.
-   **Details**:
    -   Ensure WebSocket connection is established correctly.
    -   Verify that attacks performed on the fake login page appear instantly on the dashboard.

### Phase 3: Code Optimization & Cleanup
-   **Action**: Apply recommended improvements.
-   **Details**:
    -   Replace `requests` with `httpx` in `geo_service.py`, `alert_service.py`, and `base.py`.
    -   Remove unused `pyyaml` dependency.
    -   Update misleading docstrings.

### Phase 4: Docker & Cloud Readiness
-   **Action**: Test and document Docker setup.
-   **Details**:
    -   Ensure `docker compose up` works out of the box.
    -   Provide a guide for deploying to free services like Render or Railway.

---

## 4. Conclusion

By executing this plan, the project will not only meet the required goals but will also demonstrate advanced skills in full-stack development, network security simulation, and asynchronous programming, making it a standout submission.
