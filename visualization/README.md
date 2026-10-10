# Specula dashboard

The React dashboard in this directory shows case status, findings, analyst review and live graph updates. Its backend is the FastAPI visualizer on port 8300. Protected HTTP requests carry the current Supabase session; the WebSocket authenticates before case updates are delivered.

For the verified local stack, start with [project status](../docs/PROJECT_STATUS.md) and [local remediation](../docs/local_remediation.md). The backend needs its ignored authorization policy and the shared Docker checkpoint volume. A user can operate cases they own or have been assigned. Legacy cases need trusted owner/member assignment before browser access.

From the repository root in PowerShell, after the existing dependencies and synthetic fixture case are present:

```powershell
.\venv\Scripts\python.exe scripts/configure_local_runtime.py
docker compose -f docker-compose.yml -f docker-compose.local.yml up -d --no-build hitl-api visualizer-api
cd visualization
npm run dev -- --host 127.0.0.1
```

Open `http://127.0.0.1:5173`, sign in and select an accessible case. The setup script's local validation credential is restricted to the previously created synthetic fixture case; it is for API checks, not browser sign-in. The backend checks actual case ownership or membership for normal Supabase users.

`npm run build` creates the ignored `dist/` directory. It can be regenerated; it is not source. The prior dashboard README described simulated traces and anonymous backend access and has been superseded by the current runtime behavior above.
