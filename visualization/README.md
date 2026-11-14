# Specula dashboard

The React dashboard in this directory shows case status, findings, analyst review and live graph updates. Its backend is the FastAPI visualizer on port 8300. Protected HTTP requests carry the current Supabase session; the WebSocket authenticates before case updates are delivered.

For the verified local stack, start with [project status](../docs/PROJECT_STATUS.md) and [local remediation](../docs/local_remediation.md). The backend needs its ignored authorization policy and the shared Docker checkpoint volume. A user can operate cases they own or have been assigned. Legacy cases need trusted owner/member assignment before browser access.

From the repository root in PowerShell, after the existing dependencies and synthetic fixture case are present:

```powershell
.\venv\Scripts\python.exe scripts/configure_local_runtime.py
.\venv\Scripts\python.exe -m uvicorn scripts.local_boot_api:app --host 127.0.0.1 --port 8400
```

In another terminal, run `npm run dev --prefix visualization` and open the local URL it prints. Sign in, then open System Boot. The initialization page calls the loopback boot controller, which runs `docker compose down` and `docker compose up -d --no-build --pull never` for this repository. It removes and recreates the project's containers and network, preserving named and bind-mounted data volumes. The controller checks that all required images are local before teardown. Keep its terminal open while using the page.

The loopback controller accepts requests only from the local dashboard origin and uses a custom request header. It reads the ignored local validation credential from `data/private` itself when checking the deployed visualizer's readiness, so the browser does not need the token. Rerun `scripts/configure_local_runtime.py` if that credential expires. This controller is for local development; the case APIs still check server-verified identity, ownership and membership.

The Live Investigation page now creates a fresh local case from Windows Event Log channels. Start and end dates are optional as a pair; when supplied, they bound the Windows log extraction. Max Events limits each channel, and Excluded Ports removes matching normalized network events from case analysis while retaining raw preservation. The host controller creates case-linked OCSF Event nodes and invokes the visualizer API with its private local validation credential; the browser polls the job and can submit local HITL review. This local workflow does not fetch GCP logs or run the legacy ingestion runner's database reset. The local Compose override persists Neo4j, Quickwit, Kafka and Redis data across container recreation. Data in containers removed before those volumes were configured is not automatically restored into them.

`npm run build` creates the ignored `dist/` directory. It can be regenerated; it is not source. The prior dashboard README described simulated traces and anonymous backend access and has been superseded by the current runtime behavior above.
