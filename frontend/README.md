# Frontend Dashboard

Node.js frontend service for the Wazuh fine-tuning stack.

## Run (recommended)

Run from repository root with one command:

```bash
docker compose up -d --build
```

Open: `http://localhost:3000`

## Behavior

- Loads rule list from `GET /api/rules`.
- `/api/rules` queries OpenSearch and returns top firing Wazuh rules (last 24h, top 10 by default).
- On `Fine Tune Now`, sends `POST /api/fine-tune`.
- Polls run state from `GET /api/fine-tune/:runId`.
- If backend pauses for HITL, it shows Approve/Reject and sends `POST /api/fine-tune/:runId/confirm`.

## Integration

Environment is mapped from root `.env` through root `compose.yaml`.
Defaults use internal Docker service names:
- DB: `agentos-db:5432`
- Backend API: `agentos-api:8000`
