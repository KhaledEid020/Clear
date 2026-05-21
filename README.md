# Clear: AI Fine-Tuning Agent for SIEM Alerts

Clear is an AI-driven detection engineering workflow focused on reducing noisy false-positive SIEM alerts, starting with Wazuh.

This repository packages the Clear workflow as a full local stack with:
- Backend API (`clear-api`) powered by Agno AgentOS
- PostgreSQL + pgvector (`clear-db`) for runtime/session data
- Frontend dashboard (`clear-frontend`) for configuration and workflow execution

## Overview

SOC teams often spend weeks or months manually tuning noisy detection rules. Clear shortens that cycle by orchestrating specialized agents that investigate a rule, gather context, and propose safer tuning actions.

Clear’s investigation model uses three context layers:
- Internal Behavior: how a rule behaves in your own environment
- Global Context: external intelligence from docs, community signals, and threat reporting
- Current Posture: your already deployed rules and dependencies

The workflow is human-in-the-loop by design. You approve recommendations before execution, and command-level operations are gated before changes are applied.

Reference article: https://ai.keid.workers.dev/posts/clear-ai-fine-tuning-agent

## Key Workflow Agents

- `ossecrules_agent` (Retrieval): reads existing Wazuh rules and relationships
- `threathunting_agent` (Rule Hunting): investigates alert patterns in SIEM data
- `websearch_agent` (Global Context): enriches analysis with external signal
- `reporting_agent` (Final Report): consolidates findings into recommendation options
- `detectionengineer_agent` (Execution): applies approved tuning actions with Wazuh-specific skill guidance

Workflow ID: `wazuh-fine-tuning-pipeline`

## Repository Layout

- `app/main.py`: AgentOS application entrypoint
- `agents/wazuh_pipeline.py`: multi-agent workflow definition
- `mcp_servers/ossec_mcp_server.py`: OSSEC/Wazuh rule retrieval MCP server
- `mcp_servers/wazuh_ssh_exec_mcp_server.py`: Wazuh manager SSH execution MCP server
- `skills/wazuh-detection-engineering/SKILL.md`: detection-engineering domain skill
- `frontend/`: web dashboard and backend bridge endpoints
- `compose.yaml`: full stack orchestration

## Prerequisites

## Local runtime requirements
- Docker Engine 24+ (or equivalent recent version)
- Docker Compose v2 (`docker compose`)
- Linux/macOS/WSL environment with network access to your Wazuh infrastructure

## External platform requirements
- A running Wazuh deployment (manager + indexer/OpenSearch)
- SSH access to Wazuh manager for approved rule operations
- AI provider API key (OpenAI, OpenRouter, or Anthropic)
- Web-search provider API key used by your configured web context agent

## Environment Configuration

1. Create local env file:

```bash
cp example.env .env
```

2. Infrastructure variables in `.env`:
- `DB_USER`, `DB_PASS`, `DB_DATABASE`
- `APP_DB_SCHEMA`
- `FRONTEND_PORT`
- `AGENT_WORKFLOW_ID`

3. Runtime credentials are user-scoped and persisted by the app flow in PostgreSQL:
- SIEM indexer host/user/password
- Wazuh manager SSH host/user/port and auth material
- AI and web provider selection, model, and API keys

## Run Locally (Docker Compose)

```bash
docker compose up -d --build
```

Services:
- Frontend: `http://localhost:3000`
- API docs: `http://localhost:8000/docs`

Useful operations:

```bash
# Tail API logs
docker compose logs -f agentos-api

# Stop stack
docker compose down
```

## How Deployment Works

When deployed with `compose.yaml`, Clear runs as three connected services on one network:

1. `clear-db` (PostgreSQL + pgvector): stores workflow state, sessions, and user runtime configuration.
2. `clear-api` (AgentOS/FastAPI): hosts agent workflows and orchestrates MCP + skill-driven execution.
3. `clear-frontend` (Node app): provides operator UI and feeds user-specific runtime settings to the backend.

Execution pattern:
- Operator chooses/configures workflow from frontend
- Backend resolves user-scoped runtime settings from DB
- Agents run sequence: hunting, enrichment, retrieval, reporting
- Human approval gate is enforced before engineering actions
- Detection engineer step executes approved changes via controlled tooling

## Production Deployment Notes

For production hardening, deploy with these controls:
- Use a managed PostgreSQL instance and persistent volume strategy
- Put frontend/API behind TLS reverse proxy (Nginx, Traefik, or cloud LB)
- Restrict API and DB network exposure (private subnet/security groups)
- Store API keys and SSH secrets in a secrets manager (not plaintext env files)
- Enable centralized logs/metrics and workflow audit retention
- Pin container image tags and apply CI vulnerability scanning

## Current Scope

- Supported SIEM: Wazuh
- Roadmap (planned in article): ELK, Splunk, IBM QRadar

## License

Apache-2.0
