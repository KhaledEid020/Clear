import os
import sys
import hashlib
import re
import textwrap
from dataclasses import dataclass
from pathlib import Path
from typing import AsyncIterator, Union

import psycopg
from agno.agent import Agent
from agno.models.openai import OpenAIResponses
from agno.models.openrouter import OpenRouter
from agno.run.workflow import WorkflowRunOutputEvent
from agno.skills import LocalSkills, Skills
from agno.tools.mcp import MCPTools, StreamableHTTPClientParams
from agno.workflow import OnReject, Step, StepInput, StepOutput, Workflow
from agno.workflow.types import UserInputField

from db import get_app_user_setup, get_postgres_db

# MCPs & Skills paths
PROJECT_ROOT = Path(__file__).resolve().parent.parent
MCP_SERVERS_DIR = PROJECT_ROOT / "mcp_servers"
SKILLS_DIR = PROJECT_ROOT / "skills"
OSSEC_MCP_SERVER_PATH = MCP_SERVERS_DIR / "ossec_mcp_server.py"
SSH_MCP_SERVER_PATH = MCP_SERVERS_DIR / "wazuh_ssh_exec_mcp_server.py"
WAZUH_SKILL_PATH = SKILLS_DIR / "wazuh-detection-engineering"

LLM_MAX_TOKENS_RAW = os.getenv("LLM_MAX_TOKENS", "4096").strip()
LLM_MAX_TOKENS = int(LLM_MAX_TOKENS_RAW) if LLM_MAX_TOKENS_RAW else None

DEFAULT_OPENSEARCH_MCP_COMMAND = os.getenv("OPENSEARCH_MCP_COMMAND", "opensearch-mcp-server")
DEFAULT_VERIFY_CERTS = os.getenv("VERIFY_CERTS", "false")

DEFAULT_SSH_KEY_CACHE_DIR = os.getenv("SSH_KEY_CACHE_DIR", "/tmp/clear-user-ssh-keys")


@dataclass
class RuntimeSettings:
    user_id: str
    ai_provider: str
    ai_api_key: str
    web_provider: str
    web_api_key: str
    llm_model_id: str
    opensearch_mcp_command: str
    opensearch_hosts: str
    opensearch_username: str
    opensearch_password: str
    verify_certs: str
    remote_host: str
    remote_port: str
    remote_user: str
    remote_key_path: str
    remote_password: str


def _text(value: object) -> str:
    return str(value or "").strip()


def _runtime_user_id(step_input: StepInput) -> str:
    session = getattr(step_input, "workflow_session", None)
    return _text(getattr(session, "user_id", ""))


def _db_schema_name() -> str:
    raw = _text(os.getenv("APP_DB_SCHEMA", "ai")) or "ai"
    return raw if re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", raw) else "ai"


def _workflow_session_user_id(session_id: str | None) -> str:
    session_id_text = _text(session_id)
    if not session_id_text:
        return ""
    # Native agent steps use a derived agent session id. For runtime settings,
    # always resolve through the owning workflow session.
    workflow_session_id = session_id_text.split(":", 1)[0]

    schema = _db_schema_name()
    with psycopg.connect(
        host=os.getenv("DB_HOST", "localhost"),
        port=int(os.getenv("DB_PORT", "5432")),
        user=os.getenv("DB_USER", "ai"),
        password=os.getenv("DB_PASS", "ai"),
        dbname=os.getenv("DB_DATABASE", "ai"),
    ) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                f"""
                SELECT user_id
                FROM {schema}.agno_sessions
                WHERE session_id = %s
                  AND session_type = 'workflow'
                LIMIT 1
                """,
                (workflow_session_id,),
            )
            row = cursor.fetchone()
            return _text(row[0] if row else "")


def _write_user_ssh_key_file(user_id: str, key_text: str) -> str:
    normalized_key = str(key_text or "").replace("\r\n", "\n").replace("\r", "\n").strip()
    if "\\n" in normalized_key and "\n" not in normalized_key:
        normalized_key = normalized_key.replace("\\n", "\n")
    if "\n" not in normalized_key:
        inline_match = re.match(
            r"^(-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----)(.+)(-----END [A-Z0-9 ]*PRIVATE KEY-----)$",
            normalized_key,
        )
        if inline_match:
            header, body, footer = inline_match.groups()
            compact_body = "".join(body.split())
            wrapped_body = "\n".join(textwrap.wrap(compact_body, width=70))
            normalized_key = f"{header}\n{wrapped_body}\n{footer}"
    if not normalized_key:
        return ""

    safe_user = "".join(char if char.isalnum() else "_" for char in str(user_id or "user"))
    safe_user = safe_user[:64] or "user"
    key_hash = hashlib.sha256(normalized_key.encode("utf-8")).hexdigest()[:16]
    key_dir = Path(DEFAULT_SSH_KEY_CACHE_DIR)
    key_dir.mkdir(parents=True, exist_ok=True)
    key_path = key_dir / f"{safe_user}_{key_hash}.pem"
    key_path.write_text(normalized_key + "\n", encoding="utf-8")
    os.chmod(key_path, 0o600)
    return str(key_path)


def _load_runtime_settings_for_user_id(user_id: str) -> RuntimeSettings:
    user_id = _text(user_id)
    if not user_id:
        raise ValueError("Missing workflow user_id; refusing to fall back to .env runtime settings.")

    setup = get_app_user_setup(user_id)
    if not setup:
        raise ValueError(f"No DB runtime setup found for user_id '{user_id}'.")
    row = setup

    ai_provider = _text(row.get("ai_provider")).lower()
    ai_api_key = _text(row.get("ai_api_key"))
    selected_model_id = _text(row.get("ai_model_id"))
    web_provider = _text(row.get("web_provider")).lower()
    web_api_key = _text(row.get("web_api_key"))
    ssh_auth_value = _text(row.get("siem_ssh_auth"))
    ssh_auth_mode = _text(row.get("siem_ssh_auth_mode")).lower() or "password"
    opensearch_hosts = _text(row.get("siem_indexer_url"))
    opensearch_username = _text(row.get("siem_indexer_user"))
    opensearch_password = _text(row.get("siem_indexer_pass"))
    remote_host = _text(row.get("siem_manager_url"))
    remote_port = _text(row.get("siem_ssh_port"))
    remote_user = _text(row.get("siem_ssh_user"))

    if not ai_provider:
        raise ValueError("Missing DB ai_provider for this user.")
    if not selected_model_id:
        raise ValueError("Missing DB ai_model_id for this user.")
    if not ai_api_key:
        raise ValueError("Missing DB ai_api_key for this user.")
    if not web_provider:
        raise ValueError("Missing DB web_provider for this user.")
    if not web_api_key:
        raise ValueError("Missing DB web_api_key for this user.")
    if not opensearch_hosts or not opensearch_username or not opensearch_password:
        raise ValueError("Missing DB SIEM indexer configuration for this user.")
    if not remote_host or not remote_user or not remote_port:
        raise ValueError("Missing DB Wazuh manager SSH host/user/port for this user.")

    if ai_provider == "openrouter":
        model_id = selected_model_id
    elif ai_provider == "openai":
        model_id = selected_model_id
    elif ai_provider == "anthropic":
        model_id = selected_model_id
    else:
        raise ValueError(
            f"Unsupported ai_provider '{ai_provider}'. Supported: openai, openrouter, anthropic."
        )

    if ssh_auth_mode == "key_file" and ssh_auth_value:
        remote_key_path = _write_user_ssh_key_file(user_id, ssh_auth_value)
        remote_password = ""
    elif ssh_auth_mode == "password" and ssh_auth_value:
        remote_key_path = ""
        remote_password = ssh_auth_value
    else:
        raise ValueError("Missing DB SSH authentication value for this user.")

    return RuntimeSettings(
        user_id=user_id,
        ai_provider=ai_provider,
        ai_api_key=ai_api_key,
        web_provider=web_provider,
        web_api_key=web_api_key,
        llm_model_id=model_id,
        opensearch_mcp_command=DEFAULT_OPENSEARCH_MCP_COMMAND,
        opensearch_hosts=opensearch_hosts,
        opensearch_username=opensearch_username,
        opensearch_password=opensearch_password,
        verify_certs=DEFAULT_VERIFY_CERTS,
        remote_host=remote_host,
        remote_port=remote_port,
        remote_user=remote_user,
        remote_key_path=remote_key_path,
        remote_password=remote_password,
    )


def _load_runtime_settings(step_input: StepInput) -> RuntimeSettings:
    return _load_runtime_settings_for_user_id(_runtime_user_id(step_input))


def _ensure_anthropic_compatibility() -> None:
    """Patch missing symbols expected by agno's Claude adapter when anthropic==0.49.0 is installed."""
    try:
        import anthropic.lib.streaming._beta_types as beta_types
        import anthropic.types as anth_types
        from anthropic.lib.streaming._beta_types import (
            BetaContentBlockStopEvent,
            BetaMessageStopEvent,
        )
        from anthropic.types import CitationPageLocation

        if not hasattr(beta_types, "ParsedBetaContentBlockStopEvent"):
            beta_types.ParsedBetaContentBlockStopEvent = BetaContentBlockStopEvent
        if not hasattr(beta_types, "ParsedBetaMessageStopEvent"):
            beta_types.ParsedBetaMessageStopEvent = BetaMessageStopEvent
        if not hasattr(anth_types, "CitationsWebSearchResultLocation"):
            anth_types.CitationsWebSearchResultLocation = CitationPageLocation

        # agno's anthropic adapter may read these optional usage fields, but anthropic==0.49.0
        # Usage objects do not define them. Add safe accessors so adapter code does not crash.
        usage_type = getattr(anth_types, "Usage", None)
        if usage_type is not None and not hasattr(usage_type, "server_tool_use"):
            usage_type.server_tool_use = property(lambda self: None)
        if usage_type is not None and not hasattr(usage_type, "service_tier"):
            usage_type.service_tier = property(lambda self: None)
    except Exception:
        # Let agno raise its standard import/runtime errors if compatibility patching is not possible.
        return


def _build_model(settings: RuntimeSettings):
    if settings.ai_provider == "openrouter":
        if not settings.llm_model_id:
            raise ValueError("Missing model id for openrouter provider.")
        if not settings.ai_api_key:
            raise ValueError("Missing OpenRouter API key for openrouter provider.")
        return OpenRouter(
            id=settings.llm_model_id,
            api_key=settings.ai_api_key,
            max_tokens=LLM_MAX_TOKENS or 1024,
            reasoning_effort="none",
        )

    if settings.ai_provider == "openai":
        kwargs = {"api_key": settings.ai_api_key} if settings.ai_api_key else {}
        if settings.llm_model_id:
            kwargs["id"] = settings.llm_model_id
        if LLM_MAX_TOKENS:
            kwargs["max_output_tokens"] = LLM_MAX_TOKENS
        return OpenAIResponses(**kwargs)

    if settings.ai_provider == "anthropic":
        _ensure_anthropic_compatibility()
        from agno.models.anthropic import Claude

        kwargs = {"api_key": settings.ai_api_key} if settings.ai_api_key else {}
        if settings.llm_model_id:
            kwargs["id"] = settings.llm_model_id
        if LLM_MAX_TOKENS:
            kwargs["max_tokens"] = LLM_MAX_TOKENS
        return Claude(**kwargs)

    raise ValueError(
        f"Unsupported ai_provider '{settings.ai_provider}'. Supported: openai, openrouter, anthropic."
    )


def _runtime_env_overrides(settings: RuntimeSettings) -> dict[str, str]:
    return {
        "REMOTE_HOST": settings.remote_host,
        "REMOTE_PORT": settings.remote_port,
        "REMOTE_USER": settings.remote_user,
        "REMOTE_KEY_PATH": settings.remote_key_path,
        "REMOTE_PASSWORD": settings.remote_password,
        "OPENSEARCH_HOSTS": settings.opensearch_hosts,
        "OPENSEARCH_USERNAME": settings.opensearch_username,
        "OPENSEARCH_PASSWORD": settings.opensearch_password,
        "VERIFY_CERTS": settings.verify_certs,
    }


def _build_ossec_mcp(settings: RuntimeSettings) -> MCPTools:
    return MCPTools(
        command=f"{sys.executable} {OSSEC_MCP_SERVER_PATH}",
        timeout_seconds=120,
        env={**os.environ, **_runtime_env_overrides(settings)},
    )


def _build_websearch_mcp(settings: RuntimeSettings) -> MCPTools:
    if settings.web_provider not in ("", "tavily"):
        raise ValueError(
            f"Unsupported web_provider '{settings.web_provider}'. Supported: tavily."
        )
    if not settings.web_api_key:
        raise ValueError("Missing web API key for Tavily web provider.")

    return MCPTools(
        server_params=StreamableHTTPClientParams(
            url="https://mcp.tavily.com/mcp",
            headers={"Authorization": f"Bearer {settings.web_api_key}"},
        ),
        transport="streamable-http",
        timeout_seconds=120,
    )


def _build_opensearch_mcp(settings: RuntimeSettings) -> MCPTools:
    return MCPTools(
        command=settings.opensearch_mcp_command,
        timeout_seconds=120,
        env={**os.environ, **_runtime_env_overrides(settings)},
    )


def _build_ssh_mcp(settings: RuntimeSettings) -> MCPTools:
    return MCPTools(
        command=f"{sys.executable} {SSH_MCP_SERVER_PATH}",
        requires_confirmation_tools=["run_ssh_command"],
        timeout_seconds=120,
        env={**os.environ, **_runtime_env_overrides(settings)},
    )


agent_db = get_postgres_db()


THREAT_HUNTING_INSTRUCTIONS = """
You are a threat hunting analyst with Wazuh SIEM access.
Run advanced queries and do threat hunting for this rule ID and study the behavior of this rule id from all perspectives and all different logs so you can have more context about this rule.
Make just samll query like size 50 or something do not get all the data. we do not want huge chunks
Do not make any recommendations realted to fine tuning, just collect evidence about the rule ID and report it.
Also inculde the full log of the rule ID in spearte section in the output. just one sample full log.
"""

WEBSERACH_INSTRUCTIONS = """
You are an internet threat intelligence researcher.
When given a rule ID and a description of its behavior, your job is to search the web for all relevant external information about that behavior.
This includes vendor documentation (such as Microsoft docs if the rule is Windows-related), Wazuh, security blogs, online forums.
Do not access the SIEM. Do not read rule files. Donot make final recommendations.
Your output is a structured summary of everything relevant you found on the internet about this behavior and its known associations with legitimate activity or malicious activity.
Your output should be only from the data that you found in the internet only. if you do not found any data or some error happen say that you do not have enough information and you can not find anything relevant on the internet about this rule ID behavior.
"""

SUMMARY_INSTRUCTIONS = """
You are a summarization assistant for WAZUH SIEM threat hunting output.
Summarize the previous threat hunting result in concise structured text for web research context.
Keep only high-signal context: rule behavior, top entities, patterns, and counts.
Do not include recommendations.
"""

REPORT_INSTRUCTIONS = """
You are the final report writer for Wazuh SIEM fine-tuning.
Use the outputs from previous workflow steps and produce one complete report for the given rule ID.
Before that you will search Wazuh rule files on the manager server for a given rule ID.
Using the MCP tool 'ossec_mcp' output and do not invent content.
The search priority is:
1) /var/ossec/etc/rules/*.xml
2) /var/ossec/ruleset/rules/*.xml
If found in both, use /var/ossec/etc/rules result.

so now you will have these info before give a final recommendation:
- where the rule was found (file + folder),
- the main XML rule block,
- the places in the same selected file where other rules reference this rule ID,
- and the full XML blocks of the referencing rules

Now you know what rulese exist for this Rule ID because maybe the changes to be edit exisitng rule, please add these info to the report.
instead of creating a new rule, or maybe the rule is already fine-tuned and no changes are needed, or maybe the rule is not well-written and needs to be fixed in a specific way

Now you can Produce one complete fine-tuning report for the given rule ID.
The report must include:
1) Number of Hits (Weekly / Monthly / Daily)
2) Rule intent and what it detects and Why This Rule Fire in first place?
2) Behavioral findings from SIEM (frequency, sources, users, IPs, hosts, recurring patterns) based on what info you get from threathunting_agent.
3) External context from internet/vendor/community references.
4) Ruleset Context from Wazuh Manager (where the rule was found (file + folder), the main XML rule block, the places in the same selected file where other rules reference this rule ID, and the full XML blocks of the referencing rules).
5) Full log sample of the rule ID from SIEM (you will find it from threat hunting agent report).
6) Final detection-engineering recommendations specific to Wazuh SIEM tuning. (Make one detection-engineering per recommendation like one idea per recommendation. Don’t include multiple custom rules or ideas in a single recommendation.)

Use clear normal English with concrete justifications. Do not recommend the XML syntax or XML rule files, just give logical explanation and recommendations in normal English.
Do not recommend controls outside Wazuh SIEM detection engineering (for example firewall blocks).
Just logical explanation in normal English and with justification (because other agent that has knowledge in writing xml rule IDs inside Wazuh will take these logical recommendation for you and turn it to a ready xml syntax rules to deploy it.). Be specific do not give any recommendation we can not do inside the Wazuh SIEM like as example "BLOCK THESE IPS on firewall", just focus on detection engineering inside Wazuh SIEM.

Your recommendations should foucs only on how to reduce the false positives of the rule.
"""

DETECTION_ENGINEER_INSTRUCTIONS = """
You are a Wazuh detection engineer. connected to wazuh-detection-engineering skill and ssh mcp in wazuh manager. Apply approved rule tuning recommendations safely using SSH tools.
You will receive the final report and the user-selected recommendation numbers from earlier workflow steps.
Follow the wazuh-detection-engineering skill flow, including its scripts for:
- fetching full SIEM logs for logtest input,
- validating/allocating unique custom rule IDs,
- running strict validation gate checks before finalizing changes.
Apply only the selected recommendation numbers from the final report.
If any selected number is missing or unclear in the report, do not guess.
Explain what was applied and what was skipped.
"""


def _build_threat_hunting_agent(step_input: StepInput) -> Agent:
    settings = _load_runtime_settings(step_input)
    return Agent(
        id="threathunting-agent",
        name="threathunting_agent",
        model=_build_model(settings),
        instructions=THREAT_HUNTING_INSTRUCTIONS,
        role="Collects bounded SIEM evidence for a rule ID using OpenSearch MCP tools.",
        tools=[_build_opensearch_mcp(settings)],
        db=agent_db,
    )


def _build_summary_agent(step_input: StepInput) -> Agent:
    settings = _load_runtime_settings(step_input)
    return Agent(
        id="threat-summary-agent",
        name="threat_summary_agent",
        model=_build_model(settings),
        instructions=SUMMARY_INSTRUCTIONS,
        role="Summarizes threat-hunting output for the web-intel step.",
        db=agent_db,
    )


def _build_websearch_agent(step_input: StepInput) -> Agent:
    settings = _load_runtime_settings(step_input)
    return Agent(
        id="websearch-agent",
        name="websearch_agent",
        model=_build_model(settings),
        instructions=WEBSERACH_INSTRUCTIONS,
        role="Used to search the internet, online forums, blogs, vendor docs, and related to the behavior of a given Wazuh rule ID.",
        tools=[_build_websearch_mcp(settings)],
        db=agent_db,
    )


def _build_reporting_agent(step_input: StepInput) -> Agent:
    settings = _load_runtime_settings(step_input)
    return Agent(
        id="reporting-agent",
        name="reporting_agent",
        model=_build_model(settings),
        instructions=REPORT_INSTRUCTIONS,
        role="Creates the final report using outputs from the previous sequential steps.",
        tools=[_build_ossec_mcp(settings)],
        db=agent_db,
    )


def _build_detection_engineer_agent(step_input: StepInput) -> Agent:
    return _build_detection_engineer_agent_for_user_id(_runtime_user_id(step_input))


def _build_detection_engineer_agent_for_user_id(user_id: str) -> Agent:
    settings = _load_runtime_settings_for_user_id(user_id)
    return Agent(
        id="detectionengineer-agent",
        name="detectionengineer_agent",
        model=_build_model(settings),
        instructions=DETECTION_ENGINEER_INSTRUCTIONS,
        role="Apply approved Wazuh detection changes on the server.",
        tools=[_build_ssh_mcp(settings)],
        skills=Skills(loaders=[LocalSkills(str(WAZUH_SKILL_PATH))]),
        db=agent_db,
    )


def _agent_step_session_id(session_id: str | None, agent_id: str) -> str | None:
    session_id_text = _text(session_id)
    if not session_id_text:
        return None
    if session_id_text.endswith(f":{agent_id}"):
        return session_id_text
    return f"{session_id_text}:{agent_id}"


class RuntimeDetectionEngineerAgent(Agent):
    """Native workflow agent step that resolves per-user settings at run time."""

    def __init__(self) -> None:
        super().__init__(
            id="detectionengineer-agent",
            name="detectionengineer_agent",
            role="Apply approved Wazuh detection changes on the server.",
            instructions=DETECTION_ENGINEER_INSTRUCTIONS,
            db=agent_db,
        )

    def _delegate(
        self,
        user_id: str | None = None,
        session_id: str | None = None,
        run_response: object | None = None,
    ) -> Agent:
        resolved_user_id = (
            _text(user_id)
            or _text(getattr(run_response, "user_id", ""))
            or _workflow_session_user_id(session_id or getattr(run_response, "session_id", ""))
        )
        return _build_detection_engineer_agent_for_user_id(resolved_user_id)

    def run(self, input, *args, user_id=None, session_id=None, **kwargs):
        agent = self._delegate(user_id=user_id, session_id=session_id)
        agent_session_id = _agent_step_session_id(session_id, self.id or "detectionengineer-agent")
        return agent.run(
            input,
            *args,
            user_id=user_id,
            session_id=agent_session_id,
            **kwargs,
        )

    def arun(self, input, *args, user_id=None, session_id=None, **kwargs):
        agent = self._delegate(user_id=user_id, session_id=session_id)
        agent_session_id = _agent_step_session_id(session_id, self.id or "detectionengineer-agent")
        return agent.arun(
            input,
            *args,
            user_id=user_id,
            session_id=agent_session_id,
            **kwargs,
        )

    def continue_run(self, run_response=None, *args, user_id=None, **kwargs):
        agent = self._delegate(user_id=user_id, run_response=run_response)
        return agent.continue_run(run_response=run_response, *args, user_id=user_id, **kwargs)

    def acontinue_run(self, run_response=None, *args, user_id=None, **kwargs):
        agent = self._delegate(user_id=user_id, run_response=run_response)
        return agent.acontinue_run(run_response=run_response, *args, user_id=user_id, **kwargs)


async def _run_agent_step(
    step_name: str,
    step_input: StepInput,
    agent: Agent,
    prompt: str,
) -> AsyncIterator[Union[WorkflowRunOutputEvent, StepOutput]]:
    """Stream nested agent events from custom function steps, then yield the final StepOutput."""
    _ = step_input
    try:
        response_iterator = agent.arun(prompt, stream=True, stream_events=True)
        async for event in response_iterator:
            yield event

        response = agent.get_last_run_output()
        if response is None:
            yield StepOutput(
                step_name=step_name,
                content=f"No run output was produced for step '{step_name}'.",
                success=False,
            )
            return

        yield StepOutput(
            step_name=step_name,
            content=getattr(response, "content", "") or "",
            success=bool(getattr(response, "success", True)),
        )
    except Exception as exc:
        yield StepOutput(
            step_name=step_name,
            content=f"Step '{step_name}' failed: {exc}",
            success=False,
        )


async def research_threat_hunting(
    step_input: StepInput,
) -> AsyncIterator[Union[WorkflowRunOutputEvent, StepOutput]]:
    prompt = step_input.get_input_as_string() or step_input.get_last_step_content() or ""
    agent = _build_threat_hunting_agent(step_input)
    async for event in _run_agent_step("research_threat_hunting", step_input, agent, prompt):
        yield event


async def summarize_threat_hunting(
    step_input: StepInput,
) -> AsyncIterator[Union[WorkflowRunOutputEvent, StepOutput]]:
    threat_hunting = step_input.get_step_content("research_threat_hunting") or ""
    prompt = f"""Summarize this threat hunting output for web intelligence context.

{threat_hunting}
"""
    agent = _build_summary_agent(step_input)
    async for event in _run_agent_step("summarize_threat_hunting", step_input, agent, prompt):
        yield event


async def research_web_intel(
    step_input: StepInput,
) -> AsyncIterator[Union[WorkflowRunOutputEvent, StepOutput]]:
    summary = step_input.get_step_content("summarize_threat_hunting") or ""
    fallback = step_input.get_step_content("research_threat_hunting") or ""
    prompt = summary or fallback
    agent = _build_websearch_agent(step_input)
    async for event in _run_agent_step("research_web_intel", step_input, agent, prompt):
        yield event


async def create_final_report(
    step_input: StepInput,
) -> AsyncIterator[Union[WorkflowRunOutputEvent, StepOutput]]:
    threat_hunting_research = step_input.get_step_content("research_threat_hunting") or ""
    web_intel_research = step_input.get_step_content("research_web_intel") or ""

    prompt = f"""Use this collected research and produce one final Wazuh SIEM fine-tuning report.

=== research_threat_hunting ===
{threat_hunting_research}

=== research_web_intel ===
{web_intel_research}
"""

    agent = _build_reporting_agent(step_input)
    async for event in _run_agent_step("final_report", step_input, agent, prompt):
        yield event


def approve_detection_changes(step_input: StepInput) -> StepOutput:
    return StepOutput(
        step_name="approve_detection_changes",
        content="User approved continuing to recommendation selection.",
        success=True,
    )


def collect_recommendation_selection(step_input: StepInput) -> StepOutput:
    user_input = step_input.additional_data.get("user_input", {}) if step_input.additional_data else {}
    selected = str(user_input.get("recommendation_numbers", "")).strip()
    final_report = step_input.get_step_content("final_report") or ""
    return StepOutput(
        step_name="select_recommendations",
        content=f"""Apply only the user-approved recommendations from the final report.

User-selected recommendation numbers:
{selected}

Final report:
{final_report}

Important:
- Apply only the selected recommendation numbers.
- If any selected number is missing/unclear in the report, apply the first recommendation.
- Explain what was applied and what was skipped.
""",
        success=True,
    )


# Define the workflow
fine_tuning_workflow = Workflow(
    id="wazuh-fine-tuning-pipeline",
    name="Fine Tuning Pipeline",
    db=agent_db,
    steps=[
        Step(
            name="research_threat_hunting",
            executor=research_threat_hunting,
            description="Research SIEM behavior and patterns for this rule ID",
        ),
        Step(
            name="summarize_threat_hunting",
            executor=summarize_threat_hunting,
            description="Summarize threat hunting output for the web intelligence step",
        ),
        Step(
            name="research_web_intel",
            executor=research_web_intel,
            description="Research external threat intelligence and references",
        ),
        Step(
            name="final_report",
            executor=create_final_report,
            description="Generate final report from all previous step outputs",
        ),
        Step(
            name="approve_detection_changes",
            executor=approve_detection_changes,
            requires_confirmation=True,
            confirmation_message="Do I apply recommended detection rule inside Wazuh now?",
            on_reject=OnReject.cancel,
            description="User must approve before moving to recommendation selection",
        ),
        Step(
            name="select_recommendations",
            executor=collect_recommendation_selection,
            requires_user_input=True,
            user_input_message="Enter recommendation numbers to apply (example: 1,3,5)",
            user_input_schema=[
                UserInputField(
                    name="recommendation_numbers",
                    field_type="str",
                    description="Comma-separated recommendation numbers from final report",
                    required=True,
                )
            ],
            description="Collect recommendation numbers selected by user",
        ),
        Step(
            name="apply_detection_changes",
            agent=RuntimeDetectionEngineerAgent(),
            description="Apply detection engineering changes after user confirmation and recommendation selection",
        ),
    ],
)

# Workflow is now runtime-resolved per user; keep empty static agents list.
wazuh_agents = []

wazuh_workflows = [fine_tuning_workflow]
