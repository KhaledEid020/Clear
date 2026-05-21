"""
User setup data access.
"""

from os import getenv
import re
from typing import Any

import psycopg
from psycopg.rows import dict_row

_SCHEMA_RE = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*$")


def _schema_name() -> str:
    raw = (getenv("APP_DB_SCHEMA", "ai") or "ai").strip()
    return raw if _SCHEMA_RE.match(raw) else "ai"


def get_app_user_setup(user_id: str) -> dict[str, Any] | None:
    normalized_user_id = (user_id or "").strip()
    if not normalized_user_id:
        return None

    schema = _schema_name()
    query = f"""
        SELECT
          user_id,
          ai_provider, ai_api_key, ai_model_id,
          web_provider, web_api_key,
          siem_provider,
          siem_indexer_url, siem_indexer_user, siem_indexer_pass,
          siem_manager_url, siem_ssh_user, siem_ssh_port, siem_ssh_auth, siem_ssh_auth_mode,
          onboarding_completed
        FROM {schema}.app_user_setup
        WHERE user_id = %s
        LIMIT 1
    """

    with psycopg.connect(
        host=getenv("DB_HOST", "localhost"),
        port=int(getenv("DB_PORT", "5432")),
        user=getenv("DB_USER", "ai"),
        password=getenv("DB_PASS", "ai"),
        dbname=getenv("DB_DATABASE", "ai"),
        row_factory=dict_row,
    ) as connection:
        with connection.cursor() as cursor:
            cursor.execute(query, (normalized_user_id,))
            row = cursor.fetchone()
            return dict(row) if row else None
