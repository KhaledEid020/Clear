from fastmcp import FastMCP
import paramiko
import os
import shlex
from typing import Optional


# Persistent SSH client (same reliable logic as before)
_ssh_client: Optional[paramiko.SSHClient] = None


def _reset_ssh_client() -> None:
    global _ssh_client
    if _ssh_client is not None:
        try:
            _ssh_client.close()
        except Exception:
            pass
    _ssh_client = None


def get_ssh_client() -> paramiko.SSHClient:
    global _ssh_client
    if _ssh_client is None or not _ssh_client.get_transport() or not _ssh_client.get_transport().is_active():
        _ssh_client = paramiko.SSHClient()
        _ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        key_filename = os.getenv("REMOTE_KEY_PATH") or None
        password = os.getenv("REMOTE_PASSWORD") or None
        connect_kwargs = {
            "hostname": os.getenv("REMOTE_HOST"),
            "port": int(os.getenv("REMOTE_PORT", 22)),
            "username": os.getenv("REMOTE_USER"),
        }
        if key_filename:
            connect_kwargs["key_filename"] = key_filename
        if password:
            connect_kwargs["password"] = password
        _ssh_client.connect(**connect_kwargs)
    return _ssh_client


def _exec_ssh_command(command: str, timeout: int = 90):
    last_error: Optional[Exception] = None
    for attempt in range(2):
        try:
            client = get_ssh_client()
            return client.exec_command(command, timeout=timeout)
        except Exception as exc:
            last_error = exc
            message = str(exc).lower()
            if attempt == 0 and ("timeout opening channel" in message or "channel" in message):
                _reset_ssh_client()
                continue
            raise
    if last_error is not None:
        raise last_error
    raise RuntimeError("SSH command failed unexpectedly.")


mcp = FastMCP(
    name="ossec-rules-mcp",
)


@mcp.tool
async def extract_ossec_rule(rule_id: str) -> str:
    """Find Wazuh rule XML with deterministic directory priority and show same-file references.

    Priority:
      1) /var/ossec/etc/rules/*.xml
      2) /var/ossec/ruleset/rules/*.xml
    """
    clean_rule_id = (rule_id or "").strip()
    if not clean_rule_id.isdigit():
        return "Error: rule_id must be numeric (example: 60107)."

    shell_script = f"""
set -euo pipefail
rule_id="{clean_rule_id}"

etc_matches=$(find /var/ossec/etc/rules -type f -name "*.xml" -exec grep -l "<rule[^>]*id=\\"${{rule_id}}\\"" {{}} + 2>/dev/null | sort || true)
ruleset_matches=$(find /var/ossec/ruleset/rules -type f -name "*.xml" -exec grep -l "<rule[^>]*id=\\"${{rule_id}}\\"" {{}} + 2>/dev/null | sort || true)

etc_file=$(printf "%s\\n" "$etc_matches" | sed "/^$/d" | head -n 1)
ruleset_file=$(printf "%s\\n" "$ruleset_matches" | sed "/^$/d" | head -n 1)
selected_file="${{etc_file:-$ruleset_file}}"

if [ -z "$selected_file" ]; then
  echo "I did not find rule ID $rule_id in /var/ossec/etc/rules/*.xml or /var/ossec/ruleset/rules/*.xml."
  exit 0
fi

selected_dir=$(dirname "$selected_file")

echo "I found this rule ID $rule_id inside this file: $selected_file, under this folder: $selected_dir."
echo
echo "and here is the main block of XML:"
echo
main_block=$(sed -n "/<rule[^>]*id=\\"${{rule_id}}\\"[^>]*>/,/<\\\\/rule>/p" "$selected_file")
if [ -n "$main_block" ]; then
  printf "%s\\n" "$main_block"
else
  echo "(Main <rule> block could not be extracted.)"
fi

echo
echo "and the rule ID has been used in these rules also:"
echo

ref_hits=$(awk -v target="$rule_id" '
function has_target(value, n, i, arr) {{
  gsub(/,/, " ", value)
  gsub(/^[[:space:]]+/, "", value)
  gsub(/[[:space:]]+$/, "", value)
  n = split(value, arr, /[[:space:]]+/)
  for (i = 1; i <= n; i++) {{
    if (arr[i] == target) {{
      return 1
    }}
  }}
  return 0
}}
BEGIN {{
  current_rule = ""
}}
{{
  if (match($0, /<rule[^>]*id="[0-9]+"/)) {{
    current_rule = substr($0, RSTART, RLENGTH)
    sub(/^.*id="/, "", current_rule)
    sub(/".*$/, "", current_rule)
  }}

  line = $0
  while (match(line, /<(if_sid|if_matched_sid|if_not_sid|if_group|if_matched_group)>[^<]*<\\/(if_sid|if_matched_sid|if_not_sid|if_group|if_matched_group)>/)) {{
    tag = substr(line, RSTART, RLENGTH)
    inner = tag
    sub(/^<[^>]*>/, "", inner)
    sub(/<\\/[[:alnum:]_]+>$/, "", inner)

    if (has_target(inner) && current_rule != target) {{
      printf "%d|%s|%s\\n", NR, current_rule, tag
    }}
    line = substr(line, RSTART + RLENGTH)
  }}
}}
' "$selected_file")

if [ -z "$ref_hits" ]; then
  echo "- No references found in if_sid/if_matched_sid/if_not_sid/if_group/if_matched_group inside this file."
  exit 0
fi

echo "Reference matches (line, rule id, matcher tag):"
printf "%s\\n" "$ref_hits" | while IFS='|' read -r ref_line ref_rule_id ref_tag; do
  echo "- line $ref_line | rule id $ref_rule_id | $ref_tag"
done

echo
echo "XML blocks of referencing rules:"
echo
printf "%s\\n" "$ref_hits" | awk -F'|' '{{print $2}}' | sort -u | while read -r ref_rule_id; do
  [ -n "$ref_rule_id" ] || continue
  echo "---- Referencing Rule ID: $ref_rule_id ----"
  ref_block=$(sed -n "/<rule[^>]*id=[\\"\\x27]${{ref_rule_id}}[\\"\\x27][^>]*>/,/<\\\\/rule>/p" "$selected_file")
  if [ -n "$ref_block" ]; then
    printf "%s\\n" "$ref_block"
  else
    echo "(Could not extract XML block for rule id $ref_rule_id)"
  fi
  echo
done
"""
    command = f"sudo bash -lc {shlex.quote(shell_script)}"

    try:
        stdin, stdout, stderr = _exec_ssh_command(command, timeout=90)
        result = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace").strip()

        if err and not result.strip():
            return f"Error: {err}"
        return result.strip() or "No output"
    except Exception as e:
        return f"SSH Error: {str(e)}"


if __name__ == "__main__":
    # Run with STDIO transport → perfect for local agent
    mcp.run(transport="stdio")
