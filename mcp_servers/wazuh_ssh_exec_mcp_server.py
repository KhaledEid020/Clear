"""
wazuh_ssh_exec_mcp_server.py
────────────────────────────
Minimal SSH MCP server for Wazuh manager operations.

This server intentionally does not implement human approval.
Approval is expected at the deep-agent layer via interrupt_on.
"""

from fastmcp import FastMCP
import os
import argparse
import paramiko
import shlex
from typing import Optional


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
    if (
        _ssh_client is None
        or not _ssh_client.get_transport()
        or not _ssh_client.get_transport().is_active()
    ):
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


def _run(command: str, timeout: int = 90) -> str:
    try:
        stdin, stdout, stderr = _exec_ssh_command(command, timeout=timeout)
        out = stdout.read().decode("utf-8", errors="replace").strip()
        err = stderr.read().decode("utf-8", errors="replace").strip()
        if err:
            return f"{out}\n[STDERR]: {err}".strip()
        return out or "(no output)"
    except Exception as e:
        return f"[SSH ERROR]: {str(e)}"


mcp = FastMCP(name="wazuh-ssh-exec-mcp")


def _validate_command(command: str) -> str:
    if not isinstance(command, str) or not command.strip():
        raise ValueError("command must be a non-empty string.")
    if "\x00" in command:
        raise ValueError("command contains null byte.")
    return command.strip()


def _execute_as_root(command: str, timeout_seconds: int) -> str:
    wrapped = f"sudo su -c {shlex.quote(command)}"
    return _run(wrapped, timeout=timeout_seconds)


@mcp.tool
async def run_ssh_command(command: str, timeout_seconds: int = 90) -> str:
    """
    Run SSH commands as root on the Wazuh manager.
    Human-in-the-loop approval is expected at the workflow/agent layer.
    """
    try:
        cmd = _validate_command(command)
    except ValueError as exc:
        return f"[BLOCKED]: {exc}"

    timeout_seconds = max(1, min(int(timeout_seconds), 600))
    return _execute_as_root(cmd, timeout_seconds)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Wazuh SSH exec MCP server")
    parser.add_argument(
        "--transport",
        choices=["stdio", "http", "sse", "streamable-http"],
        default=os.getenv("MCP_TRANSPORT", "stdio"),
        help="MCP transport mode",
    )
    parser.add_argument(
        "--host",
        default=os.getenv("MCP_HOST", "0.0.0.0"),
        help="Host for network transports",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.getenv("MCP_PORT", "9002")),
        help="Port for network transports",
    )
    args = parser.parse_args()

    if args.transport == "stdio":
        mcp.run(transport="stdio")
    else:
        mcp.run(
            transport=args.transport,
            host=args.host,
            port=args.port,
        )
