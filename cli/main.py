"""
SafeRun CLI - Security check for Python files.
Usage: saferun <file>      Check if a file is safe
       saferun run <file>   Execute in sandbox
       saferun history      Show execution history
"""

import os
import sys
import click
import requests
from pathlib import Path


# Default to the local backend. Point SAFERUN_API_URL at a remote one when
# you have deployed it yourself.
def get_default_api_url():
    """Get API URL from environment or fall back to a local backend."""
    return os.getenv("SAFERUN_API_URL", "http://127.0.0.1:8000")


API_BASE = get_default_api_url()


def auth_headers():
    """Headers for authenticated endpoints (X-API-Key when configured)."""
    key = os.getenv("SAFERUN_API_KEY")
    return {"X-API-Key": key} if key else {}


def explain_auth_failure():
    """Printed when the backend rejects the key."""
    click.secho(
        "\nAuthentication failed.\n"
        "Set an API key for this backend:\n"
        "  export SAFERUN_API_KEY=...\n"
        "or pass --api-key. The backend needs SAFERUN_API_KEYS configured.",
        fg="red",
    )


def get_code(file_path):
    """Read file and return code string."""
    path = Path(file_path)
    if not path.exists():
        click.secho(f"Error: File '{file_path}' not found.", fg="red")
        sys.exit(1)
    if path.suffix not in (".py", ".txt"):
        click.secho(f"Warning: '{file_path}' is not a .py file.", fg="yellow")
    return path.read_text(encoding="utf-8")


def check_api(api_url=None):
    """Verify backend is reachable."""
    url = api_url or API_BASE
    try:
        requests.get(f"{url}/health", timeout=2)
    except requests.ConnectionError:
        click.secho(
            f"Error: Backend not reachable at {url}\n\n"
            "Options:\n"
            "  1. Start local backend: uvicorn backend.main:app --host 0.0.0.0 --port 8000\n"
            "  2. Use remote backend: export SAFERUN_API_URL=https://your-backend.com\n"
            "  3. Install full package: pip install saferun-ai[full]",
            fg="red",
        )
        sys.exit(1)


@click.group(invoke_without_command=True)
@click.argument("file", type=click.Path(), required=False, default=None)
@click.option(
    "--api-url",
    envvar="SAFERUN_API_URL",
    default=get_default_api_url(),
    help="Backend API URL",
)
@click.option(
    "--api-key",
    envvar="SAFERUN_API_KEY",
    default=None,
    help="API key for the backend (sent as X-API-Key).",
)
@click.pass_context
def cli(ctx, file, api_url, api_key):
    """
    SafeRun AI - Security check for Python files.

    Default behavior: scans the file for security risks without executing it.

    \b
    Examples:
      saferun script.py          Check if script.py is safe
      saferun run script.py      Execute script.py in sandbox
      saferun history            Show recent execution history

    \b
    Setup:
      export SAFERUN_API_URL=https://your-backend.com
      saferun script.py
    """
    global API_BASE
    API_BASE = api_url

    if ctx.invoked_subcommand is None:
        if file:
            ctx.invoke(check, file=file)
        else:
            click.echo(ctx.get_help())


@cli.command()
@click.argument("file", type=click.Path())
@click.option("--api-url", envvar="SAFERUN_API_URL", hidden=True)
@click.pass_context
def check(ctx, file, api_url):
    """Scan a Python file for security risks. (Default command)"""
    if api_url:
        global API_BASE
        API_BASE = api_url

    code = get_code(file)
    filename = Path(file).name
    check_api()

    click.echo(f"Checking {filename}...")

    try:
        resp = requests.post(
            f"{API_BASE}/scan", json={"code": code}, headers=auth_headers(), timeout=10
        )
        if resp.status_code in (401, 403, 503):
            explain_auth_failure()
            sys.exit(1)
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        click.secho(f"Error: {e}", fg="red")
        sys.exit(1)

    risk = data["risk_level"]
    warnings = data.get("warnings", [])
    violations = data.get("policy_violations", [])

    if risk == "LOW":
        click.echo(
            f"\n{click.style('PASSED', fg='green', bold=True)} {filename} appears safe."
        )
        click.echo(data.get("explanation", ""))
        sys.exit(0)
    elif risk == "MEDIUM":
        click.echo(
            f"\n{click.style('WARNING', fg='yellow', bold=True)} {filename} has potential risks."
        )
        for w in warnings:
            click.secho(f"  • {w}", fg="yellow")
        click.echo(f"\n{data.get('explanation', '')}")
        sys.exit(0)
    elif risk == "HIGH":
        click.echo(
            f"\n{click.style('FAILED', fg='red', bold=True)} {filename} contains high-risk patterns."
        )
        for w in warnings:
            click.secho(f"  • {w}", fg="red")
        if violations:
            click.echo("\nPolicy violations:")
            for v in violations:
                click.secho(f"  • {v}", fg="red")
        click.echo(f"\n{data.get('explanation', '')}")
        sys.exit(1)
    elif risk == "BLOCKED":
        click.echo(
            f"\n{click.style('BLOCKED', fg='red', bold=True)} {filename} would be blocked from execution."
        )
        for w in warnings:
            click.secho(f"  • {w}", fg="red")
        if violations:
            click.echo("\nPolicy violations:")
            for v in violations:
                click.secho(f"  • {v}", fg="red")
        click.echo(f"\n{data.get('explanation', '')}")
        sys.exit(1)


@cli.command()
@click.argument("file", type=click.Path())
@click.option("--api-url", envvar="SAFERUN_API_URL", hidden=True)
@click.option(
    "--override",
    is_flag=True,
    help="Ask the server to override a block (needs an admin key).",
)
@click.option("--api-key", envvar="SAFERUN_API_KEY", default=None, help="API key.")
@click.pass_context
def run(ctx, file, api_url, override, api_key):
    """Execute a Python file in the sandbox."""
    if api_url:
        global API_BASE
        API_BASE = api_url

    code = get_code(file)
    filename = Path(file).name
    check_api()

    if override:
        click.secho("Override enabled: bypassing safety blocks.", fg="yellow")

    click.echo(f"Running {filename} in sandbox...")

    try:
        resp = requests.post(
            f"{API_BASE}/execute",
            json={"code": code, "override": override},
            headers=auth_headers(),
            timeout=30,
        )
        if resp.status_code in (401, 503):
            explain_auth_failure()
            sys.exit(1)
        resp.raise_for_status()
        data = resp.json()
    except requests.HTTPError as e:
        if e.response is not None and e.response.status_code == 403:
            click.secho(
                "\nExecution blocked by security policy.\n"
                "Overriding a block is an operator action: it needs an admin key "
                "on the server (SAFERUN_ADMIN_KEY) and --override here.",
                fg="red",
            )
            sys.exit(1)
        click.secho(f"Error: {e.response.text}", fg="red")
        sys.exit(1)
    except Exception as e:
        click.secho(f"Error: {e}", fg="red")
        sys.exit(1)

    status = data["status"]
    if status == "success":
        click.secho(
            f"\n{click.style('SUCCESS', fg='green', bold=True)} Executed in {data['execution_time']:.3f}s"
        )
    elif status == "timeout":
        click.secho(
            f"\n{click.style('TIMEOUT', fg='yellow', bold=True)} Execution exceeded time limit."
        )
    else:
        click.secho(
            f"\n{click.style('ERROR', fg='red', bold=True)} Exit code: {data['exit_code']}"
        )

    if data.get("stdout"):
        click.echo(f"\n{click.style('stdout:', bold=True)}")
        click.echo(data["stdout"])

    if data.get("stderr"):
        click.echo(f"\n{click.style('stderr:', fg='yellow', bold=True)}")
        click.secho(data["stderr"], fg="yellow")

    click.echo(f"\n{data.get('explanation', '')}")


@cli.command()
@click.option("--api-url", envvar="SAFERUN_API_URL", hidden=True)
@click.option("--api-key", envvar="SAFERUN_API_KEY", default=None, help="API key.")
@click.pass_context
def history(ctx, api_url, api_key):
    """Show recent execution history."""
    if api_url:
        global API_BASE
        API_BASE = api_url

    check_api()

    try:
        resp = requests.get(f"{API_BASE}/history", headers=auth_headers(), timeout=5)
        if resp.status_code in (401, 403, 503):
            explain_auth_failure()
            sys.exit(1)
        resp.raise_for_status()
        records = resp.json()
    except Exception as e:
        click.secho(f"Error: {e}", fg="red")
        sys.exit(1)

    if not records:
        click.echo("No execution history yet.")
        return

    click.echo(f"\n{'ID':<5} {'Risk':<8} {'Status':<10} {'Time':<8} {'Date'}")
    click.echo("-" * 55)
    for r in records[:20]:
        risk_color = {
            "LOW": "green",
            "MEDIUM": "yellow",
            "HIGH": "red",
            "BLOCKED": "red",
        }
        risk = r["risk_level"]
        click.echo(
            f"{r['id']:<5} "
            f"{click.style(risk, fg=risk_color.get(risk, 'white')):<12} "
            f"{r['status']:<10} "
            f"{r['execution_time']:.2f}s   "
            f"{r['created_at'][:19]}"
        )
    click.echo()


if __name__ == "__main__":
    cli()
