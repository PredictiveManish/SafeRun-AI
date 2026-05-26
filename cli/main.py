"""
SafeRun CLI - Security check for Python files.
Usage: saferun <file>      Check if a file is safe
       saferun run <file>   Execute in sandbox
       saferun history      Show execution history
"""

import sys
import click
import requests
from pathlib import Path

API_BASE = "http://localhost:8000"


def get_code(file_path):
    """Read file and return code string."""
    path = Path(file_path)
    if not path.exists():
        click.secho(f"Error: File '{file_path}' not found.", fg="red")
        sys.exit(1)
    if path.suffix not in (".py", ".txt"):
        click.secho(f"Warning: '{file_path}' is not a .py file.", fg="yellow")
    return path.read_text(encoding="utf-8")


def check_api():
    """Verify backend is reachable."""
    try:
        requests.get(f"{API_BASE}/health", timeout=2)
    except requests.ConnectionError:
        click.secho(
            "Error: Backend not running. Start it with:\n"
            "  uvicorn backend.main:app --host 0.0.0.0 --port 8000",
            fg="red",
        )
        sys.exit(1)


@click.group(invoke_without_command=True)
@click.argument("file", type=click.Path(), required=False, default=None)
@click.option("--api", default=API_BASE, help="Backend API URL", hidden=True)
@click.pass_context
def cli(ctx, file, api):
    """
    SafeRun AI - Security check for Python files.

    Default behavior: scans the file for security risks without executing it.

    \b
    Examples:
      saferun script.py          Check if script.py is safe
      saferun run script.py      Execute script.py in sandbox
      saferun history            Show recent execution history
    """
    # Only try to check a file if no subcommand is being invoked
    if ctx.invoked_subcommand is None:
        if file:
            ctx.invoke(check, file=file, api=api)
        else:
            click.echo(ctx.get_help())

@cli.command()
@click.argument("file", type=click.Path())
@click.option("--api", default=API_BASE, help="Backend API URL", hidden=True)
def check(file, api):
    """Scan a Python file for security risks. (Default command)"""
    code = get_code(file)
    filename = Path(file).name
    check_api()

    click.echo(f"Checking {filename}...")

    try:
        resp = requests.post(f"{api}/scan", json={"code": code}, timeout=10)
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        click.secho(f"Error: {e}", fg="red")
        sys.exit(1)

    risk = data["risk_level"]
    blocked = data["blocked"]
    warnings = data.get("warnings", [])
    violations = data.get("policy_violations", [])
    patterns = data.get("detected_patterns", [])

    # Print results in ruff-like style
    if risk == "LOW":
        click.echo(f"\n{click.style('PASSED', fg='green', bold=True)} {filename} appears safe.")
        click.echo(data.get("explanation", ""))
        sys.exit(0)

    elif risk == "MEDIUM":
        click.echo(f"\n{click.style('WARNING', fg='yellow', bold=True)} {filename} has potential risks.")
        for w in warnings:
            click.secho(f"  • {w}", fg="yellow")
        click.echo(f"\n{data.get('explanation', '')}")
        sys.exit(0)

    elif risk == "HIGH":
        click.echo(f"\n{click.style('FAILED', fg='red', bold=True)} {filename} contains high-risk patterns.")
        for w in warnings:
            click.secho(f"  • {w}", fg="red")
        if violations:
            click.echo(f"\nPolicy violations:")
            for v in violations:
                click.secho(f"  • {v}", fg="red")
        click.echo(f"\n{data.get('explanation', '')}")
        sys.exit(1)

    elif risk == "BLOCKED":
        click.echo(f"\n{click.style('BLOCKED', fg='red', bold=True)} {filename} would be blocked from execution.")
        for w in warnings:
            click.secho(f"  • {w}", fg="red")
        if violations:
            click.echo(f"\nPolicy violations:")
            for v in violations:
                click.secho(f"  • {v}", fg="red")
        click.echo(f"\n{data.get('explanation', '')}")
        sys.exit(1)


@cli.command()
@click.argument("file", type=click.Path())
@click.option("--api", default=API_BASE, help="Backend API URL", hidden=True)
@click.option("--override", is_flag=True, help="Override safety blocks")
def run(file, api, override):
    """Execute a Python file in the sandbox."""
    code = get_code(file)
    filename = Path(file).name
    check_api()

    if override:
        click.secho("Override enabled: bypassing safety blocks.", fg="yellow")

    click.echo(f"Running {filename} in sandbox...")

    try:
        resp = requests.post(
            f"{api}/execute",
            json={"code": code, "override": override},
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
    except requests.HTTPError as e:
        if e.response.status_code == 403:
            click.secho(
                "\nExecution blocked by security policy.\n"
                "Use --override to force execution at your own risk.",
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
        click.secho(f"\n{click.style('SUCCESS', fg='green', bold=True)} Executed in {data['execution_time']:.3f}s")
    elif status == "timeout":
        click.secho(f"\n{click.style('TIMEOUT', fg='yellow', bold=True)} Execution exceeded time limit.")
    else:
        click.secho(f"\n{click.style('ERROR', fg='red', bold=True)} Exit code: {data['exit_code']}")

    if data.get("stdout"):
        click.echo(f"\n{click.style('stdout:', bold=True)}")
        click.echo(data["stdout"])

    if data.get("stderr"):
        click.echo(f"\n{click.style('stderr:', fg='yellow', bold=True)}")
        click.secho(data["stderr"], fg="yellow")

    click.echo(f"\n{data.get('explanation', '')}")


@cli.command()
@click.option("--api", default=API_BASE, help="Backend API URL", hidden=True)
def history(api):
    """Show recent execution history."""
    check_api()

    try:
        resp = requests.get(f"{api}/history", timeout=5)
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
        risk_color = {"LOW": "green", "MEDIUM": "yellow", "HIGH": "red", "BLOCKED": "red"}
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