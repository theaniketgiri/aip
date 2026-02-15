"""
AIP CLI — Command-line interface for the Agent Intent Protocol.

Commands:
  aip create-passport   Create a new agent passport
  aip sign-intent       Create and sign an intent envelope
  aip verify            Verify a signed intent envelope
  aip revoke            Revoke an agent identity
  aip inspect           Inspect an envelope or passport
  aip init              Scaffold a new AIP-protected project
  aip login             Authenticate with AIP Cloud
  aip watch             Stream live verification events
  aip status            Show current AIP Cloud connection status
"""

from __future__ import annotations

import json
import os
import sys
import time
import webbrowser
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.live import Live
from rich import print as rprint

from aip_protocol.passport import AgentPassport
from aip_protocol.envelope import create_envelope, sign_envelope, envelope_to_json, envelope_from_json
from aip_protocol.verification import verify_intent
from aip_protocol.crypto import load_public_key, public_key_to_b64
from aip_protocol.revocation import RevocationStore
from aip_protocol.errors import AIPErrorCode

console = Console()

# ── Paths ────────────────────────────────────────────────────────────────
AIP_DIR = Path.home() / ".aip"
CREDENTIALS_FILE = AIP_DIR / "credentials.json"
AIP_CLOUD_URL = os.environ.get("AIP_CLOUD_URL", "https://aip.synthexai.tech")

# Global revocation store (in-memory for CLI usage)
_store = RevocationStore()


def _load_credentials() -> dict | None:
    """Load saved AIP Cloud credentials."""
    if CREDENTIALS_FILE.exists():
        try:
            return json.loads(CREDENTIALS_FILE.read_text())
        except (json.JSONDecodeError, IOError):
            return None
    return None


def _save_credentials(data: dict) -> None:
    """Save AIP Cloud credentials."""
    AIP_DIR.mkdir(parents=True, exist_ok=True)
    CREDENTIALS_FILE.write_text(json.dumps(data, indent=2))
    CREDENTIALS_FILE.chmod(0o600)  # Owner read/write only


@click.group()
@click.version_option(version="0.2.0", prog_name="aip")
def cli():
    """AIP — Agent Intent Protocol CLI"""
    pass


@cli.command("create-passport")
@click.option("--domain", "-d", default="localhost", help="Domain for DID (e.g., entripse.com)")
@click.option("--name", "-n", default=None, help="Agent name")
@click.option("--principal", "-p", default=None, help="Principal DID")
@click.option("--actions", "-a", multiple=True, help="Allowed actions")
@click.option("--monetary-limit", "-m", default=0.0, type=float, help="Per-transaction monetary limit")
@click.option("--output", "-o", default="./agent_passport", help="Output directory")
def create_passport_cmd(domain, name, principal, actions, monetary_limit, output):
    """Create a new agent passport with fresh Ed25519 keys."""
    passport = AgentPassport.create(
        domain=domain,
        agent_name=name,
        principal_id=principal,
        allowed_actions=list(actions) if actions else [],
        monetary_limit_per_txn=monetary_limit,
    )

    passport.save(output)

    console.print()
    console.print(Panel.fit(
        f"[bold green]✓ Agent Passport Created[/bold green]\n\n"
        f"  [bold]Agent ID:[/bold]    {passport.agent_id}\n"
        f"  [bold]Principal:[/bold]   {passport.principal.id}\n"
        f"  [bold]Actions:[/bold]     {', '.join(passport.boundaries.allowed_actions) or 'unrestricted'}\n"
        f"  [bold]Monetary:[/bold]    ${monetary_limit:.2f}/txn\n"
        f"  [bold]Saved to:[/bold]    {output}/\n"
        f"  [bold]Public Key:[/bold]  {public_key_to_b64(passport.public_key)[:32]}...",
        title="AIP Passport",
        border_style="green",
    ))


@cli.command("sign-intent")
@click.option("--passport", "-p", default="./agent_passport", help="Passport directory")
@click.option("--action", "-a", required=True, help="Intent action")
@click.option("--target", "-t", default="", help="Target DID or URL")
@click.option("--amount", type=float, default=None, help="Transaction amount")
@click.option("--ttl", default=300, type=int, help="TTL in seconds")
@click.option("--output", "-o", default=None, help="Output file (default: stdout)")
def sign_intent_cmd(passport, action, target, amount, ttl, output):
    """Create and sign an intent envelope."""
    agent = AgentPassport.load(passport)

    params = {}
    if amount is not None:
        params["amount"] = amount

    envelope = create_envelope(
        passport=agent,
        action=action,
        target=target,
        parameters=params,
        ttl=ttl,
    )

    signed = sign_envelope(envelope, agent.private_key)
    json_str = envelope_to_json(signed)

    if output:
        Path(output).write_text(json_str)
        console.print(f"[green]✓[/green] Signed intent saved to {output}")
    else:
        console.print(json_str)

    console.print()
    console.print(Panel.fit(
        f"  [bold]Action:[/bold]  {action}\n"
        f"  [bold]Target:[/bold]  {target or 'none'}\n"
        f"  [bold]Tier:[/bold]    {signed.verification_tier.value}\n"
        f"  [bold]TTL:[/bold]     {ttl}s\n"
        f"  [bold]Signed:[/bold]  [green]✓[/green]",
        title="Intent Envelope",
        border_style="blue",
    ))


@cli.command("verify")
@click.option("--envelope", "-e", required=True, help="Envelope JSON file")
@click.option("--public-key", "-k", required=True, help="Public key PEM file")
def verify_cmd(envelope, public_key):
    """Verify a signed intent envelope."""
    json_str = Path(envelope).read_text()
    env = envelope_from_json(json_str)
    pub_key = load_public_key(public_key)

    result = verify_intent(env, pub_key, revocation_store=_store)

    # Display results
    table = Table(title="Verification Result", border_style="bold")
    table.add_column("Check", style="bold")
    table.add_column("Status")
    table.add_column("Detail")

    checks = [
        ("Signature", result.signature_valid),
        ("Boundaries", result.within_boundaries),
        ("Attestation", result.attestation_match),
        ("Not Revoked", not result.revoked),
    ]

    for name, passed in checks:
        status = "[green]✓ PASS[/green]" if passed else "[red]✗ FAIL[/red]"
        table.add_row(name, status, "")

    table.add_row(
        "Trust Score",
        f"{result.trust_score:.2f}",
        "",
    )

    console.print()
    console.print(table)

    if result.passed:
        console.print("\n[bold green]✓ INTENT VERIFIED — All checks passed[/bold green]")
    else:
        console.print(f"\n[bold red]✗ INTENT REJECTED[/bold red]")
        for err in result.errors:
            console.print(f"  [red]• [{err.value}] {err.name}[/red]")

    sys.exit(0 if result.passed else 1)


@cli.command("revoke")
@click.argument("agent_id")
@click.option("--reason", "-r", default="manual_revocation", help="Revocation reason")
def revoke_cmd(agent_id, reason):
    """Revoke an agent identity."""
    record = _store.revoke(agent_id, reason=reason)
    console.print(f"\n[bold red]✓ REVOKED[/bold red] {agent_id}")
    console.print(f"  Reason: {record.reason}")
    console.print(f"  At:     {record.revoked_at.isoformat()}")


@cli.command("inspect")
@click.argument("path")
def inspect_cmd(path):
    """Inspect a passport directory or envelope JSON file."""
    p = Path(path)

    if p.is_dir():
        # It's a passport directory
        passport = AgentPassport.load(p)
        console.print(Panel.fit(
            json.dumps(passport.to_dict(), indent=2, default=str),
            title=f"Passport: {passport.agent_id}",
            border_style="cyan",
        ))
    elif p.is_file():
        # It's an envelope JSON
        data = json.loads(p.read_text())
        console.print(Panel.fit(
            json.dumps(data, indent=2, default=str),
            title="Intent Envelope",
            border_style="blue",
        ))
    else:
        console.print(f"[red]Error:[/red] {path} not found")
        sys.exit(1)


# ═══════════════════════════════════════════════════════════════════════════
#  aip init — Scaffold a new AIP-protected project (< 30s to Hello World)
# ═══════════════════════════════════════════════════════════════════════════

_INIT_AGENT_TEMPLATE = '''"""
{project_name} — Protected by AIP (Agent Intent Protocol)
Generated by: aip init
"""

from aip_protocol import shield, protect, AgentPassport, verify_intent


@shield(actions=["read_data", "send_alert"], limit=500.0)
class {class_name}:
    """An AI agent with AIP-verified boundaries."""

    def read_data(self, query: str) -> str:
        """Read data — AIP verifies this action before execution."""
        return f"✅ Data for: {{query}}"

    def send_alert(self, message: str, severity: str = "info") -> str:
        """Send alert — AIP enforces monetary and action limits."""
        return f"✅ Alert [{{severity}}]: {{message}}"


def main():
    print(f"🛡️  {{__doc__.strip()}}")
    print()

    agent = {class_name}()

    # ✅ These will pass AIP verification
    print(agent.read_data("system metrics"))
    print(agent.send_alert("CPU spike detected", severity="warning"))

    # ❌ This would fail — action not in allowed list
    # agent.delete_everything()  # AIP-E200: Action Not Allowed

    print()
    print("✅ All actions verified by AIP!")


if __name__ == "__main__":
    main()
'''

_INIT_SWARM_TEMPLATE = '''"""
{project_name} — Multi-Agent Swarm Protected by AIP
Generated by: aip init
"""

from aip_protocol import shield, protect_agent, AgentPassport, verify_intent


@shield(actions=["analyze", "report"], limit=100.0)
class AnalystAgent:
    """Reads data and generates reports."""

    def analyze(self, topic: str) -> str:
        return f"📊 Analysis of {{topic}}: metrics look healthy"

    def report(self, findings: str) -> str:
        return f"📝 Report: {{findings}}"


@shield(actions=["send_email", "send_slack"], limit=50.0)
class NotifierAgent:
    """Sends notifications through verified channels."""

    def send_email(self, to: str, body: str) -> str:
        return f"📧 Email to {{to}}: {{body}}"

    def send_slack(self, channel: str, message: str) -> str:
        return f"💬 Slack #{{channel}}: {{message}}"


def main():
    print(f"🛡️  {{__doc__.strip()}}")
    print()

    analyst = AnalystAgent()
    notifier = NotifierAgent()

    # Agent collaboration — each stays in its own boundaries
    findings = analyst.analyze("Q4 revenue")
    report = analyst.report(findings)
    print(report)

    notifier.send_email("team@company.com", report)
    notifier.send_slack("general", "New report available")

    print()
    print("✅ All agents verified by AIP — each stayed in its lane!")


if __name__ == "__main__":
    main()
'''


@cli.command("init")
@click.option("--name", "-n", prompt="Project name", default="my-aip-agent", help="Project name")
@click.option("--type", "project_type", type=click.Choice(["agent", "swarm"]), prompt="What are you building?", default="agent", help="agent or swarm")
def init_cmd(name, project_type):
    """Scaffold a new AIP-protected project. Hello World in <30 seconds."""
    project_dir = Path(name)

    if project_dir.exists():
        console.print(f"[red]Error:[/red] Directory '{name}' already exists")
        sys.exit(1)

    project_dir.mkdir(parents=True)

    # Generate class name from project name
    class_name = "".join(word.capitalize() for word in name.replace("-", "_").split("_")) + "Agent"

    if project_type == "agent":
        template = _INIT_AGENT_TEMPLATE
    else:
        template = _INIT_SWARM_TEMPLATE

    # Write main file
    main_file = project_dir / "main.py"
    main_file.write_text(template.format(
        project_name=name,
        class_name=class_name,
    ))

    # Write requirements
    req_file = project_dir / "requirements.txt"
    req_file.write_text("aip-protocol>=0.2.0\n")

    # Write .env template
    env_file = project_dir / ".env.example"
    env_lines = [
        "# AIP Cloud (optional — enables managed revocation, trust scores, audit logs)",
        "# Get your key at https://aip.synthexai.tech/dashboard",
        "# AIP_API_KEY=kya_your_key_here",
        "",
        "# Or login with: aip login",
        "",
    ]
    env_file.write_text("\n".join(env_lines) + "\n")

    console.print()
    console.print(Panel.fit(
        f"[bold green]✓ Project created: {name}/[/bold green]\n\n"
        f"  [dim]{name}/[/dim]\n"
        f"  ├── main.py           [dim]# Your {project_type} with AIP protection[/dim]\n"
        f"  ├── requirements.txt  [dim]# pip install -r requirements.txt[/dim]\n"
        f"  └── .env.example      [dim]# AIP Cloud config (optional)[/dim]\n\n"
        f"  [bold]Run it:[/bold]\n"
        f"  [cyan]cd {name}[/cyan]\n"
        f"  [cyan]pip install -r requirements.txt[/cyan]\n"
        f"  [cyan]python main.py[/cyan]",
        title="🛡️  AIP Init",
        border_style="green",
    ))


# ═══════════════════════════════════════════════════════════════════════════
#  aip login — Authenticate with AIP Cloud
# ═══════════════════════════════════════════════════════════════════════════

@cli.command("login")
@click.option("--token", "-t", default=None, help="Paste token directly (skip browser)")
@click.option("--api-key", "-k", default=None, help="Authenticate with API key instead")
def login_cmd(token, api_key):
    """Authenticate with AIP Cloud. Opens browser or accepts token/key directly."""

    if api_key:
        _save_credentials({"api_key": api_key, "type": "api_key"})
        console.print()
        console.print("[bold green]✓ API key saved[/bold green] to ~/.aip/credentials.json")
        console.print(f"  [dim]Key: {api_key[:8]}...{api_key[-4:]}[/dim]")
        return

    if token:
        _save_credentials({"token": token, "type": "jwt"})
        console.print()
        console.print("[bold green]✓ Token saved[/bold green] to ~/.aip/credentials.json")
        return

    # Interactive browser flow
    activate_url = f"{AIP_CLOUD_URL}/activate"

    login_text = (
        "[bold]Opening AIP Cloud login...[/bold]\n\n"
        "  1. A browser window will open\n"
        "  2. Log in to your AIP Cloud account\n"
        "  3. Copy the token shown on the page\n"
        "  4. Paste it below\n\n"
        f"  URL: [cyan]{activate_url}[/cyan]"
    )
    console.print()
    console.print(Panel.fit(login_text, title="🔐 AIP Login", border_style="blue"))

    try:
        webbrowser.open(activate_url)
        console.print()
        console.print("[dim]Browser opened. Waiting for token...[/dim]")
    except Exception:
        console.print()
        console.print(f"[yellow]Could not open browser.[/yellow] Visit: {activate_url}")

    pasted_token = click.prompt("\nPaste your token", hide_input=False)

    if pasted_token:
        _save_credentials({"token": pasted_token.strip(), "type": "jwt"})
        console.print()
        console.print("[bold green]✓ Logged in![/bold green] Token saved to ~/.aip/credentials.json")
        console.print("  [dim]File permissions: 600 (owner-only)[/dim]")
    else:
        console.print("[red]No token provided.[/red]")
        sys.exit(1)


# ═══════════════════════════════════════════════════════════════════════════
#  aip status — Show current AIP Cloud connection status
# ═══════════════════════════════════════════════════════════════════════════

@cli.command("status")
def status_cmd():
    """Show AIP Cloud connection status and credentials."""
    creds = _load_credentials()

    console.print()

    if creds is None:
        not_auth_text = (
            "[yellow]Not authenticated[/yellow]\n\n"
            "  Run [cyan]aip login[/cyan] to connect to AIP Cloud\n"
            "  Or set [cyan]AIP_API_KEY[/cyan] environment variable"
        )
        console.print(Panel.fit(not_auth_text, title="AIP Status", border_style="yellow"))
        return

    auth_type = creds.get("type", "unknown")
    if auth_type == "api_key":
        key = creds.get("api_key", "")
        display = f"{key[:8]}...{key[-4:]}" if len(key) > 12 else "***"
        auth_info = f"  [bold]Type:[/bold]  API Key\n  [bold]Key:[/bold]   {display}"
    else:
        token = creds.get("token", "")
        display = f"{token[:15]}..." if len(token) > 15 else "***"
        auth_info = f"  [bold]Type:[/bold]  JWT Token\n  [bold]Token:[/bold] {display}"

    # Try to reach the cloud
    cloud_status = "[yellow]unknown[/yellow]"
    try:
        import urllib.request
        req = urllib.request.Request(
            f"{AIP_CLOUD_URL}/api/health",
            headers={"User-Agent": "aip-cli/0.2.0"},
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            if resp.status == 200:
                cloud_status = "[green]connected ✓[/green]"
            else:
                cloud_status = f"[red]HTTP {resp.status}[/red]"
    except Exception:
        cloud_status = "[red]unreachable[/red]"

    status_text = (
        f"[bold green]Authenticated[/bold green]\n\n"
        f"{auth_info}\n"
        f"  [bold]Cloud:[/bold] {cloud_status}\n"
        f"  [bold]URL:[/bold]   {AIP_CLOUD_URL}\n"
        f"  [bold]File:[/bold]  ~/.aip/credentials.json"
    )
    console.print(Panel.fit(status_text, title="AIP Status", border_style="green"))


# ═══════════════════════════════════════════════════════════════════════════
#  aip watch — Live stream verification events (requires AIP Cloud)
# ═══════════════════════════════════════════════════════════════════════════

@cli.command("watch")
@click.option("--agent-id", "-a", default=None, help="Filter by agent ID")
@click.option("--tail", "-n", default=20, type=int, help="Number of recent events to show")
def watch_cmd(agent_id, tail):
    """Stream live verification events from AIP Cloud."""
    creds = _load_credentials()

    if creds is None:
        console.print("[red]Not authenticated.[/red] Run [cyan]aip login[/cyan] first.")
        sys.exit(1)

    # Build auth header
    if creds.get("type") == "api_key":
        auth_header = f"Bearer {creds['api_key']}"
    else:
        auth_header = f"Bearer {creds['token']}"

    watch_text = (
        "[bold]Streaming verification events...[/bold]\n\n"
        f"  Cloud:    {AIP_CLOUD_URL}\n"
        f"  Agent:    {agent_id or 'all agents'}\n"
        f"  Tail:     {tail} events\n\n"
        "  Press [bold]Ctrl+C[/bold] to stop"
    )
    console.print()
    console.print(Panel.fit(watch_text, title="🔍 AIP Watch", border_style="cyan"))

    # Fetch recent verifications
    try:
        import urllib.request
        url = f"{AIP_CLOUD_URL}/api/verifications?limit={tail}"
        if agent_id:
            url += f"&agent_id={agent_id}"

        req = urllib.request.Request(url, headers={
            "Authorization": auth_header,
            "User-Agent": "aip-cli/0.2.0",
        })

        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())

        verifications = data.get("verifications", [])

        if not verifications:
            console.print()
            console.print("[dim]No verification events yet. Run your agents to see activity.[/dim]")
        else:
            table = Table(title=f"Recent Verifications ({len(verifications)})", border_style="dim")
            table.add_column("Time", style="dim", width=20)
            table.add_column("Agent", style="cyan", width=30)
            table.add_column("Action", width=20)
            table.add_column("Result", width=10)
            table.add_column("Detail", style="dim")

            for v in verifications:
                ts = v.get("created_at", v.get("timestamp", ""))[:19]
                agent = v.get("agent_id", "unknown")[:28]
                action = v.get("action", "unknown")
                passed = v.get("passed", v.get("result", ""))
                detail = v.get("detail", "")

                if isinstance(passed, bool):
                    status = "[green]✓ PASS[/green]" if passed else "[red]✗ FAIL[/red]"
                else:
                    status = str(passed)

                table.add_row(ts, agent, action, status, detail[:40])

            console.print()
            console.print(table)

        # Polling loop
        console.print()
        console.print("[dim]Polling for new events every 3s... (Ctrl+C to stop)[/dim]")
        seen = {v.get("id", i) for i, v in enumerate(verifications)}

        while True:
            time.sleep(3)
            try:
                with urllib.request.urlopen(req, timeout=5) as resp:
                    data = json.loads(resp.read().decode())

                for v in data.get("verifications", []):
                    vid = v.get("id", "")
                    if vid not in seen:
                        seen.add(vid)
                        ts = v.get("created_at", "")[:19]
                        agent = v.get("agent_id", "unknown")[:28]
                        action = v.get("action", "unknown")
                        passed = v.get("passed", "")
                        status = "[green]✓[/green]" if passed else "[red]✗[/red]"
                        console.print(f"  {status} {ts}  {agent}  {action}")
            except Exception:
                pass  # Silent retry

    except urllib.error.HTTPError as e:
        if e.code == 401:
            console.print()
            console.print("[red]Authentication failed.[/red] Run [cyan]aip login[/cyan] to refresh.")
        else:
            console.print(f"[red]HTTP Error {e.code}[/red]: {e.reason}")
        sys.exit(1)
    except KeyboardInterrupt:
        console.print()
        console.print("[dim]Stopped watching.[/dim]")
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        console.print("[dim]Make sure you're authenticated: aip login[/dim]")
        sys.exit(1)


if __name__ == "__main__":
    cli()
