"""
AIP CLI — Command-line interface for the Agent Intent Protocol.

Commands:
  aip create-passport   Create a new agent passport
  aip sign-intent       Create and sign an intent envelope
  aip verify            Verify a signed intent envelope
  aip revoke            Revoke an agent identity
  aip inspect           Inspect an envelope or passport
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import print as rprint

from aip_protocol.passport import AgentPassport
from aip_protocol.envelope import create_envelope, sign_envelope, envelope_to_json, envelope_from_json
from aip_protocol.verification import verify_intent
from aip_protocol.crypto import load_public_key, public_key_to_b64
from aip_protocol.revocation import RevocationStore
from aip_protocol.errors import AIPErrorCode

console = Console()

# Global revocation store (in-memory for CLI usage)
_store = RevocationStore()


@click.group()
@click.version_option(version="0.1.0", prog_name="aip")
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


if __name__ == "__main__":
    cli()
