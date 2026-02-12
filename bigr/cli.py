"""CLI interface for BİGR Discovery."""

from __future__ import annotations

import json
import os
import signal
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from bigr.classifier.bigr_mapper import classify_assets
from bigr.config import load_config, parse_interval
from bigr.db import (
    add_subnet,
    get_all_assets,
    get_latest_scan,
    get_scan_list,
    get_subnets,
    get_tags,
    init_db,
    remove_subnet,
    save_scan,
    tag_asset,
    untag_asset,
    update_subnet_stats,
)
from bigr.diff import diff_scans, get_changes_from_db
from bigr.models import BigrCategory, ScanResult
from bigr.output import write_csv, write_json
from bigr.scanner.active import is_root
from bigr.scanner.hybrid import run_hybrid_scan
from bigr.watcher import WatcherDaemon, get_watcher_status

app = typer.Typer(
    name="bigr",
    help="BİGR Discovery - Asset Discovery & Classification Agent",
    no_args_is_help=True,
)
console = Console()


@app.command()
def scan(
    targets: list[str] = typer.Argument(None, help="Target subnet(s) in CIDR notation (e.g., 192.168.1.0/24)"),
    scan_all: bool = typer.Option(False, "--all", help="Scan all registered subnets from DB"),
    mode: str = typer.Option("hybrid", "--mode", "-m", help="Scan mode: passive, active, or hybrid"),
    ports: Optional[str] = typer.Option(None, "--ports", "-p", help="Comma-separated port list"),
    timeout: float = typer.Option(2.0, "--timeout", "-t", help="Per-port scan timeout in seconds"),
    output: str = typer.Option("assets.json", "--output", "-o", help="Output file path"),
    fmt: str = typer.Option("json", "--format", "-f", help="Output format: json or csv"),
    diff: bool = typer.Option(True, "--diff/--no-diff", help="Show diff against previous scan"),
    db_path: Optional[str] = typer.Option(None, "--db-path", hidden=True, help="Database path (for testing)"),
) -> None:
    """Scan network for assets and classify them per BİGR guidelines."""
    resolved_db = Path(db_path) if db_path else None

    # Build target list
    target_list: list[str] = []
    if scan_all:
        registered = get_subnets(db_path=resolved_db)
        if not registered:
            console.print("[yellow]No registered subnets.[/yellow] Use 'bigr subnets add' first.")
            raise typer.Exit(1)
        target_list = [s["cidr"] for s in registered]
    elif targets:
        target_list = list(targets)
    else:
        console.print("[red]Error:[/red] Provide target subnet(s) or use --all.")
        raise typer.Exit(1)

    # Parse ports if provided
    port_list = None
    if ports:
        port_list = [int(p.strip()) for p in ports.split(",")]

    # Root check warning
    if not is_root() and mode in ("active", "hybrid"):
        console.print(
            "[yellow]Warning:[/yellow] Not running as root. "
            "Active scanning (ARP sweep) will be skipped. "
            "Running in passive mode with port scanning.",
        )

    total_assets = 0
    last_result: ScanResult | None = None

    for target in target_list:
        # Load previous scan for diffing (before we save the new one)
        previous_scan = None
        if diff:
            try:
                previous_scan = get_latest_scan(target=target, db_path=resolved_db)
            except Exception:
                pass

        # Run scan
        with console.status(f"[bold green]Scanning {target}..."):
            result = run_hybrid_scan(target, mode=mode, ports=port_list, timeout=timeout)

        # Classify
        with console.status("[bold blue]Classifying assets..."):
            classify_assets(result.assets, do_fingerprint=True)

        # Persist to database
        try:
            scan_id = save_scan(result, db_path=resolved_db)
            console.print(f"[dim]Saved to database (scan {scan_id[:8]}...)[/dim]")
        except Exception as exc:
            console.print(f"[yellow]Warning:[/yellow] Could not save to database: {exc}")

        # Update subnet stats if registered
        try:
            update_subnet_stats(target, asset_count=len(result.assets), db_path=resolved_db)
        except Exception:
            pass

        total_assets += len(result.assets)
        last_result = result

        # Show diff against previous scan
        if diff and previous_scan and previous_scan.get("assets"):
            current_assets = [a.to_dict() for a in result.assets]
            diff_result = diff_scans(current_assets, previous_scan["assets"])
            if diff_result.has_changes:
                _print_diff(diff_result)
            else:
                console.print(f"\n[dim]No changes since last scan for {target}.[/dim]")

    # Output last result (or combined if needed)
    if last_result is not None:
        if fmt == "csv":
            out_path = write_csv(last_result, path=output.replace(".json", ".csv") if output == "assets.json" else output)
        else:
            out_path = write_json(last_result, path=output)

        console.print(f"\n[green]Scan complete![/green] Found [bold]{total_assets}[/bold] assets.")
        console.print(f"Results saved to: [bold]{out_path}[/bold]")

        if last_result.duration_seconds is not None:
            console.print(f"Duration: {last_result.duration_seconds:.1f}s | Root: {'Yes' if last_result.is_root else 'No'}")

        # Show summary table for the last result
        _print_summary(last_result)


@app.command()
def report(
    input_file: str = typer.Option("assets.json", "--input", "-i", help="Input scan result file"),
    fmt: str = typer.Option("summary", "--format", "-f",
                            help="Report format: summary, detailed, bigr-matrix, html-report"),
    output: str = typer.Option("", "--output", "-o", help="Output file path (for html-report)"),
) -> None:
    """Generate report from existing scan results."""
    path = Path(input_file)
    if not path.exists():
        console.print(f"[red]Error:[/red] File not found: {input_file}")
        raise typer.Exit(1)

    with path.open(encoding="utf-8") as f:
        data = json.load(f)

    if fmt == "html-report":
        from bigr.report.generator import ReportConfig, build_full_report

        assets = data.get("assets", [])
        category_summary = data.get("category_summary", {})
        total_assets = data.get("total_assets", len(assets))

        # Build compliance data from scan result
        total_classified = sum(
            v for k, v in category_summary.items() if k != "unclassified"
        )
        total_unclassified = category_summary.get("unclassified", 0)
        # Simple compliance score: % classified
        score = (total_classified / total_assets * 100) if total_assets > 0 else 0
        grade = _score_to_grade(score)

        compliance_data = {
            "score": round(score, 1),
            "grade": grade,
            "scan_date": data.get("started_at", ""),
            "category_distribution": category_summary,
            "total_classified": total_classified,
            "total_unclassified": total_unclassified,
        }

        config = ReportConfig()
        generated = build_full_report(assets, compliance_data, config=config)

        # Determine output path
        out_path = output if output else str(path.with_suffix(".html"))
        generated.save(out_path)
        console.print(f"[green]HTML report saved:[/green] {out_path}")
    elif fmt == "detailed":
        _print_detailed(data)
    elif fmt == "bigr-matrix":
        _print_bigr_matrix(data)
    else:
        _print_summary_from_data(data)


@app.command()
def serve(
    port: int = typer.Option(9978, "--port", "-p", help="Dashboard port"),
    host: str = typer.Option("127.0.0.1", "--host", help="Dashboard host"),
    data: str = typer.Option("assets.json", "--data", "-d", help="Scan result file to display"),
) -> None:
    """Launch web dashboard to view scan results."""
    try:
        from bigr.dashboard.app import create_app
    except ImportError:
        console.print("[red]Error:[/red] Dashboard dependencies not available.")
        raise typer.Exit(1)

    path = Path(data)
    if not path.exists():
        console.print(f"[red]Error:[/red] No scan data found at {data}. Run 'bigr scan' first.")
        raise typer.Exit(1)

    import uvicorn

    dashboard_app = create_app(data_path=str(path))
    console.print(f"[green]Dashboard starting at http://{host}:{port}[/green]")
    uvicorn.run(dashboard_app, host=host, port=port, log_level="warning")


@app.command()
def history(
    limit: int = typer.Option(20, "--limit", "-l", help="Number of recent scans to show"),
) -> None:
    """Show recent scan history from the database."""
    scans = get_scan_list(limit=limit)
    if not scans:
        console.print("[yellow]No scan history found.[/yellow] Run 'bigr scan' first.")
        return

    table = Table(title="\nScan History")
    table.add_column("#", justify="right", style="dim")
    table.add_column("Target", style="cyan")
    table.add_column("Date", style="green")
    table.add_column("Assets", justify="right")
    table.add_column("Mode")
    table.add_column("Duration", justify="right")
    table.add_column("Root")

    for i, scan in enumerate(scans, 1):
        # Parse duration
        duration_str = "-"
        if scan.get("completed_at") and scan.get("started_at"):
            from datetime import datetime
            started = datetime.fromisoformat(scan["started_at"])
            completed = datetime.fromisoformat(scan["completed_at"])
            dur = (completed - started).total_seconds()
            duration_str = f"{dur:.1f}s"

        # Parse date
        date_str = scan.get("started_at", "-")
        if date_str and date_str != "-":
            date_str = date_str[:19].replace("T", " ")

        table.add_row(
            str(i),
            scan.get("target", "-"),
            date_str,
            str(scan.get("total_assets", 0)),
            scan.get("scan_method", "-"),
            duration_str,
            "Yes" if scan.get("is_root") else "No",
        )

    console.print(table)


# Valid categories for manual tagging (excludes 'unclassified')
_VALID_TAG_CATEGORIES = [c.value for c in BigrCategory if c != BigrCategory.UNCLASSIFIED]


@app.command()
def tag(
    ip: str = typer.Argument(..., help="IP address of the asset to tag"),
    category: str = typer.Option(..., "--category", "-c", help="BİGR category override"),
    note: Optional[str] = typer.Option(None, "--note", "-n", help="Optional note for the override"),
) -> None:
    """Apply a manual BİGR category override to an asset."""
    # Validate category
    if category not in _VALID_TAG_CATEGORIES:
        console.print(
            f"[red]Error:[/red] Invalid category '{category}'. "
            f"Valid options: {', '.join(_VALID_TAG_CATEGORIES)}"
        )
        raise typer.Exit(1)

    tag_asset(ip, category, note=note)
    console.print(f"[green]Tagged[/green] {ip} → [bold]{category}[/bold]")
    if note:
        console.print(f"  Note: {note}")


@app.command()
def untag(
    ip: str = typer.Argument(..., help="IP address of the asset to untag"),
) -> None:
    """Remove manual BİGR category override from an asset."""
    untag_asset(ip)
    console.print(f"[green]Untagged[/green] {ip} — manual override removed.")


@app.command()
def tags() -> None:
    """List all manual category overrides."""
    tag_list = get_tags()
    if not tag_list:
        console.print("[yellow]No manual overrides found.[/yellow]")
        return

    table = Table(title="\nManual Category Overrides")
    table.add_column("IP", style="cyan")
    table.add_column("MAC")
    table.add_column("Hostname")
    table.add_column("Manual Category", style="bold magenta")
    table.add_column("Note")

    for t in tag_list:
        table.add_row(
            t.get("ip", "-"),
            t.get("mac") or "-",
            t.get("hostname") or "-",
            t.get("manual_category", "-"),
            t.get("manual_note") or "-",
        )

    console.print(table)


@app.command()
def changes(
    limit: int = typer.Option(50, "--limit", "-l", help="Number of recent changes to show"),
) -> None:
    """Show recent asset changes from the database."""
    change_list = get_changes_from_db(limit=limit)
    if not change_list:
        console.print("[yellow]No asset changes found.[/yellow] Run 'bigr scan' at least twice.")
        return

    table = Table(title="\nRecent Asset Changes")
    table.add_column("Timestamp", style="dim")
    table.add_column("IP", style="cyan")
    table.add_column("Change Type")
    table.add_column("Field")
    table.add_column("Old Value")
    table.add_column("New Value")

    _change_type_styles = {
        "new_asset": "green",
        "field_changed": "yellow",
    }

    for change in change_list:
        change_type = change.get("change_type", "-")
        style = _change_type_styles.get(change_type, "white")

        # Format timestamp: trim to seconds
        ts = change.get("detected_at", "-")
        if ts and ts != "-":
            ts = ts[:19].replace("T", " ")

        old_val = change.get("old_value") or "-"
        new_val = change.get("new_value") or "-"
        field_name = change.get("field_name") or "-"

        if change_type == "new_asset":
            field_name = "-"
            old_val = "-"
            new_val = "-"

        table.add_row(
            ts,
            change.get("ip", "-"),
            f"[{style}]{change_type}[/{style}]",
            field_name,
            old_val,
            new_val,
        )

    console.print(table)


@app.command()
def watch(
    target: Optional[str] = typer.Argument(None, help="Target subnet in CIDR notation (e.g., 192.168.1.0/24)"),
    interval: str = typer.Option("5m", "--interval", "-i", help="Scan interval (e.g., 5m, 2h, 30s)"),
    config: bool = typer.Option(False, "--config", help="Watch all targets from config file"),
    stop: bool = typer.Option(False, "--stop", help="Stop running watcher"),
    status: bool = typer.Option(False, "--status", help="Check watcher status"),
) -> None:
    """Watch network targets with periodic scans."""
    # --status: check if watcher is running
    if status:
        watcher_status = get_watcher_status()
        if watcher_status.is_running:
            console.print(
                f"[green]Watcher is running[/green] (PID {watcher_status.pid})."
            )
        else:
            console.print("[yellow]Watcher is not running.[/yellow]")
        return

    # --stop: stop running watcher
    if stop:
        watcher_status = get_watcher_status()
        if not watcher_status.is_running:
            console.print("[yellow]No watcher is currently running.[/yellow]")
            return

        try:
            os.kill(watcher_status.pid, signal.SIGTERM)
            console.print(
                f"[green]Stopped watcher[/green] (PID {watcher_status.pid})."
            )
        except OSError as exc:
            console.print(f"[red]Error stopping watcher:[/red] {exc}")
        return

    # Build target list
    targets: list[dict] = []

    if config:
        # Load from config file
        cfg = load_config()
        if not cfg.targets:
            console.print("[yellow]No targets in config.[/yellow] Add targets to ~/.bigr/config.yaml")
            return
        for t in cfg.targets:
            targets.append({
                "subnet": t.subnet,
                "interval_seconds": parse_interval(t.interval),
            })
    elif target:
        # Single target from argument
        targets.append({
            "subnet": target,
            "interval_seconds": parse_interval(interval),
        })
    else:
        console.print("[red]Error:[/red] Provide a target subnet or use --config.")
        raise typer.Exit(1)

    # Start watcher
    console.print(f"[green]Starting watcher[/green] for {len(targets)} target(s)...")
    for t in targets:
        console.print(f"  - {t['subnet']} (every {t['interval_seconds']}s)")

    watcher = WatcherDaemon(targets=targets)
    try:
        watcher.start()
    except RuntimeError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(1)
    except KeyboardInterrupt:
        console.print("\n[yellow]Watcher stopped.[/yellow]")


# ---------------------------------------------------------------------------
# Subnets sub-app
# ---------------------------------------------------------------------------

subnets_app = typer.Typer(help="Manage network subnets")
app.add_typer(subnets_app, name="subnets")


@subnets_app.command("add")
def subnets_add(
    cidr: str = typer.Argument(..., help="Subnet in CIDR notation (e.g., 10.0.0.0/24)"),
    label: str = typer.Option("", "--label", "-l", help="Friendly label for the subnet"),
    vlan: Optional[int] = typer.Option(None, "--vlan", "-v", help="VLAN ID"),
    db_path_opt: Optional[str] = typer.Option(None, "--db-path", hidden=True, help="Database path (for testing)"),
) -> None:
    """Register a network subnet."""
    resolved_db = Path(db_path_opt) if db_path_opt else None
    add_subnet(cidr, label=label, vlan_id=vlan, db_path=resolved_db)
    vlan_str = f" (VLAN {vlan})" if vlan else ""
    console.print(f"[green]Added[/green] subnet {cidr}{vlan_str}")
    if label:
        console.print(f"  Label: {label}")


@subnets_app.command("remove")
def subnets_remove(
    cidr: str = typer.Argument(..., help="Subnet CIDR to remove"),
    db_path_opt: Optional[str] = typer.Option(None, "--db-path", hidden=True, help="Database path (for testing)"),
) -> None:
    """Remove a registered subnet."""
    resolved_db = Path(db_path_opt) if db_path_opt else None
    remove_subnet(cidr, db_path=resolved_db)
    console.print(f"[green]Removed[/green] subnet {cidr}")


@subnets_app.command("list")
def subnets_list(
    db_path_opt: Optional[str] = typer.Option(None, "--db-path", hidden=True, help="Database path (for testing)"),
) -> None:
    """List all registered subnets."""
    resolved_db = Path(db_path_opt) if db_path_opt else None
    subnet_list = get_subnets(db_path=resolved_db)
    if not subnet_list:
        console.print("[yellow]No subnets registered.[/yellow] Use 'bigr subnets add' to register one.")
        return

    table = Table(title="\nRegistered Subnets")
    table.add_column("CIDR", style="cyan")
    table.add_column("Label")
    table.add_column("VLAN", justify="right")
    table.add_column("Assets", justify="right")
    table.add_column("Last Scanned")

    for s in subnet_list:
        vlan_str = str(s["vlan_id"]) if s.get("vlan_id") is not None else "-"
        last_scanned = s.get("last_scanned") or "-"
        if last_scanned != "-":
            last_scanned = last_scanned[:19].replace("T", " ")
        table.add_row(
            s["cidr"],
            s.get("label") or "-",
            vlan_str,
            str(s.get("asset_count", 0)),
            last_scanned,
        )

    console.print(table)


# ---------------------------------------------------------------------------
# SNMP sub-app
# ---------------------------------------------------------------------------

snmp_app = typer.Typer(help="Manage SNMP switches")
app.add_typer(snmp_app, name="snmp")


@snmp_app.command("add")
def snmp_add(
    host: str = typer.Argument(..., help="Switch IP address or hostname"),
    community: str = typer.Option("public", "--community", "-c", help="SNMP community string"),
    label: str = typer.Option("", "--label", "-l", help="Friendly label"),
    snmp_version: str = typer.Option("2c", "--version", "-v", help="SNMP version (2c or 3)"),
    db_path_opt: Optional[str] = typer.Option(None, "--db-path", hidden=True, help="Database path (for testing)"),
) -> None:
    """Register an SNMP-managed switch."""
    from bigr.scanner.snmp import SwitchConfig
    from bigr.scanner.switch_map import save_switch

    resolved_db = Path(db_path_opt) if db_path_opt else None
    config = SwitchConfig(host=host, community=community, version=snmp_version, label=label)
    save_switch(config, db_path=resolved_db)
    console.print(f"[green]Added[/green] switch {host}")
    if label:
        console.print(f"  Label: {label}")


@snmp_app.command("remove")
def snmp_remove(
    host: str = typer.Argument(..., help="Switch IP address or hostname to remove"),
    db_path_opt: Optional[str] = typer.Option(None, "--db-path", hidden=True, help="Database path (for testing)"),
) -> None:
    """Remove a registered switch."""
    from bigr.scanner.switch_map import remove_switch

    resolved_db = Path(db_path_opt) if db_path_opt else None
    remove_switch(host, db_path=resolved_db)
    console.print(f"[green]Removed[/green] switch {host}")


@snmp_app.command("list")
def snmp_list(
    db_path_opt: Optional[str] = typer.Option(None, "--db-path", hidden=True, help="Database path (for testing)"),
) -> None:
    """List all registered switches."""
    from bigr.scanner.switch_map import get_switches

    resolved_db = Path(db_path_opt) if db_path_opt else None
    switch_list = get_switches(db_path=resolved_db)
    if not switch_list:
        console.print("[yellow]No switches registered.[/yellow] Use 'bigr snmp add' to register one.")
        return

    table = Table(title="\nRegistered Switches")
    table.add_column("Host", style="cyan")
    table.add_column("Label")
    table.add_column("Community")
    table.add_column("Version")
    table.add_column("MACs", justify="right")
    table.add_column("Last Polled")

    for s in switch_list:
        last_polled = s.get("last_polled") or "-"
        if last_polled != "-":
            last_polled = last_polled[:19].replace("T", " ")
        table.add_row(
            s["host"],
            s.get("label") or "-",
            s.get("community", "public"),
            s.get("version", "2c"),
            str(s.get("mac_count", 0)),
            last_polled,
        )

    console.print(table)


@snmp_app.command("scan")
def snmp_scan(
    db_path_opt: Optional[str] = typer.Option(None, "--db-path", hidden=True, help="Database path (for testing)"),
) -> None:
    """Scan all registered switches for MAC tables."""
    from bigr.scanner.switch_map import get_switches, scan_all_switches

    resolved_db = Path(db_path_opt) if db_path_opt else None
    switch_list = get_switches(db_path=resolved_db)
    if not switch_list:
        console.print("[yellow]No switches registered.[/yellow] Use 'bigr snmp add' first.")
        return

    console.print(f"[bold]Scanning {len(switch_list)} switch(es)...[/bold]")

    with console.status("[bold green]Reading MAC tables..."):
        entries = scan_all_switches(db_path=resolved_db)

    console.print(f"[green]Scan complete![/green] Found [bold]{len(entries)}[/bold] MAC entries.")

    if entries:
        table = Table(title="\nMAC Table Summary")
        table.add_column("MAC", style="cyan")
        table.add_column("Switch")
        table.add_column("Port")
        table.add_column("Port Index", justify="right")

        for entry in entries[:50]:  # Show first 50
            table.add_row(
                entry.mac,
                f"{entry.switch_label or entry.switch_host}",
                entry.port_name,
                str(entry.port_index),
            )

        console.print(table)
        if len(entries) > 50:
            console.print(f"[dim]... and {len(entries) - 50} more entries.[/dim]")


# ---------------------------------------------------------------------------
# Certs sub-app
# ---------------------------------------------------------------------------

certs_app = typer.Typer(help="TLS certificate discovery and monitoring")
app.add_typer(certs_app, name="certs")


@certs_app.command("scan")
def certs_scan(
    host: Optional[str] = typer.Argument(None, help="Specific host IP to scan (default: all known assets)"),
    db_path_opt: Optional[str] = typer.Option(None, "--db-path", hidden=True, help="Database path (for testing)"),
) -> None:
    """Scan assets for TLS certificates. Optionally specify a single host."""
    from bigr.db import get_all_assets, save_certificate
    from bigr.scanner.tls import scan_host_certificates

    resolved_db = Path(db_path_opt) if db_path_opt else None

    # Build IP list: single host or all known assets
    if host:
        ip_list = [host]
    else:
        all_assets = get_all_assets(db_path=resolved_db)
        if not all_assets:
            console.print("[yellow]No assets found.[/yellow] Run 'bigr scan' first.")
            return
        ip_list = [a.get("ip", "") for a in all_assets if a.get("ip")]

    console.print(f"[bold]Scanning {len(ip_list)} host(s) for TLS certificates...[/bold]")

    total_found = 0
    for ip in ip_list:
        with console.status(f"[bold green]Checking {ip}..."):
            certs = scan_host_certificates(ip)
        for cert in certs:
            save_certificate(cert, db_path=resolved_db)
            total_found += 1

    console.print(f"[green]Scan complete![/green] Found [bold]{total_found}[/bold] certificate(s).")


@certs_app.command("list")
def certs_list(
    db_path_opt: Optional[str] = typer.Option(None, "--db-path", hidden=True, help="Database path (for testing)"),
) -> None:
    """List all discovered TLS certificates."""
    from bigr.db import get_certificates

    resolved_db = Path(db_path_opt) if db_path_opt else None
    cert_list = get_certificates(db_path=resolved_db)

    if not cert_list:
        console.print("[yellow]No certificates found.[/yellow] Run 'bigr certs scan' first.")
        return

    table = Table(title="\nTLS Certificates")
    table.add_column("IP", style="cyan")
    table.add_column("Port", justify="right")
    table.add_column("CN")
    table.add_column("Issuer")
    table.add_column("Valid To")
    table.add_column("Days Left", justify="right")
    table.add_column("Self-Signed")
    table.add_column("Key Size", justify="right")

    for c in cert_list:
        days = c.get("days_until_expiry")
        days_str = str(days) if days is not None else "-"
        if days is not None and days <= 30:
            days_str = f"[red]{days}[/red]"
        elif days is not None and days <= 7:
            days_str = f"[red bold]{days}[/red bold]"

        valid_to = c.get("valid_to") or "-"
        if valid_to != "-":
            valid_to = valid_to[:10]

        table.add_row(
            c.get("ip", "-"),
            str(c.get("port", "-")),
            c.get("cn") or "-",
            c.get("issuer") or "-",
            valid_to,
            days_str,
            "Yes" if c.get("is_self_signed") else "No",
            str(c.get("key_size") or "-"),
        )

    console.print(table)


@certs_app.command("expiring")
def certs_expiring(
    days: int = typer.Option(30, "--days", "-d", help="Days until expiry threshold"),
    db_path_opt: Optional[str] = typer.Option(None, "--db-path", hidden=True, help="Database path (for testing)"),
) -> None:
    """Show certificates expiring within N days."""
    from bigr.db import get_expiring_certificates

    resolved_db = Path(db_path_opt) if db_path_opt else None
    cert_list = get_expiring_certificates(days=days, db_path=resolved_db)

    if not cert_list:
        console.print(f"[green]No certificates expiring within {days} days.[/green]")
        return

    table = Table(title=f"\nCertificates Expiring Within {days} Days")
    table.add_column("IP", style="cyan")
    table.add_column("Port", justify="right")
    table.add_column("CN")
    table.add_column("Issuer")
    table.add_column("Days Left", justify="right")
    table.add_column("Status")

    for c in cert_list:
        d = c.get("days_until_expiry")
        if d is not None and d < 0:
            status = "[red bold]EXPIRED[/red bold]"
            days_str = f"[red bold]{d}[/red bold]"
        elif d is not None and d <= 7:
            status = "[red]CRITICAL[/red]"
            days_str = f"[red]{d}[/red]"
        else:
            status = "[yellow]WARNING[/yellow]"
            days_str = f"[yellow]{d}[/yellow]"

        table.add_row(
            c.get("ip", "-"),
            str(c.get("port", "-")),
            c.get("cn") or "-",
            c.get("issuer") or "-",
            days_str,
            status,
        )

    console.print(table)


@app.command()
def compliance(
    fmt: str = typer.Option("summary", "--format", "-f", help="Output format: summary, detailed, json"),
    db_path: Optional[str] = typer.Option(None, "--db-path", hidden=True, help="Database path (for testing)"),
) -> None:
    """Show BİGR compliance score and breakdown."""
    from bigr.compliance import calculate_compliance, calculate_subnet_compliance

    resolved_db = Path(db_path) if db_path else None

    # Load all assets from the database
    all_assets = get_all_assets(db_path=resolved_db)

    # Convert to compliance-friendly dicts
    asset_dicts = []
    for a in all_assets:
        asset_dicts.append({
            "ip": a.get("ip", ""),
            "mac": a.get("mac"),
            "hostname": a.get("hostname"),
            "vendor": a.get("vendor"),
            "confidence_score": a.get("confidence_score", 0.0),
            "bigr_category": a.get("bigr_category", "unclassified"),
            "manual_category": a.get("manual_category"),
        })

    report = calculate_compliance(asset_dicts)

    # Get subnets and calculate per-subnet compliance
    subnets = get_subnets(db_path=resolved_db)
    if subnets:
        report.subnet_compliance = calculate_subnet_compliance(asset_dicts, subnets)

    if fmt == "json":
        console.print(json.dumps(report.to_dict(), indent=2))
        return

    # Summary format
    score = report.breakdown.compliance_score
    grade = report.breakdown.grade
    grade_colors = {"A": "green", "B": "blue", "C": "yellow", "D": "red", "F": "red bold"}
    grade_color = grade_colors.get(grade, "white")

    console.print(f"\n[bold]BİGR Compliance Report[/bold]")
    console.print(f"  Score: [{grade_color}]{score}%[/{grade_color}]  Grade: [{grade_color}]{grade}[/{grade_color}]")
    console.print()

    # Breakdown
    b = report.breakdown
    table = Table(title="Classification Breakdown")
    table.add_column("Category", style="bold")
    table.add_column("Count", justify="right")
    table.add_row("[green]Fully Classified[/green]", str(b.fully_classified))
    table.add_row("[yellow]Partially Classified[/yellow]", str(b.partially_classified))
    table.add_row("[red]Unclassified[/red]", str(b.unclassified))
    table.add_row("[cyan]Manual Overrides[/cyan]", str(b.manual_overrides))
    table.add_row("[bold]Total[/bold]", str(b.total_assets))
    console.print(table)

    # Distribution
    dist = report.distribution
    if dist.total > 0:
        console.print()
        dist_table = Table(title="Category Distribution")
        dist_table.add_column("Category", style="bold")
        dist_table.add_column("Count", justify="right")
        dist_table.add_column("Percentage", justify="right")
        pct = dist.percentages()
        labels = {
            "ag_ve_sistemler": "Ag ve Sistemler",
            "uygulamalar": "Uygulamalar",
            "iot": "IoT",
            "tasinabilir": "Tasinabilir",
            "unclassified": "Siniflandirilmamis",
        }
        for key, label in labels.items():
            count = getattr(dist, key)
            if count > 0:
                dist_table.add_row(label, str(count), f"{pct[key]}%")
        console.print(dist_table)

    # Action items
    if report.action_items:
        console.print()
        action_table = Table(title="Action Items")
        action_table.add_column("Priority", style="bold")
        action_table.add_column("Type")
        action_table.add_column("IP", style="cyan")
        action_table.add_column("Reason")
        for item in report.action_items[:20]:
            pri = item["priority"]
            pri_style = {"critical": "red", "high": "yellow", "normal": "dim"}.get(pri, "white")
            action_table.add_row(
                f"[{pri_style}]{pri}[/{pri_style}]",
                item["type"],
                item["ip"],
                item["reason"],
            )
        console.print(action_table)


@app.command()
def analytics(
    days: int = typer.Option(30, "--days", "-d", help="Lookback period in days"),
    fmt: str = typer.Option("summary", "--format", "-f", help="Output format: summary, json"),
    db_path: Optional[str] = typer.Option(None, "--db-path", hidden=True, help="Database path (for testing)"),
) -> None:
    """Show historical trends and analytics."""
    from bigr.analytics import get_full_analytics

    resolved_db = Path(db_path) if db_path else None
    result = get_full_analytics(days=days, db_path=resolved_db)

    if fmt == "json":
        console.print(json.dumps(result.to_dict(), indent=2, default=str))
        return

    # Summary format
    console.print("\n[bold]BIGR Analytics[/bold]")
    console.print(f"Period: last {days} days\n")

    # Asset count trend
    if result.asset_count_trend and result.asset_count_trend.points:
        table = Table(title="Asset Count Trend")
        table.add_column("Date", style="cyan")
        table.add_column("Assets", justify="right")
        for pt in result.asset_count_trend.points:
            table.add_row(pt.date, str(pt.value))
        console.print(table)
    else:
        console.print("[dim]No asset count data available.[/dim]")

    # Category trends
    if result.category_trends:
        table = Table(title="\nCategory Trends")
        table.add_column("Category", style="bold")
        table.add_column("Total", justify="right")
        for series in result.category_trends:
            total = sum(p.value for p in series.points)
            table.add_row(series.name, str(total))
        console.print(table)

    # Most changed assets
    if result.most_changed_assets:
        table = Table(title="\nMost Changed Assets")
        table.add_column("IP", style="cyan")
        table.add_column("Changes", justify="right")
        table.add_column("Last Change")
        for asset in result.most_changed_assets[:10]:
            table.add_row(
                asset.get("ip", "-"),
                str(asset.get("change_count", 0)),
                (asset.get("last_change") or "-")[:19].replace("T", " "),
            )
        console.print(table)

    # Scan frequency
    if result.scan_frequency:
        table = Table(title="\nScan Frequency")
        table.add_column("Date", style="cyan")
        table.add_column("Scans", justify="right")
        table.add_column("Total Assets", justify="right")
        for entry in result.scan_frequency:
            table.add_row(
                entry.get("date", "-"),
                str(entry.get("scan_count", 0)),
                str(entry.get("total_assets", 0)),
            )
        console.print(table)


@app.command()
def risk(
    fmt: str = typer.Option("summary", "--format", "-f", help="Output: summary, json, top10"),
    db_path: Optional[str] = typer.Option(None, "--db-path", hidden=True, help="Database path (for testing)"),
) -> None:
    """Assess network risk and show top risky assets."""
    from bigr.risk.scorer import assess_network_risk

    resolved_db = Path(db_path) if db_path else None
    all_assets = get_all_assets(db_path=resolved_db)

    # Build asset dicts
    asset_dicts = []
    for a in all_assets:
        asset_dicts.append({
            "ip": a.get("ip", ""),
            "mac": a.get("mac"),
            "hostname": a.get("hostname"),
            "vendor": a.get("vendor"),
            "bigr_category": a.get("bigr_category", "unclassified"),
            "confidence_score": a.get("confidence_score", 0.0),
            "open_ports": a.get("open_ports", []),
            "first_seen": a.get("first_seen"),
        })

    # Integrate CVE vulnerability data into risk assessment
    vuln_summaries = None
    try:
        from bigr.vuln.cve_db import init_cve_db
        from bigr.vuln.matcher import scan_all_vulnerabilities

        init_cve_db()
        vuln_results = scan_all_vulnerabilities(asset_dicts)
        if vuln_results:
            vuln_summaries = [
                {"ip": s.ip, "max_cvss": s.max_cvss, "top_cve": s.top_cve}
                for s in vuln_results
            ]
    except Exception:
        pass  # CVE DB not seeded yet, proceed without

    report = assess_network_risk(asset_dicts, vuln_summaries=vuln_summaries)

    if fmt == "json":
        console.print(json.dumps(report.to_dict(), indent=2))
        return

    if fmt == "top10":
        table = Table(title="\nTop 10 Riskiest Assets")
        table.add_column("IP", style="cyan")
        table.add_column("Vendor")
        table.add_column("Category")
        table.add_column("Risk Score", justify="right")
        table.add_column("Risk Level")
        table.add_column("Top CVE")

        level_styles = {
            "critical": "red bold",
            "high": "red",
            "medium": "yellow",
            "low": "green",
            "info": "dim",
        }

        for p in report.top_risks:
            style = level_styles.get(p.risk_level, "white")
            table.add_row(
                p.ip,
                p.vendor or "-",
                p.bigr_category,
                f"[{style}]{p.risk_score:.1f}[/{style}]",
                f"[{style}]{p.risk_level.upper()}[/{style}]",
                p.top_cve or "-",
            )

        console.print(table)
        return

    # Summary format (default)
    console.print(f"\n[bold]Network Risk Assessment[/bold]")
    console.print(f"  Average Risk: [bold]{report.average_risk:.1f}[/bold] / 10.0")
    console.print(f"  Max Risk:     [bold]{report.max_risk:.1f}[/bold] / 10.0")
    console.print()

    # Risk level distribution
    dist_table = Table(title="Risk Distribution")
    dist_table.add_column("Level", style="bold")
    dist_table.add_column("Count", justify="right")
    dist_table.add_row("[red bold]Critical[/red bold]", str(report.critical_count))
    dist_table.add_row("[red]High[/red]", str(report.high_count))
    dist_table.add_row("[yellow]Medium[/yellow]", str(report.medium_count))
    dist_table.add_row("[green]Low[/green]", str(report.low_count))
    console.print(dist_table)

    # Show top 5 in summary
    if report.top_risks:
        console.print()
        top_table = Table(title="Top Risks")
        top_table.add_column("IP", style="cyan")
        top_table.add_column("Category")
        top_table.add_column("Score", justify="right")
        top_table.add_column("Level")
        for p in report.top_risks[:5]:
            top_table.add_row(p.ip, p.bigr_category, f"{p.risk_score:.1f}", p.risk_level)
        console.print(top_table)


# ---------------------------------------------------------------------------
# Vuln sub-app
# ---------------------------------------------------------------------------

vuln_app = typer.Typer(help="Vulnerability scanning and CVE correlation")
app.add_typer(vuln_app, name="vuln")


@vuln_app.command("seed")
def vuln_seed(
    db_path: Optional[str] = typer.Option(None, "--db-path", hidden=True, help="CVE DB path (for testing)"),
) -> None:
    """Seed the CVE database with built-in vulnerability data."""
    from bigr.vuln.cve_db import init_cve_db
    from bigr.vuln.nvd_sync import seed_cve_database

    resolved = Path(db_path) if db_path else None
    if resolved:
        init_cve_db(resolved)
    count = seed_cve_database(db_path=resolved)
    console.print(f"[green]Seeded[/green] {count} CVEs into the database.")


@vuln_app.command("scan")
def vuln_scan(
    db_path: Optional[str] = typer.Option(None, "--db-path", hidden=True, help="CVE DB path (for testing)"),
    asset_db_path: Optional[str] = typer.Option(None, "--asset-db-path", hidden=True, help="Asset DB path (for testing)"),
) -> None:
    """Scan assets for known vulnerabilities."""
    from bigr.vuln.cve_db import get_cve_stats, init_cve_db
    from bigr.vuln.matcher import scan_all_vulnerabilities
    from bigr.vuln.nvd_sync import seed_cve_database

    resolved_cve = Path(db_path) if db_path else None
    resolved_asset = Path(asset_db_path) if asset_db_path else None

    # Ensure CVE DB is initialized and seeded
    init_cve_db(resolved_cve)
    stats = get_cve_stats(db_path=resolved_cve)
    if stats["total"] == 0:
        seed_cve_database(db_path=resolved_cve)

    # Get assets from the asset database
    all_assets = get_all_assets(db_path=resolved_asset)
    asset_dicts = [
        {
            "ip": a.get("ip", ""),
            "mac": a.get("mac"),
            "vendor": a.get("vendor"),
            "open_ports": a.get("open_ports", []),
        }
        for a in all_assets
    ]

    summaries = scan_all_vulnerabilities(asset_dicts, db_path=resolved_cve)

    if not summaries:
        console.print("[yellow]No vulnerabilities found.[/yellow]")
        return

    table = Table(title="\nVulnerability Scan Results")
    table.add_column("IP", style="cyan")
    table.add_column("Total", justify="right")
    table.add_column("Critical", justify="right", style="red bold")
    table.add_column("High", justify="right", style="red")
    table.add_column("Medium", justify="right", style="yellow")
    table.add_column("Low", justify="right", style="dim")
    table.add_column("Max CVSS", justify="right")

    for s in summaries:
        table.add_row(
            s.ip,
            str(s.total_vulns),
            str(s.critical_count),
            str(s.high_count),
            str(s.medium_count),
            str(s.low_count),
            f"{s.max_cvss:.1f}",
        )

    console.print(table)
    console.print(f"\n[bold]{len(summaries)}[/bold] assets with vulnerabilities found.")


@vuln_app.command("stats")
def vuln_stats(
    db_path: Optional[str] = typer.Option(None, "--db-path", hidden=True, help="CVE DB path (for testing)"),
) -> None:
    """Show CVE database statistics."""
    from bigr.vuln.cve_db import get_cve_stats, init_cve_db

    resolved = Path(db_path) if db_path else None
    init_cve_db(resolved)
    stats = get_cve_stats(db_path=resolved)

    console.print(f"\n[bold]CVE Database Statistics[/bold]")
    console.print(f"  Total CVEs: [bold]{stats['total']}[/bold]")
    if stats.get("last_sync"):
        console.print(f"  Last Sync:  {stats['last_sync']}")

    by_sev = stats.get("by_severity", {})
    if by_sev:
        table = Table(title="By Severity")
        table.add_column("Severity", style="bold")
        table.add_column("Count", justify="right")
        sev_styles = {"critical": "red bold", "high": "red", "medium": "yellow", "low": "dim", "none": "dim"}
        for sev in ("critical", "high", "medium", "low", "none"):
            count = by_sev.get(sev, 0)
            if count > 0:
                style = sev_styles.get(sev, "white")
                table.add_row(f"[{style}]{sev.capitalize()}[/{style}]", str(count))
        console.print(table)


@vuln_app.command("search")
def vuln_search(
    query: str = typer.Argument(..., help="Vendor name or CVE ID to search"),
    db_path: Optional[str] = typer.Option(None, "--db-path", hidden=True, help="CVE DB path (for testing)"),
) -> None:
    """Search CVE database by vendor or CVE ID."""
    from bigr.vuln.cve_db import get_cve_by_id, init_cve_db, search_cves_by_vendor

    resolved = Path(db_path) if db_path else None
    init_cve_db(resolved)

    results = []

    # Check if query looks like a CVE ID
    if query.upper().startswith("CVE-"):
        entry = get_cve_by_id(query.upper(), db_path=resolved)
        if entry:
            results = [entry]
    else:
        results = search_cves_by_vendor(query, db_path=resolved)

    if not results:
        console.print(f"[yellow]No CVEs found for '{query}'.[/yellow]")
        return

    table = Table(title=f"\nCVE Search: {query}")
    table.add_column("CVE ID", style="cyan")
    table.add_column("CVSS", justify="right")
    table.add_column("Severity")
    table.add_column("Vendor")
    table.add_column("Product")
    table.add_column("Description")
    table.add_column("KEV")

    sev_styles = {"critical": "red bold", "high": "red", "medium": "yellow", "low": "dim", "none": "dim"}
    for entry in results:
        style = sev_styles.get(entry.severity, "white")
        kev = "[red]YES[/red]" if entry.cisa_kev else "-"
        # Truncate description
        desc = entry.description[:60] + "..." if len(entry.description) > 60 else entry.description
        table.add_row(
            entry.cve_id,
            f"{entry.cvss_score:.1f}",
            f"[{style}]{entry.severity.upper()}[/{style}]",
            entry.affected_vendor,
            entry.affected_product,
            desc,
            kev,
        )

    console.print(table)
    console.print(f"\n[bold]{len(results)}[/bold] CVEs found.")


# ---------------------------------------------------------------------------
# Agent sub-app
# ---------------------------------------------------------------------------

agent_app = typer.Typer(help="Remote agent management (register, start, stop, status)")
app.add_typer(agent_app, name="agent")


@agent_app.command("register")
def agent_register(
    api_url: str = typer.Option(..., "--api-url", help="Cloud API base URL"),
    name: str = typer.Option(..., "--name", help="Agent name"),
    site: str = typer.Option("", "--site", help="Site name"),
    secret: Optional[str] = typer.Option(None, "--secret", help="Registration secret"),
    config_path: Optional[str] = typer.Option(None, "--config", hidden=True),
) -> None:
    """Register this agent with the cloud API and save credentials locally."""
    import httpx

    from bigr.agent.config import AgentConfig

    body: dict = {"name": name, "site_name": site}
    if secret:
        body["secret"] = secret

    try:
        resp = httpx.post(f"{api_url.rstrip('/')}/api/agents/register", json=body, timeout=30.0)
        resp.raise_for_status()
    except httpx.HTTPStatusError as exc:
        console.print(f"[red]Registration failed:[/red] {exc.response.status_code} — {exc.response.text}")
        raise typer.Exit(1)
    except httpx.RequestError as exc:
        console.print(f"[red]Connection error:[/red] {exc}")
        raise typer.Exit(1)

    data = resp.json()
    agent_id = data["agent_id"]
    token = data["token"]

    # Save to config
    cfg_path = Path(config_path) if config_path else None
    cfg = AgentConfig(
        api_url=api_url.rstrip("/"),
        token=token,
        agent_id=agent_id,
        name=name,
        site_name=site,
    )
    saved = cfg.save(cfg_path)

    console.print(f"[green]Registered![/green] Agent ID: {agent_id}")
    console.print(f"Config saved to: {saved}")
    console.print("[dim]Token stored in config. Keep this file secure.[/dim]")


@agent_app.command("start")
def agent_start(
    targets: list[str] = typer.Argument(None, help="Target subnet(s) to scan"),
    api_url: Optional[str] = typer.Option(None, "--api-url", help="Cloud API URL (overrides config)"),
    token: Optional[str] = typer.Option(None, "--token", help="Bearer token (overrides config)"),
    name: Optional[str] = typer.Option(None, "--name", "-n", help="Agent name (default: device hostname)"),
    interval: str = typer.Option("5m", "--interval", "-i", help="Scan interval (e.g. 5m, 1h)"),
    shield: bool = typer.Option(True, "--shield/--no-shield", help="Run shield security modules (default: on)"),
    config_path: Optional[str] = typer.Option(None, "--config", hidden=True),
) -> None:
    """Start the agent daemon to scan and push results to cloud."""
    import httpx

    from bigr.agent.config import AgentConfig
    from bigr.agent.daemon import AgentDaemon
    from bigr.config import parse_interval

    cfg_path = Path(config_path) if config_path else None
    cfg = AgentConfig.load(cfg_path)

    resolved_url = api_url or cfg.api_url or "http://127.0.0.1:9978"
    resolved_token = token or cfg.token
    resolved_targets = list(targets) if targets else cfg.targets
    auto_detect = not resolved_targets

    if auto_detect:
        # Auto-detect current subnet
        from bigr.agent.network_fingerprint import detect_local_subnet

        detected = detect_local_subnet()
        if detected:
            console.print(f"[cyan]Auto-detected subnet:[/cyan] {detected}")
        else:
            console.print("[yellow]Could not auto-detect subnet — will retry each cycle[/yellow]")

    # Auto-register if no token or token is stale
    need_register = not resolved_token
    if resolved_token and not need_register:
        try:
            resp = httpx.post(
                f"{resolved_url}/api/agents/heartbeat",
                json={"status": "online"},
                headers={"Authorization": f"Bearer {resolved_token}"},
                timeout=10.0,
            )
            if resp.status_code == 401:
                console.print("[yellow]Token expired or invalid — re-registering...[/yellow]")
                need_register = True
        except httpx.RequestError:
            pass

    if need_register:
        import platform as _platform

        hostname = _platform.node().replace(".local", "").replace("-", " ")
        agent_name = name or cfg.name or hostname or "BİGR Agent"
        console.print(f"[cyan]Registering agent[/cyan] '{agent_name}' → {resolved_url}")
        try:
            resp = httpx.post(
                f"{resolved_url}/api/agents/register",
                json={"name": agent_name, "site_name": ""},
                timeout=30.0,
            )
            resp.raise_for_status()
            data = resp.json()
            resolved_token = data["token"]
            cfg.api_url = resolved_url
            cfg.token = resolved_token
            cfg.agent_id = data["agent_id"]
            cfg.name = agent_name
            cfg.targets = resolved_targets
            cfg.shield = shield
            cfg.save(cfg_path)
            console.print(f"[green]Registered![/green] Agent ID: {data['agent_id']}")
        except httpx.HTTPStatusError as exc:
            console.print(f"[red]Auto-registration failed:[/red] {exc.response.status_code}")
            raise typer.Exit(1)
        except httpx.RequestError as exc:
            console.print(f"[red]Cannot reach API:[/red] {exc}")
            console.print("[dim]Make sure the dashboard is running: bigr serve[/dim]")
            raise typer.Exit(1)

    interval_sec = parse_interval(interval)
    console.print(f"[green]Starting agent[/green] → {resolved_url}")
    if auto_detect:
        console.print("  Targets: [cyan]otomatik algılama[/cyan] (her döngüde ağ tespit edilir)")
    else:
        console.print(f"  Targets: {', '.join(resolved_targets)}")
    console.print(f"  Interval: {interval_sec}s | Shield: {'Yes' if shield else 'No'}")

    daemon = AgentDaemon(
        api_url=resolved_url,
        token=resolved_token,
        targets=resolved_targets,
        interval_seconds=interval_sec,
        shield=shield,
        auto_detect=auto_detect,
    )
    try:
        daemon.start()
    except RuntimeError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(1)
    except KeyboardInterrupt:
        console.print("\n[yellow]Agent stopped.[/yellow]")


@agent_app.command("stop")
def agent_stop() -> None:
    """Stop the running agent daemon."""
    import httpx

    from bigr.agent.config import AgentConfig

    pid_path = Path.home() / ".bigr" / "agent.pid"
    if not pid_path.exists():
        console.print("[yellow]No agent is running.[/yellow]")
        return

    try:
        pid = int(pid_path.read_text().strip())
    except (ValueError, OSError):
        console.print("[yellow]Invalid PID file.[/yellow]")
        pid_path.unlink(missing_ok=True)
        return

    # Notify API that agent is going offline (best-effort)
    cfg = AgentConfig.load()
    if cfg.api_url and cfg.token:
        try:
            httpx.post(
                f"{cfg.api_url}/api/agents/heartbeat",
                json={"status": "offline"},
                headers={"Authorization": f"Bearer {cfg.token}"},
                timeout=5.0,
            )
        except Exception:
            pass  # Don't block stop on network errors

    try:
        os.kill(pid, signal.SIGTERM)
        console.print(f"[green]Stopped agent[/green] (PID {pid}).")
    except OSError as exc:
        console.print(f"[red]Error stopping agent:[/red] {exc}")
    pid_path.unlink(missing_ok=True)


@agent_app.command("status")
def agent_status() -> None:
    """Check agent daemon status."""
    pid_path = Path.home() / ".bigr" / "agent.pid"
    if not pid_path.exists():
        console.print("[yellow]Agent is not running.[/yellow]")
        return

    try:
        pid = int(pid_path.read_text().strip())
    except (ValueError, OSError):
        console.print("[yellow]Invalid PID file. Cleaning up.[/yellow]")
        pid_path.unlink(missing_ok=True)
        return

    from bigr.agent.daemon import _is_process_alive

    if _is_process_alive(pid):
        console.print(f"[green]Agent is running[/green] (PID {pid}).")
    else:
        console.print("[yellow]Agent is not running (stale PID).[/yellow]")
        pid_path.unlink(missing_ok=True)


@agent_app.command("menubar")
def agent_menubar() -> None:
    """Launch the macOS menu bar status monitor.

    Shows agent status, scan stats, and quick actions in the system tray.
    The agent daemon runs independently — this is a lightweight monitor.
    """
    import platform as _platform

    if _platform.system() != "Darwin":
        console.print("[red]Error:[/red] Menu bar app is only available on macOS.")
        raise typer.Exit(1)

    try:
        from bigr.agent.menubar import run_menubar
    except ImportError:
        console.print(
            "[red]Error:[/red] rumps is required for the menu bar app.\n"
            "Install it with: pip install rumps"
        )
        raise typer.Exit(1)

    console.print("[green]Launching BİGR menu bar app...[/green]")
    run_menubar()


@agent_app.command("install")
def agent_install() -> None:
    """Install BİGR agent as a macOS background service (LaunchAgent).

    The agent will start automatically at login and restart on crash.
    """
    from bigr.agent.launchd import install, is_installed

    if is_installed():
        console.print("[yellow]LaunchAgent already installed.[/yellow] Use 'bigr agent uninstall' first to reinstall.")
        return

    console.print("[cyan]Installing BİGR LaunchAgent...[/cyan]")
    success, message = install()
    if success:
        console.print(f"[green]Installed![/green] Plist: {message}")
        console.print("[dim]Agent will start automatically at login.[/dim]")
        console.print("[dim]Logs: ~/.bigr/logs/[/dim]")
    else:
        console.print(f"[red]Installation failed:[/red] {message}")


@agent_app.command("uninstall")
def agent_uninstall() -> None:
    """Remove BİGR agent background service."""
    from bigr.agent.launchd import is_installed, uninstall

    if not is_installed():
        console.print("[yellow]LaunchAgent is not installed.[/yellow]")
        return

    success, message = uninstall()
    if success:
        console.print(f"[green]Uninstalled.[/green] {message}")
    else:
        console.print(f"[red]Uninstall failed:[/red] {message}")


# ---------------------------------------------------------------------------
# Threat Intelligence sub-app
# ---------------------------------------------------------------------------

threat_app = typer.Typer(help="Threat intelligence feed management")
app.add_typer(threat_app, name="threat")


@threat_app.command("sync")
def threat_sync(
    feed: Optional[str] = typer.Option(None, "--feed", "-f", help="Sync a specific feed (default: all)"),
) -> None:
    """Sync all enabled threat intelligence feeds."""
    import asyncio
    import hashlib

    from bigr.core.database import get_session_factory
    from bigr.core.settings import settings
    from bigr.threat.ingestor import ThreatIngestor

    hmac_key = settings.THREAT_HMAC_KEY
    if not hmac_key:
        hmac_key = hashlib.sha256(b"bigr-threat-default-key").hexdigest()

    ingestor = ThreatIngestor(
        session_factory=get_session_factory(),
        hmac_key=hmac_key,
        otx_api_key=settings.OTX_API_KEY or None,
        expiry_days=settings.THREAT_EXPIRY_DAYS,
    )

    if feed:
        console.print(f"[bold]Syncing feed: {feed}[/bold]")
        with console.status(f"[bold green]Fetching {feed}..."):
            result = asyncio.run(ingestor.sync_feed(feed))
        console.print(f"[green]Done![/green] {result.get('indicators_fetched', 0)} indicators fetched, "
                       f"{result.get('indicators_processed', 0)} subnets processed.")
    else:
        console.print("[bold]Syncing all enabled threat feeds...[/bold]")
        with console.status("[bold green]Fetching threat intelligence..."):
            result = asyncio.run(ingestor.sync_all_feeds())

        console.print(f"\n[green]Sync complete![/green]")
        console.print(f"  Feeds synced: [bold]{result['feeds_synced']}[/bold]")
        console.print(f"  Total indicators: [bold]{result['total_indicators']}[/bold]")

        if result.get("expired_cleaned", 0) > 0:
            console.print(f"  Expired cleaned: [bold]{result['expired_cleaned']}[/bold]")

        if result.get("errors"):
            console.print(f"\n[yellow]Errors ({len(result['errors'])}):[/yellow]")
            for err in result["errors"]:
                console.print(f"  [red]-[/red] {err}")

        # Show per-feed details
        if result.get("details"):
            table = Table(title="\nFeed Details")
            table.add_column("Feed", style="cyan")
            table.add_column("Fetched", justify="right")
            table.add_column("Processed", justify="right")
            table.add_column("Status")

            for name, detail in result["details"].items():
                if "error" in detail:
                    table.add_row(name, "-", "-", f"[red]{detail['error'][:50]}[/red]")
                else:
                    table.add_row(
                        name,
                        str(detail.get("indicators_fetched", 0)),
                        str(detail.get("indicators_processed", 0)),
                        "[green]OK[/green]",
                    )

            console.print(table)


@threat_app.command("lookup")
def threat_lookup(
    ip: str = typer.Argument(..., help="IP address to look up"),
) -> None:
    """Look up threat score for an IP address."""
    import asyncio
    import hashlib

    from bigr.core.database import get_session_factory
    from bigr.core.settings import settings
    from bigr.threat.ingestor import ThreatIngestor

    hmac_key = settings.THREAT_HMAC_KEY
    if not hmac_key:
        hmac_key = hashlib.sha256(b"bigr-threat-default-key").hexdigest()

    ingestor = ThreatIngestor(
        session_factory=get_session_factory(),
        hmac_key=hmac_key,
        expiry_days=settings.THREAT_EXPIRY_DAYS,
    )

    result = asyncio.run(ingestor.lookup_subnet(ip))

    if result is None:
        console.print(f"[green]Clean[/green] — No threat data for {ip}'s /24 subnet.")
        return

    score = result["threat_score"]
    if score >= 0.7:
        score_style = "red bold"
        level = "HIGH"
    elif score >= 0.4:
        score_style = "yellow"
        level = "MEDIUM"
    else:
        score_style = "dim"
        level = "LOW"

    console.print(f"\n[bold]Threat Lookup: {ip}[/bold]")
    console.print(f"  Score: [{score_style}]{score:.4f}[/{score_style}] ({level})")
    console.print(f"  Sources: {', '.join(result['source_feeds'])}")
    console.print(f"  Types: {', '.join(result['indicator_types'])}")
    console.print(f"  Reports: {result['report_count']}")
    console.print(f"  First seen: {result['first_seen'][:19].replace('T', ' ')}")
    console.print(f"  Last seen: {result['last_seen'][:19].replace('T', ' ')}")
    console.print(f"  Expires: {result['expires_at'][:19].replace('T', ' ')}")


@threat_app.command("stats")
def threat_stats() -> None:
    """Show threat intelligence statistics."""
    import asyncio
    import hashlib

    from bigr.core.database import get_session_factory
    from bigr.core.settings import settings
    from bigr.threat.ingestor import ThreatIngestor

    hmac_key = settings.THREAT_HMAC_KEY
    if not hmac_key:
        hmac_key = hashlib.sha256(b"bigr-threat-default-key").hexdigest()

    ingestor = ThreatIngestor(
        session_factory=get_session_factory(),
        hmac_key=hmac_key,
        expiry_days=settings.THREAT_EXPIRY_DAYS,
    )

    stats = asyncio.run(ingestor.get_stats())

    console.print(f"\n[bold]Threat Intelligence Statistics[/bold]")
    console.print(f"  Total indicators: [bold]{stats['total_indicators']}[/bold]")
    console.print(f"  Active feeds: [bold]{stats['enabled_feeds']}[/bold] / {stats['total_feeds']}")
    console.print(f"  Avg threat score: [bold]{stats['average_threat_score']:.4f}[/bold]")

    dist = stats.get("score_distribution", {})
    if dist:
        table = Table(title="\nScore Distribution")
        table.add_column("Level", style="bold")
        table.add_column("Count", justify="right")
        table.add_row("[red]High (>=0.7)[/red]", str(dist.get("high", 0)))
        table.add_row("[yellow]Medium (0.4-0.7)[/yellow]", str(dist.get("medium", 0)))
        table.add_row("[dim]Low (<0.4)[/dim]", str(dist.get("low", 0)))
        console.print(table)


@threat_app.command("feeds")
def threat_feeds() -> None:
    """List all registered threat feeds."""
    import asyncio

    from sqlalchemy import select

    from bigr.core.database import get_session_factory
    from bigr.threat.models import ThreatFeedDB

    async def _list():
        factory = get_session_factory()
        async with factory() as session:
            stmt = select(ThreatFeedDB).order_by(ThreatFeedDB.name)
            result = await session.execute(stmt)
            return result.scalars().all()

    feeds = asyncio.run(_list())

    if not feeds:
        console.print("[yellow]No feeds registered.[/yellow] Run 'bigr threat sync' to initialize feeds.")
        return

    table = Table(title="\nThreat Intelligence Feeds")
    table.add_column("Name", style="cyan")
    table.add_column("Type")
    table.add_column("Enabled")
    table.add_column("Last Synced")
    table.add_column("Entries", justify="right")

    for f in feeds:
        enabled_str = "[green]Yes[/green]" if f.enabled else "[red]No[/red]"
        synced = f.last_synced_at or "-"
        if synced != "-":
            synced = synced[:19].replace("T", " ")

        table.add_row(
            f.name,
            f.feed_type,
            enabled_str,
            synced,
            str(f.entries_count),
        )

    console.print(table)


@app.command()
def version() -> None:
    """Show version information."""
    from bigr import __version__
    console.print(f"BİGR Discovery v{__version__}")


# --- Display Helpers ---


def _score_to_grade(score: float) -> str:
    """Convert compliance percentage to letter grade."""
    if score >= 95:
        return "A+"
    if score >= 90:
        return "A"
    if score >= 85:
        return "B+"
    if score >= 80:
        return "B"
    if score >= 75:
        return "C+"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"

def _print_summary(result: ScanResult) -> None:
    table = Table(title="\nBİGR Asset Summary")
    table.add_column("BİGR Group", style="bold")
    table.add_column("Count", justify="right")
    table.add_column("Avg Confidence", justify="right")

    summary = result.category_summary
    category_labels = {
        "ag_ve_sistemler": "Ağ ve Sistemler",
        "uygulamalar": "Uygulamalar",
        "iot": "IoT",
        "tasinabilir": "Taşınabilir Cihazlar",
        "unclassified": "Sınıflandırılmamış",
    }

    for cat_key, label in category_labels.items():
        count = summary.get(cat_key, 0)
        if count > 0:
            # Calculate avg confidence for this category
            cat_assets = [a for a in result.assets if a.bigr_category.value == cat_key]
            avg_conf = sum(a.confidence_score for a in cat_assets) / len(cat_assets)
            conf_bar = "█" * int(avg_conf * 7) + "░" * (7 - int(avg_conf * 7))
            table.add_row(label, str(count), f"{conf_bar} {avg_conf:.2f}")

    console.print(table)


def _print_summary_from_data(data: dict) -> None:
    table = Table(title="BİGR Asset Summary")
    table.add_column("BİGR Group", style="bold")
    table.add_column("Count", justify="right")

    for cat, count in data.get("category_summary", {}).items():
        labels = {
            "ag_ve_sistemler": "Ağ ve Sistemler",
            "uygulamalar": "Uygulamalar",
            "iot": "IoT",
            "tasinabilir": "Taşınabilir Cihazlar",
            "unclassified": "Sınıflandırılmamış",
        }
        table.add_row(labels.get(cat, cat), str(count))

    console.print(table)
    console.print(f"\nTotal assets: {data.get('total_assets', 0)}")


def _print_detailed(data: dict) -> None:
    table = Table(title="BİGR Asset Inventory (Detailed)")
    table.add_column("IP", style="cyan")
    table.add_column("MAC")
    table.add_column("Hostname")
    table.add_column("Vendor")
    table.add_column("Ports")
    table.add_column("BİGR Group", style="bold")
    table.add_column("Confidence", justify="right")

    for asset in data.get("assets", []):
        ports_str = ",".join(str(p) for p in asset.get("open_ports", []))
        conf = asset.get("confidence_score", 0)
        style = "green" if conf >= 0.7 else "yellow" if conf >= 0.4 else "red"
        table.add_row(
            asset.get("ip", ""),
            asset.get("mac", "-"),
            asset.get("hostname", "-"),
            asset.get("vendor", "-"),
            ports_str or "-",
            asset.get("bigr_category_tr", "-"),
            f"[{style}]{conf:.2f}[/{style}]",
        )

    console.print(table)


def _print_diff(diff_result) -> None:
    """Print a color-coded diff table to the console."""
    from bigr.diff import DiffResult

    console.print(f"\n[bold]Scan Diff:[/bold] {diff_result.summary}")

    if not diff_result.has_changes:
        return

    table = Table(title="Changes Detected")
    table.add_column("Type")
    table.add_column("IP", style="cyan")
    table.add_column("MAC")
    table.add_column("Detail")

    for asset in diff_result.new_assets:
        table.add_row(
            "[green]+NEW[/green]",
            asset.get("ip", "-"),
            asset.get("mac") or "-",
            f"Category: {asset.get('bigr_category', '-')}",
        )

    for asset in diff_result.removed_assets:
        table.add_row(
            "[red]-REMOVED[/red]",
            asset.get("ip", "-"),
            asset.get("mac") or "-",
            f"Was: {asset.get('bigr_category', '-')}",
        )

    for change in diff_result.changed_assets:
        old_display = change.old_value or "-"
        new_display = change.new_value or "-"
        table.add_row(
            f"[yellow]~{change.change_type.upper()}[/yellow]",
            change.ip,
            change.mac or "-",
            f"{change.field}: {old_display} -> {new_display}",
        )

    console.print(table)


def _print_bigr_matrix(data: dict) -> None:
    console.print("[bold]BİGR Compliance Matrix[/bold]\n")

    for asset in data.get("assets", []):
        conf = asset.get("confidence_score", 0)
        level = asset.get("confidence_level", "unclassified")
        ip = asset.get("ip", "?")
        cat_tr = asset.get("bigr_category_tr", "?")

        icon = {"high": "✓", "medium": "~", "low": "!", "unclassified": "✗"}.get(level, "?")
        style = {"high": "green", "medium": "yellow", "low": "red", "unclassified": "dim"}.get(level, "white")

        console.print(f"  [{style}][{icon}][/{style}] {ip:15s} → {cat_tr:24s} (confidence: {conf:.2f})")


# ---------------------------------------------------------------------------
# Guardian DNS filtering commands
# ---------------------------------------------------------------------------
guardian_app = typer.Typer(help="Guardian DNS filtering server")
app.add_typer(guardian_app, name="guardian")


@guardian_app.command("start")
def guardian_start(
    port: int = typer.Option(5353, "--port", "-p", help="DNS server port"),
    host: str = typer.Option("0.0.0.0", "--host", help="DNS server bind address"),
) -> None:
    """Start the Guardian DNS filtering server."""
    import asyncio

    from bigr.guardian.config import GuardianConfig
    from bigr.guardian.daemon import GuardianDaemon

    config = GuardianConfig(dns_host=host, dns_port=port)
    daemon = GuardianDaemon(config=config)

    console.print(f"[green]Starting Guardian DNS on {host}:{port}...[/green]")
    try:
        asyncio.run(daemon.start())
        # Keep running until interrupted
        asyncio.get_event_loop().run_forever()
    except RuntimeError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(1)
    except KeyboardInterrupt:
        console.print("\n[yellow]Stopping Guardian...[/yellow]")
        asyncio.run(daemon.stop())


@guardian_app.command("stop")
def guardian_stop() -> None:
    """Stop the Guardian DNS filtering server."""
    from bigr.guardian.daemon import GuardianDaemon

    daemon = GuardianDaemon()
    status = daemon.get_status()
    if not status["running"]:
        console.print("[yellow]Guardian is not running.[/yellow]")
        return

    pid = status["pid"]
    try:
        os.kill(pid, signal.SIGTERM)
        console.print(f"[green]Guardian stopped (PID {pid}).[/green]")
    except OSError as exc:
        console.print(f"[red]Failed to stop Guardian:[/red] {exc}")


@guardian_app.command("status")
def guardian_status() -> None:
    """Check Guardian DNS server status."""
    from bigr.guardian.daemon import GuardianDaemon

    daemon = GuardianDaemon()
    status = daemon.get_status()

    if status["running"]:
        console.print(f"[green]Guardian is running[/green] (PID {status['pid']})")
    else:
        console.print(f"[yellow]Guardian is not running[/yellow]: {status['message']}")


if __name__ == "__main__":
    app()
