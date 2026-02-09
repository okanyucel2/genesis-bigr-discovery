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
    port: int = typer.Option(8090, "--port", "-p", help="Dashboard port"),
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


if __name__ == "__main__":
    app()
