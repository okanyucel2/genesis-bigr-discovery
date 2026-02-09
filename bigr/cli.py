"""CLI interface for BİGR Discovery."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from bigr.classifier.bigr_mapper import classify_assets
from bigr.db import get_latest_scan, get_scan_list, get_tags, save_scan, tag_asset, untag_asset
from bigr.diff import diff_scans, get_changes_from_db
from bigr.models import BigrCategory, ScanResult
from bigr.output import write_csv, write_json
from bigr.scanner.active import is_root
from bigr.scanner.hybrid import run_hybrid_scan

app = typer.Typer(
    name="bigr",
    help="BİGR Discovery - Asset Discovery & Classification Agent",
    no_args_is_help=True,
)
console = Console()


@app.command()
def scan(
    target: str = typer.Argument(..., help="Target subnet in CIDR notation (e.g., 192.168.1.0/24)"),
    mode: str = typer.Option("hybrid", "--mode", "-m", help="Scan mode: passive, active, or hybrid"),
    ports: Optional[str] = typer.Option(None, "--ports", "-p", help="Comma-separated port list"),
    timeout: float = typer.Option(2.0, "--timeout", "-t", help="Per-port scan timeout in seconds"),
    output: str = typer.Option("assets.json", "--output", "-o", help="Output file path"),
    fmt: str = typer.Option("json", "--format", "-f", help="Output format: json or csv"),
    diff: bool = typer.Option(True, "--diff/--no-diff", help="Show diff against previous scan"),
) -> None:
    """Scan network for assets and classify them per BİGR guidelines."""
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

    # Load previous scan for diffing (before we save the new one)
    previous_scan = None
    if diff:
        try:
            previous_scan = get_latest_scan(target=target)
        except Exception:
            pass

    # Run scan
    with console.status("[bold green]Scanning network..."):
        result = run_hybrid_scan(target, mode=mode, ports=port_list, timeout=timeout)

    # Classify
    with console.status("[bold blue]Classifying assets..."):
        classify_assets(result.assets, do_fingerprint=True)

    # Persist to database
    try:
        scan_id = save_scan(result)
        console.print(f"[dim]Saved to database (scan {scan_id[:8]}...)[/dim]")
    except Exception as exc:
        console.print(f"[yellow]Warning:[/yellow] Could not save to database: {exc}")

    # Output
    if fmt == "csv":
        out_path = write_csv(result, path=output.replace(".json", ".csv") if output == "assets.json" else output)
    else:
        out_path = write_json(result, path=output)

    console.print(f"\n[green]Scan complete![/green] Found [bold]{len(result.assets)}[/bold] assets.")
    console.print(f"Results saved to: [bold]{out_path}[/bold]")

    if result.duration_seconds is not None:
        console.print(f"Duration: {result.duration_seconds:.1f}s | Root: {'Yes' if result.is_root else 'No'}")

    # Show summary table
    _print_summary(result)

    # Show diff against previous scan
    if diff and previous_scan and previous_scan.get("assets"):
        current_assets = [a.to_dict() for a in result.assets]
        diff_result = diff_scans(current_assets, previous_scan["assets"])
        if diff_result.has_changes:
            _print_diff(diff_result)
        else:
            console.print("\n[dim]No changes since last scan.[/dim]")


@app.command()
def report(
    input_file: str = typer.Option("assets.json", "--input", "-i", help="Input scan result file"),
    fmt: str = typer.Option("summary", "--format", "-f", help="Report format: summary, detailed, bigr-matrix"),
) -> None:
    """Generate report from existing scan results."""
    path = Path(input_file)
    if not path.exists():
        console.print(f"[red]Error:[/red] File not found: {input_file}")
        raise typer.Exit(1)

    with path.open(encoding="utf-8") as f:
        data = json.load(f)

    if fmt == "detailed":
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
def version() -> None:
    """Show version information."""
    from bigr import __version__
    console.print(f"BİGR Discovery v{__version__}")


# --- Display Helpers ---

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
