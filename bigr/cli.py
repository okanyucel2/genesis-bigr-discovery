"""CLI interface for BİGR Discovery."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from bigr.classifier.bigr_mapper import classify_assets
from bigr.models import ScanResult
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

    # Run scan
    with console.status("[bold green]Scanning network..."):
        result = run_hybrid_scan(target, mode=mode, ports=port_list, timeout=timeout)

    # Classify
    with console.status("[bold blue]Classifying assets..."):
        classify_assets(result.assets, do_fingerprint=True)

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
