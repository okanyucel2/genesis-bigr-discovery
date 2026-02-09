# CLAUDE.md - genesis-bigr-discovery

## Project Overview

**Name:** BİGR Discovery - Asset Discovery & Classification Agent
**Type:** Standalone CLI + Web Dashboard
**Tech Stack:** Python 3.12+, Typer, Scapy, FastAPI, Rich

---

## Agent Identity

- Agent name: `bigr-worker`
- Parent: GENESIS v3 subproject

---

## Port Allocation

| Service | Port |
|---------|------|
| Dashboard | 8090 |

---

## Commands

```bash
# Install (development)
pip install -e ".[dev]"

# Run scan
bigr scan --target 192.168.1.0/24
sudo bigr scan --target 192.168.1.0/24  # full mode with ARP sweep

# Report
bigr report --format detailed

# Dashboard
bigr serve --port 8090

# Tests
pytest
pytest -v tests/test_classifier.py
```

---

## BİGR Categories

| ID | Turkish Name | Examples |
|----|-------------|----------|
| ag_ve_sistemler | Ağ ve Sistemler | Switches, routers, firewalls |
| uygulamalar | Uygulamalar | Web servers, app servers |
| iot | IoT | Cameras, printers, sensors |
| tasinabilir | Taşınabilir Cihazlar | Laptops, phones |

---

## Inherited Protocols

This project inherits from GENESIS root:
- P0.40: TDD
- P0.47: Pre-Commit Verification
- P0.50: Destructive Action Guard
- P0.99: Session Guard

---

*Project-specific rules for genesis-bigr-discovery*
