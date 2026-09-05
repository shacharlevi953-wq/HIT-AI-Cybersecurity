# Lab 1a — Synthetic Security Logs and MITRE Detection

Student: **Shachar Levi**

This project implements a local, Docker-based SOC pipeline:

`simulator → security.log → detector → MITRE STIX enrichment → dashboard`

## Run

```powershell
docker compose up -d
docker compose --profile simulation up -d
docker compose --profile simulation ps
```

Open <http://localhost:8000>.

Stop the environment:

```powershell
docker compose --profile simulation down --remove-orphans
```

## Configurable extension

`NETWORK_SCAN_PORT_THRESHOLD` is set to `4`. A scan with two ports is ignored; a scan with four or more distinct ports creates a T1046 finding. The configured threshold is written to `output/findings.json` and displayed on the dashboard.

## Deliverables

- `detector.py` — rules and STIX enrichment
- `docker-compose.yml` — three local services and detection configuration
- `dashboard.py` — local dashboard on port 8000
- `analysis.txt` — required experiment analysis
- `dashboard-screenshot.png` — validated example output

All events are synthetic and safe. A finding is evidence for analyst review, not proof that an attack occurred.
