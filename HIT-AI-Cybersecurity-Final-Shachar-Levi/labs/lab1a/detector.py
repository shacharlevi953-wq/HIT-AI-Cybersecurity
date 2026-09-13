import json
import os
import re
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

LOG_FILE = Path(os.getenv("LOG_FILE", "/app/logs/security.log"))
OUTPUT_FILE = Path(os.getenv("OUTPUT_FILE", "/app/output/findings.json"))
STIX_FILE = Path(os.getenv("STIX_FILE", "/app/mitre/enterprise-attack.json"))
FAILED_LOGIN_THRESHOLD = int(os.getenv("FAILED_LOGIN_THRESHOLD", "3"))
NETWORK_SCAN_PORT_THRESHOLD = int(os.getenv("NETWORK_SCAN_PORT_THRESHOLD", "4"))
SCAN_INTERVAL = int(os.getenv("SCAN_INTERVAL", "5"))

FAILED_RE = re.compile(r"Failed password.*?from\s+(?P<ip>[0-9.]+)", re.I)
SCAN_RE = re.compile(r"Network scan detected from\s+(?P<ip>[0-9.]+)\s+against ports\s+(?P<ports>[0-9,\s]+)", re.I)


def load_attack_catalog():
    with STIX_FILE.open(encoding="utf-8") as handle:
        bundle = json.load(handle)
    catalog = {}
    for obj in bundle.get("objects", []):
        ext = obj.get("external_references", [])
        attack_ref = next((x for x in ext if x.get("source_name") == "mitre-attack"), {})
        technique_id = attack_ref.get("external_id")
        if technique_id:
            catalog[technique_id] = {
                "name": obj.get("name"),
                "url": attack_ref.get("url"),
                "tactics": [x.get("phase_name") for x in obj.get("kill_chain_phases", [])],
                "stix_id": obj.get("id"),
            }
    return catalog


def enrich(technique_id, evidence, source_ip, severity, extra=None):
    meta = load_attack_catalog().get(technique_id)
    if not meta:
        return None
    finding = {
        "detected_at": datetime.now(timezone.utc).isoformat(),
        "technique_id": technique_id,
        "technique_name": meta["name"],
        "tactic": ", ".join(x.replace("-", " ").title() for x in meta["tactics"]),
        "mitre_url": meta["url"],
        "stix_lookup_status": "matched",
        "stix_id": meta["stix_id"],
        "severity": severity,
        "source_ip": source_ip,
        "evidence": evidence,
        "network_scan_port_threshold": NETWORK_SCAN_PORT_THRESHOLD,
    }
    if extra:
        finding.update(extra)
    return finding


def detect(lines):
    findings = []
    failed = Counter()
    failed_evidence = {}
    for raw in lines:
        line = raw.strip()
        match = FAILED_RE.search(line)
        if match:
            ip = match.group("ip")
            failed[ip] += 1
            failed_evidence.setdefault(ip, []).append(line)

        match = SCAN_RE.search(line)
        if match:
            ip = match.group("ip")
            ports = sorted({int(x.strip()) for x in match.group("ports").split(",") if x.strip()})
            if len(ports) >= NETWORK_SCAN_PORT_THRESHOLD:
                finding = enrich(
                    "T1046", line, ip, "medium",
                    {"scanned_ports": ports, "scanned_port_count": len(ports)},
                )
                if finding:
                    findings.append(finding)

    for ip, count in failed.items():
        if count >= FAILED_LOGIN_THRESHOLD:
            finding = enrich(
                "T1110", " | ".join(failed_evidence[ip]), ip, "high",
                {"failed_login_count": count, "failed_login_threshold": FAILED_LOGIN_THRESHOLD},
            )
            if finding:
                findings.append(finding)
    return findings


def scan_once():
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    LOG_FILE.touch(exist_ok=True)
    lines = LOG_FILE.read_text(encoding="utf-8").splitlines()
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "configuration": {
            "failed_login_threshold": FAILED_LOGIN_THRESHOLD,
            "network_scan_port_threshold": NETWORK_SCAN_PORT_THRESHOLD,
        },
        "total_findings": 0,
        "findings": detect(lines),
    }
    payload["total_findings"] = len(payload["findings"])
    OUTPUT_FILE.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return payload


if __name__ == "__main__":
    print(f"Detector started; network scan threshold={NETWORK_SCAN_PORT_THRESHOLD}", flush=True)
    while True:
        result = scan_once()
        print(f"Scan complete: {result['total_findings']} finding(s)", flush=True)
        time.sleep(SCAN_INTERVAL)
