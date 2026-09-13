import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def run_case(lines):
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        log = tmp / "security.log"
        out = tmp / "findings.json"
        log.write_text("\n".join(lines), encoding="utf-8")
        env = os.environ.copy()
        env.update({
            "LOG_FILE": str(log),
            "OUTPUT_FILE": str(out),
            "STIX_FILE": str(ROOT / "mitre" / "enterprise-attack.json"),
            "NETWORK_SCAN_PORT_THRESHOLD": "4",
            "FAILED_LOGIN_THRESHOLD": "3",
        })
        code = "import detector; detector.scan_once()"
        subprocess.run([sys.executable, "-c", code], cwd=ROOT, env=env, check=True)
        return json.loads(out.read_text(encoding="utf-8"))


def test_empty_log():
    assert run_case([])["total_findings"] == 0


def test_two_ports_do_not_trigger():
    result = run_case(["Network scan detected from 172.18.0.20 against ports 22,80"])
    assert all(x["technique_id"] != "T1046" for x in result["findings"])


def test_four_ports_trigger_t1046():
    result = run_case(["Network scan detected from 172.18.0.20 against ports 22,80,443,3306"])
    finding = next(x for x in result["findings"] if x["technique_id"] == "T1046")
    assert finding["scanned_port_count"] == 4
    assert finding["network_scan_port_threshold"] == 4
    assert finding["stix_lookup_status"] == "matched"


def test_three_failures_trigger_t1110():
    result = run_case([
        "Failed password for user admin from 172.18.0.15",
        "Failed password for user root from 172.18.0.15",
        "Failed password for user service from 172.18.0.15",
    ])
    assert any(x["technique_id"] == "T1110" for x in result["findings"])


if __name__ == "__main__":
    for test in [test_empty_log, test_two_ports_do_not_trigger, test_four_ports_trigger_t1046, test_three_failures_trigger_t1110]:
        test()
        print(f"PASS {test.__name__}")
