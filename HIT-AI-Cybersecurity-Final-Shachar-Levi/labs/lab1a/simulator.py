import os
import time
from datetime import datetime, timezone
from pathlib import Path

LOG_FILE = Path(os.getenv("LOG_FILE", "/app/logs/security.log"))
INTERVAL = int(os.getenv("SIMULATION_INTERVAL", "4"))

EVENTS = [
    "Successful login for user analyst from 172.18.0.10",
    "Failed password for user admin from 172.18.0.15",
    "Failed password for user root from 172.18.0.15",
    "Failed password for user service from 172.18.0.15",
    "Network scan detected from 172.18.0.20 against ports 22,80",
    "Network scan detected from 172.18.0.20 against ports 22,80,443,3306",
]

LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
for event in EVENTS:
    stamp = datetime.now(timezone.utc).isoformat()
    with LOG_FILE.open("a", encoding="utf-8") as handle:
        handle.write(f"{stamp} {event}\n")
    print(event, flush=True)
    time.sleep(INTERVAL)

while True:
    time.sleep(3600)
