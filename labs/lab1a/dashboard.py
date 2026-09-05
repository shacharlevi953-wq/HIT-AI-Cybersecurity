import html
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

LOG_FILE = Path(os.getenv("LOG_FILE", "/app/logs/security.log"))
FINDINGS_FILE = Path(os.getenv("OUTPUT_FILE", "/app/output/findings.json"))
PORT = int(os.getenv("DASHBOARD_PORT", "8000"))


def read_state():
    try:
        payload = json.loads(FINDINGS_FILE.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        payload = {"configuration": {"network_scan_port_threshold": "waiting"}, "findings": []}
    try:
        raw_log = LOG_FILE.read_text(encoding="utf-8")
    except FileNotFoundError:
        raw_log = ""
    return payload, raw_log


def render_dashboard():
    payload, raw_log = read_state()
    findings = payload.get("findings", [])
    threshold = payload.get("configuration", {}).get("network_scan_port_threshold", "waiting")
    cards = []
    for item in findings:
        cards.append(f'''<article class="card {html.escape(item['severity'])}">
        <div><span class="badge">{html.escape(item['severity'].upper())}</span>
        <strong>{html.escape(item['technique_id'])} — {html.escape(item['technique_name'])}</strong></div>
        <p><b>Tactic:</b> {html.escape(item['tactic'])} · <b>Source:</b> {html.escape(item['source_ip'])}</p>
        <p><b>Evidence:</b> {html.escape(item['evidence'])}</p>
        <p><b>STIX lookup:</b> {html.escape(item['stix_lookup_status'])}</p></article>''')
    cards_html = "".join(cards) or '<div class="empty">No findings. The detector is still scanning.</div>'
    return f'''<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="refresh" content="5">
    <title>MITRE Detection Dashboard</title><style>
    body{{font-family:Arial,sans-serif;background:#08111f;color:#eaf2ff;margin:0}}header{{padding:30px 6%;background:#102641;border-bottom:3px solid #2f81f7}}
    main{{width:88%;margin:24px auto}}.summary{{display:flex;gap:18px;margin:20px 0}}.metric{{background:#132a46;border:1px solid #31557c;border-radius:12px;padding:18px;min-width:220px}}
    .metric b{{display:block;color:#75b7ff;font-size:28px}}.card{{background:#102238;border-left:6px solid #e0a82e;border-radius:10px;padding:18px;margin:14px 0}}
    .card.high{{border-left-color:#ff5d62}}.badge{{background:#24496f;padding:5px 9px;border-radius:12px;margin-right:10px;font-size:12px}}
    pre{{background:#02070e;border:1px solid #28496c;border-radius:10px;padding:18px;white-space:pre-wrap;color:#b9d8f8}}a{{color:#75b7ff}}.empty{{padding:30px;background:#102238;border-radius:10px}}
    </style></head><body><header><h1>Local SOC Detection Dashboard</h1><p>Synthetic logs · transparent rules · MITRE ATT&CK STIX enrichment</p></header>
    <main><section class="summary"><div class="metric"><span>Total findings</span><b>{len(findings)}</b></div><div class="metric"><span>Network scan threshold</span><b>{threshold} ports</b></div></section>
    <h2>Findings</h2>{cards_html}<h2>Current raw security log</h2><pre>{html.escape(raw_log) or 'Log is empty.'}</pre></main></body></html>'''


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = render_dashboard().encode("utf-8")
        self.send_response(200); self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)


if __name__ == "__main__":
    print(f"Dashboard available at http://localhost:{PORT}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
