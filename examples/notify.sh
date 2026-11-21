#!/bin/sh
# Optional example dependency: Python 3. No shell expansion of event values.
set -eu
exec python3 -c '
import json, sys
data = sys.stdin.buffer.read(65537)
if len(data) > 65536:
    raise SystemExit("event too large")
event = json.loads(data)
if event.get("schema_version") != 1:
    raise SystemExit("unsupported schema")
summary = {key: event.get(key) for key in
           ("notification_id", "incident_id", "revision", "severity", "outcome")}
sys.stdout.write(json.dumps(summary, ensure_ascii=True) + "\n")
'
