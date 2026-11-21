"""Measure bounded watch startup/idle/append behavior in an isolated state directory.

Windows termination is forced after periodic checkpointing; Unix sends SIGINT.
This is a short measurement harness, not evidence of multi-day endurance.
"""
import argparse
import datetime
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time

parser = argparse.ArgumentParser()
parser.add_argument("--jar", type=Path, default=Path("target/webauditJ.jar"))
parser.add_argument("--seconds", type=int, default=10)
parser.add_argument("--lines", type=int, default=100)
parser.add_argument("--output", type=Path, default=Path(".workflow/watch-measurement.json"))
args = parser.parse_args()
assert 3 <= args.seconds <= 3600 and 1 <= args.lines <= 100000
jar = args.jar.resolve()
with tempfile.TemporaryDirectory(prefix="webauditJ-watch-") as temp:
    root = Path(temp)
    log = root / "access.log"
    log.touch()
    env = dict(os.environ, XDG_DATA_HOME=str(root / "data"), XDG_STATE_HOME=str(root / "state"))
    start = time.perf_counter()
    with (root / "events.jsonl").open("w", encoding="utf-8") as out, (root / "stderr.txt").open("w", encoding="utf-8") as err:
        p = subprocess.Popen(["java", "-Xms32m", "-Xmx256m", "-jar", str(jar), "watch", str(log), "--format", "jsonl"],
                             env=env, stdout=out, stderr=err)
        try:
            deadline = time.monotonic() + 15
            while "monitoring" not in (root / "stderr.txt").read_text(encoding="utf-8"):
                assert p.poll() is None and time.monotonic() < deadline, "watch startup failed"
                time.sleep(.05)
            startup = time.perf_counter() - start
            stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%d/%b/%Y:%H:%M:%S +0000")
            with log.open("a", encoding="utf-8") as writer:
                for i in range(args.lines):
                    writer.write(f'198.51.100.1 - - [{stamp}] "GET /.env HTTP/1.1" 404 12\n')
            time.sleep(args.seconds)
        finally:
            if p.poll() is None:
                if os.name == "nt": p.terminate()
                else: p.send_signal(signal.SIGINT)
            try: p.wait(timeout=15)
            except subprocess.TimeoutExpired: p.kill(); p.wait()
    events = [json.loads(line) for line in (root / "events.jsonl").read_text(encoding="utf-8").splitlines()]
    assert events, (root / "stderr.txt").read_text(encoding="utf-8")
    snapshots = list((root / "state").rglob("*.json"))
    result = dict(java=subprocess.check_output(["java", "-version"], stderr=subprocess.STDOUT, text=True).splitlines()[0],
                  platform=os.name, seconds=args.seconds, input_lines=args.lines, event_count=len(events),
                  startup_seconds=round(startup, 3), elapsed_seconds=round(time.perf_counter() - start, 3),
                  exit_code=p.returncode, graceful_stop=os.name != "nt",
                  checkpoint_bytes=sum(path.stat().st_size for path in snapshots))
args.output.parent.mkdir(parents=True, exist_ok=True)
args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
print(json.dumps(result))
