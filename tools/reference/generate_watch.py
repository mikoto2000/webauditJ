"""Generate watch parity fixtures from an explicit checkout of webaudit v2.0.0."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

parser = argparse.ArgumentParser()
parser.add_argument("source", type=Path)
parser.add_argument("--go", default="go")
args = parser.parse_args()
source = args.source.resolve()
commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=source, text=True).strip()
assert commit == "96e3c8a3148d1684d60abac22d3aa2939354e891", commit
root = Path(__file__).resolve().parents[2]
with tempfile.TemporaryDirectory(prefix="watch-reference-", dir=source / "tools") as temp:
    shutil.copyfile(Path(__file__).with_name("watch-reference.go"), Path(temp) / "main.go")
    result = subprocess.check_output([args.go, "run", "-mod=vendor", "./tools/" + Path(temp).name], cwd=source)
data = json.loads(result)
output = root / "src/test/resources/watch-golden.json"
output.write_text(json.dumps(data, ensure_ascii=False, separators=(",", ":")) + "\n", encoding="utf-8")
baseline = root / "docs/reference/baseline.json"
v = json.loads(baseline.read_text(encoding="utf-8"))
v["files"]["watch-golden.json"] = dict(sha256=hashlib.sha256(output.read_bytes()).hexdigest(), cases=sum(len(s["steps"]) for s in data), commit=commit)
baseline.write_text(json.dumps(v, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
