"""Measure a cold JVM analysis with bounded heap; file generation is excluded."""
import argparse
import ctypes
import datetime as dt
import json
import locale
import os
import platform
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("--lines", type=int, default=100000)
parser.add_argument("--scenario", choices=["repeated_mixed", "distinct_mixed", "both"], default="both")
parser.add_argument("--country", type=Path, default=Path("src/test/resources/geoip/country.mmdb"))
parser.add_argument("--asn", type=Path, default=Path("src/test/resources/geoip/asn.mmdb"))
parser.add_argument("--output", type=Path, default=Path(".workflow/performance.json"))
args = parser.parse_args()
assert args.lines > 0
root = Path(__file__).resolve().parents[1]
os.chdir(root)
java, javac = shutil.which("java"), shutil.which("javac")
assert java and javac
classes = root / ".build/benchmark/classes"
classes.mkdir(parents=True, exist_ok=True)
jar = root / "target/webauditJ.jar"
subprocess.run([javac, "-cp", str(jar), "-d", str(classes), str(root / "tools/Benchmark.java")], check=True)
classpath = str(classes) + os.pathsep + str(jar)
locale.setlocale(locale.LC_TIME, "C")


def process_resident_peak(process):
    if platform.system() == "Windows":
        from ctypes import wintypes

        class Counters(ctypes.Structure):
            _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD)] + [
                (name, ctypes.c_size_t) for name in ["PeakWorkingSetSize", "WorkingSetSize",
                "QuotaPeakPagedPoolUsage", "QuotaPagedPoolUsage", "QuotaPeakNonPagedPoolUsage",
                "QuotaNonPagedPoolUsage", "PagefileUsage", "PeakPagefileUsage"]]
        counters = Counters()
        counters.cb = ctypes.sizeof(counters)
        query = ctypes.windll.psapi.GetProcessMemoryInfo
        query.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD]
        if query(wintypes.HANDLE(int(process._handle)), ctypes.byref(counters), counters.cb):
            return counters.PeakWorkingSetSize
    elif platform.system() == "Linux":
        try:
            for line in Path(f"/proc/{process.pid}/status").read_text().splitlines():
                if line.startswith("VmHWM:"):
                    return int(line.split()[1]) * 1024
        except FileNotFoundError:
            pass
    return 0


workspace = (root / ".build/benchmark/inputs").resolve()
workspace.mkdir(parents=True, exist_ok=True)
results = []
with tempfile.TemporaryDirectory(dir=workspace, prefix="run-") as temporary:
    # Validate the only directory TemporaryDirectory will recursively remove.
    owned = Path(temporary).resolve()
    assert owned != workspace and owned.is_relative_to(workspace)
    for scenario in (["repeated_mixed", "distinct_mixed"] if args.scenario == "both" else [args.scenario]):
        input_file = owned / (scenario + ".log")
        with input_file.open("w", encoding="utf-8", newline="\n", buffering=1 << 20) as output:
            label, previous = "", -1
            for i in range(args.lines):
                second = i // 320
                if second != previous:
                    label = (dt.datetime(2026, 11, 1) + dt.timedelta(seconds=second)).strftime("%d/%b/%Y:%H:%M:%S +0000")
                    previous = second
                ip = "8.8.8.8" if i % 2 == 0 else "2606:4700::1111"
                if scenario == "distinct_mixed":
                    n = i // 2
                    ip = f"11.{(n >> 16) & 255}.{(n >> 8) & 255}.{n & 255}" if i % 2 == 0 else f"2600:100::{n >> 16:x}:{n & 65535:x}"
                output.write(f'{ip} - - [{label}] "GET /api/items HTTP/1.1" 200 100 "-" "Mozilla/5.0"\n')
        pair = []
        for enabled in [False, True]:
            command = [java, "-Xms64m", "-Xmx512m", "-cp", classpath,
                       "io.github.mikoto2000.webaudit.Benchmark", str(input_file)]
            if enabled:
                command += [str(args.country.resolve()), str(args.asn.resolve())]
            with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
                process = subprocess.Popen(command, stdout=stdout, stderr=stderr)
                peak = 0
                while process.poll() is None:
                    peak = max(peak, process_resident_peak(process))
                    time.sleep(0.05)
                stdout.seek(0)
                stderr.seek(0)
                error = stderr.read().decode("utf-8", "replace")
                assert process.returncode == 0, error
                row = json.loads(stdout.read())
            row.update(scenario=scenario, lines=args.lines, peak_sampled_process_resident_bytes=peak,
                       heap_limit_bytes=512 << 20, synthetic=True)
            assert row["parsed"] == args.lines and row["unparsed"] == 0
            pair.append(row)
            results.append(row)
            print(json.dumps(row), flush=True)
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
        assert pair[0]["detection_sha256"] == pair[1]["detection_sha256"], "GeoIP changed detection"
