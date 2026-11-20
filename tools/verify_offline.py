"""Linux amd64: all-thread kernel network denial before application main.

The test-only Java agent lets JVM/libc initialization finish, initializes literal
IP support, and installs a TSYNC seccomp filter before the application starts.
Any subsequent socket/connect/send/receive syscall kills the JVM. The guard is
self-tested. Synthetic fixtures need no external service or provider database.
"""
import hashlib
import json
import os
import platform
import resource
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

assert platform.system() == "Linux" and platform.machine() == "x86_64"


def disable_core():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


root = Path(__file__).resolve().parents[1]
jar = Path(sys.argv[1] if len(sys.argv) > 1 else root / "target/webauditJ.jar").resolve()
java = shutil.which("java")
assert java
count = 0

with tempfile.TemporaryDirectory(prefix="webauditJ-offline-") as temporary:
    base = Path(temporary)
    agent_classes = base / "agent"
    agent_classes.mkdir()
    javac = str(Path(java).resolve().parent / "javac")
    subprocess.run([javac, "-d", str(agent_classes), str(root / "tools/OfflineGuard.java")], check=True)
    import zipfile
    agent = base / "offline-guard.jar"
    with zipfile.ZipFile(agent, "w") as archive:
        archive.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\r\nPremain-Class: OfflineGuard\r\n\r\n")
        archive.write(agent_classes / "OfflineGuard.class", "OfflineGuard.class")
    guard_args = [java, "-Xmx256m", "-XX:+DisableAttachMechanism", "--enable-native-access=ALL-UNNAMED", "-javaagent:" + str(agent)]
    probe = subprocess.run([*guard_args[:-1], guard_args[-1] + "=probe", "-version"],
                           preexec_fn=disable_core, capture_output=True)
    assert probe.returncode < 0, ("Network guard did not stop socket creation", probe.returncode, probe.stderr[-2000:])
    app = base / "webauditJ.jar"
    shutil.copyfile(jar, app)
    env = dict(os.environ, XDG_DATA_HOME=str(base / "data"))
    log = base / "access.log"
    log.write_text("".join(f'{ip} - - [01/Nov/2026:00:00:00 +0000] "GET /.env HTTP/1.1" 404 0\n'
                           for ip in ["8.8.8.8", "8.8.8.8", "2606:4700::1111", "1.1.1.1", "10.0.0.1"]),
                   encoding="utf-8")

    def run(args, code=0):
        global count
        result = subprocess.run([*guard_args, "-jar", str(app), *args],
                                cwd="/", env=env, preexec_fn=disable_core, capture_output=True,
                                text=True, timeout=60)
        assert result.returncode == code, (args, result.returncode, result.stderr[-2000:])
        count += 1
        return result

    assert "Not installed" in run(["geoip", "status"]).stdout
    fixture = root / "src/test/resources/geoip"
    explicit = ["--geoip-country", str(fixture / "country.mmdb"), "--geoip-asn", str(fixture / "asn.mmdb")]
    for extra in [[], explicit]:
        for fmt in ["json", "csv", "html"]:
            result = run([str(log), "--format", fmt, *extra])
            if fmt == "json":
                assert ("geoip" in json.loads(result.stdout)) == bool(extra)
    legacy = base / "geoip"
    legacy.mkdir()
    for role in ["country", "asn"]:
        shutil.copyfile(fixture / (role + ".mmdb"), legacy / (role + ".mmdb"))
    assert json.loads(run([str(log), "--format", "json"]).stdout)["geoip"]["databases"]
    managed = Path(env["XDG_DATA_HOME"]) / "webauditJ/geoip"
    generation = managed / "versions/gen-offline"
    generation.mkdir(parents=True)
    databases = []
    for role in ["country", "asn"]:
        data = (fixture / (role + ".mmdb")).read_bytes()
        (generation / (role + ".mmdb")).write_bytes(data)
        databases.append(dict(role=role, provider="DB-IP Lite",
                              type="DBIP-" + ("Country" if role == "country" else "ASN") + "-Lite",
                              version="2026-11",
                              url="https://download.db-ip.com/free/dbip-" + role + "-lite-2026-11.mmdb.gz",
                              downloaded_at="2026-11-20T00:00:00Z", build_time="2026-11-01T00:00:00Z",
                              size=len(data), sha256=hashlib.sha256(data).hexdigest(),
                              source_sha1=hashlib.sha1(data).hexdigest(),
                              file="versions/gen-offline/" + role + ".mmdb"))
    (managed / "metadata.json").write_text(json.dumps(dict(
        format=1, current=dict(id="gen-offline", databases=databases),
        last_checked_at="2026-11-20T00:00:00Z")), encoding="utf-8")
    for operation in ["status", "download"]:
        assert "2026-11" in run(["geoip", operation]).stdout
    for fmt in ["json", "csv", "html"]:
        result = run([str(log), "--format", fmt])
        assert "2026-11" in result.stdout
        if fmt == "json":
            assert json.loads(result.stdout)["geoip"]["databases"][0]["generation"] == "gen-offline"
    (generation / "country.mmdb").write_bytes(b"corrupt")
    assert "FAILED" in run(["geoip", "status"], 1).stderr
    result = run([str(log), "--format", "json"])
    assert "geoip" not in json.loads(result.stdout)
    assert "Managed GeoIP unavailable" in result.stderr

print(json.dumps(dict(passed=True, invocations=count, kernel_network_denial=True)))
