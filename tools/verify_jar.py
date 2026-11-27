"""Check the independently runnable distribution without loading project classes."""
import hashlib
import json
import sys
import zipfile
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

def check_jar(jar):
    with zipfile.ZipFile(jar) as archive:
        entries = set(archive.namelist())
        manifest = archive.read("META-INF/MANIFEST.MF").decode()
        assert "Main-Class: io.github.mikoto2000.webaudit.Main" in manifest
        assert "Multi-Release: true" in manifest, "Shaded multi-release dependencies must be enabled"
        assert "Enable-Native-Access: ALL-UNNAMED" in manifest, "Watch OS operations require native access"
        required = [
            "audience-content.json", "audience_index.ftlh", "audience_executive.ftlh", "audience_technical.ftlh", "audience.css", "secondary-investigation.js", "report-spec.md", "audience-readme.md",
            "rules.json", "parser-patterns.json", "report.ftlh", "investigation.ftlh", "report-resources.json", "report-aspects.json", "report-aggregate-rules.json", "upstream/manifest.json",
            "picocli/CommandLine.class", "com/google/re2j/Pattern.class",
            "com/maxmind/db/Reader.class", "freemarker/template/Configuration.class",
            "tools/jackson/databind/json/JsonMapper.class", "org/apache/commons/csv/CSVPrinter.class",
            "META-INF/THIRD_PARTY_NOTICES.md", "META-INF/licenses/webauditJ-LICENSE",
            "META-INF/licenses/dependencies.json",
            "locales/ja.json", "locales/investigation_en.json", "locales/investigation.json",
            "io/github/mikoto2000/webaudit/WatchHookChild.class",
        ]
        for name in required:
            assert name in entries, name
        for dependency in json.loads(archive.read("META-INF/licenses/dependencies.json")):
            folder = dependency["artifact"].rsplit("/", 1)[-1] + "-" + dependency["version"]
            for name, expected in dependency["license_files"].items():
                entry = "META-INF/licenses/" + folder + "/" + name
                assert entry in entries, entry
                assert hashlib.sha256(archive.read(entry)).hexdigest() == expected, entry
        assert not any(name.endswith(".mmdb") for name in entries), "Provider databases must not be shipped"
        assert not any(name.endswith("-golden.json") for name in entries), "Test fixtures leaked into JAR"
    with tempfile.TemporaryDirectory(prefix="webauditJ-jar-bundle-") as temporary:
        base = Path(temporary)
        source = base / "access.log"
        source.write_text('192.0.2.1 - - [01/Nov/2026:00:00:00 +0000] "GET /.env HTTP/1.1" 404 0\n', encoding="utf-8")
        destination = base / "report"
        environment = dict(os.environ, XDG_DATA_HOME=str(base / "data"), LOCALAPPDATA=str(base / "data"))
        run = subprocess.run([shutil.which("java"), "-Xmx256m", "-jar", str(jar.resolve()), str(source), "--report-dir", str(destination), "--lang", "en"], env=environment, capture_output=True, text=True, encoding="utf-8", timeout=60)
        assert run.returncode == 0, run.stderr
        manifest = json.loads((destination / "manifest.json").read_text(encoding="utf-8"))
        assert manifest["build"]["artifact_sha256"] == hashlib.sha256(jar.read_bytes()).hexdigest()
        assert manifest["build"]["artifact_hash_scope"] == "distribution_jar_bytes_at_manifest_generation"
        for artifact in manifest["artifacts"]:
            assert hashlib.sha256((destination / artifact["path"]).read_bytes()).hexdigest() == artifact["sha256"]
    return dict(jar=str(jar), bytes=jar.stat().st_size,
                          sha256=hashlib.sha256(jar.read_bytes()).hexdigest(), verified=True)


if __name__ == "__main__":
    artifact = Path(sys.argv[1] if len(sys.argv) > 1 else "target/webauditJ.jar")
    print(json.dumps(check_jar(artifact)))
