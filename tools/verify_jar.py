"""Check the independently runnable distribution without loading project classes."""
import hashlib
import json
import sys
import zipfile
from pathlib import Path

def check_jar(jar):
    with zipfile.ZipFile(jar) as archive:
        entries = set(archive.namelist())
        manifest = archive.read("META-INF/MANIFEST.MF").decode()
        assert "Main-Class: io.github.mikoto2000.webaudit.Main" in manifest
        assert "Multi-Release: true" in manifest, "Shaded multi-release dependencies must be enabled"
        required = [
            "rules.json", "parser-patterns.json", "report.ftlh", "upstream/manifest.json",
            "picocli/CommandLine.class", "com/google/re2j/Pattern.class",
            "com/maxmind/db/Reader.class", "freemarker/template/Configuration.class",
            "tools/jackson/databind/json/JsonMapper.class", "org/apache/commons/csv/CSVPrinter.class",
            "META-INF/THIRD_PARTY_NOTICES.md", "META-INF/licenses/webauditJ-LICENSE",
            "META-INF/licenses/dependencies.json",
            "locales/ja.json", "locales/investigation_en.json", "locales/investigation.json",
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
    return dict(jar=str(jar), bytes=jar.stat().st_size,
                          sha256=hashlib.sha256(jar.read_bytes()).hexdigest(), verified=True)


if __name__ == "__main__":
    artifact = Path(sys.argv[1] if len(sys.argv) > 1 else "target/webauditJ.jar")
    print(json.dumps(check_jar(artifact)))
