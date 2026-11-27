"""Verify committed synthetic examples and stage only report artifacts for Pages."""
import hashlib
from html.parser import HTMLParser
import json
from pathlib import Path
import shutil
import sys
from urllib.parse import unquote, urlsplit


class References(HTMLParser):
    def __init__(self, text):
        super().__init__()
        self.ids = set()
        self.links = []
        self.feed(text)

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if "id" in values:
            self.ids.add(values["id"])
        for key in ("href", "src"):
            if values.get(key):
                self.links.append(values[key])


def build(destination):
    root = Path(__file__).resolve().parents[1]
    examples = root / "examples"
    sources = [examples / f"investigation-{lang}" for lang in ("ja", "en")]
    singles = [examples / f"sample-report.{suffix}" for suffix in ("html", "json", "csv")]
    singles.append(examples / "geoip-sample-report.html")
    for source in sources:
        manifest = json.loads((source / "manifest.json").read_text(encoding="utf-8"))
        listed = {"manifest.json"}
        for artifact in manifest["artifacts"]:
            path = source / artifact["path"]
            if not path.resolve().is_relative_to(source.resolve()):
                raise ValueError(f"Artifact outside bundle: {path}")
            data = path.read_bytes()
            if len(data) != artifact["bytes"] or hashlib.sha256(data).hexdigest() != artifact["sha256"]:
                raise ValueError(f"Artifact hash or size mismatch: {path}")
            listed.add(path.relative_to(source).as_posix())
        actual = set()
        for path in source.rglob("*"):
            if path.is_symlink():
                raise ValueError(f"Symlink in report bundle: {path}")
            if path.is_file():
                actual.add(path.relative_to(source).as_posix())
        if actual != listed:
            raise ValueError(f"Unlisted or missing report artifacts: {source}: {actual ^ listed}")
        print(f"Verified {len(listed) - 1} artifacts: {source.name}")

    # Fail rather than overwrite an existing directory, including the repository.
    destination.mkdir(parents=True, exist_ok=False)
    destination = destination.resolve()
    for source in sources:
        shutil.copytree(source, destination / source.name)
    for source in singles:
        shutil.copyfile(source, destination / source.name)
    shutil.copyfile(root / "docs/report-examples/index.html", destination / "index.html")
    (destination / ".nojekyll").touch()

    documents = {
        path: References(path.read_text(encoding="utf-8"))
        for path in destination.rglob("*.html")
        if "templates" not in path.relative_to(destination).parts
    }
    for path, document in documents.items():
        for link in document.links:
            url = urlsplit(link)
            if url.scheme or url.netloc:
                continue
            target = (path.parent / unquote(url.path)).resolve() if url.path else path
            if not target.is_relative_to(destination) or not target.is_file():
                raise ValueError(f"Missing or out-of-site link: {path}: {link}")
            if url.fragment and target in documents and unquote(url.fragment) not in documents[target].ids:
                raise ValueError(f"Missing anchor: {path}: {link}")
    print(f"Verified local links and anchors in {len(documents)} HTML documents")
    print(f"Pages artifact ready: {destination}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Usage: python3 tools/build-report-pages.py NEW_OUTPUT_DIRECTORY")
    build(Path(sys.argv[1]))
