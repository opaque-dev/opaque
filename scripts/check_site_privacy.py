#!/usr/bin/env python3
"""Verify the generated visitor site; never publish or upload the artifact.

--build copies docs into temporary storage, marks private sources, runs the real
MkDocs build, and inspects the complete output before deleting the fixture.
--site-dir inspects an existing deployment artifact with the same route policy.
"""
from __future__ import annotations

import argparse
import gzip
import html
import io
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
from urllib.parse import unquote, urlsplit
import uuid
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parent.parent
# This visitor-content allowlist is independent of navigation. Adding a page to
# mkdocs.yml alone must not authorize publication of an internal document.
PUBLIC_ROUTES = frozenset({
    "", "adversarial-security-review-2026-02-14", "architecture", "audit-analytics",
    "aws", "azure", "gcp", "bitwarden", "blog/why-we-built-opaque", "demos", "deployment",
    "bounded-work", "compliance/certification-roadmap", "compliance/control-mapping",
    "compliance/fips-assessment", "compliance/hardening", "compliance/verifying-releases",
    "enterprise-architecture", "evaluation-guide", "evidence-checkpoints", "federation", "getting-started",
    "mcp-qualified-tools", "github-ci-inference", "github-secret-inventory",
    "installable-releases", "ssh-health", "workload-attestation",
    "hosted-demo", "identity", "linux-polkit", "llm-harness", "mcp-integration",
    "mobile-approvals", "operations", "policy", "roadmap-deferred",
    "remote-approvals", "reusable-core", "scoped-authority", "authority-policy",
    "scope-evidence", "scope-recovery",
    "security-assessment", "storage", "testing-coverage", "tutorial", "vault",
    "web-dashboard", "site",  # Existing tracked docs/site/index.html landing page.
})
PUBLIC_HTML = frozenset({"index.html", "404.html"}) | frozenset(
    f"{route}/index.html" for route in PUBLIC_ROUTES if route
)
PRIVATE_NAMES = frozenset({"product", "dogfood", "release-dogfood", "tenant-boundaries"})
PRIVATE_REFERENCES = re.compile(
    r"(?:^|[/\\])(?:product(?:[/\\]|$)|(?:dogfood|release-dogfood|tenant-boundaries)(?:[/\\.#?]|$))"
)
MAX_ASSET_BYTES = 64 * 1024 * 1024


def decoded(value: str) -> str:
    # Catch encoded path separators as well as HTML attribute escaping. Repeated
    # encoding is bounded to keep adversarial artifacts cheap to inspect.
    for _ in range(4):
        expanded = unquote(html.unescape(value))
        if expanded == value:
            break
        value = expanded
    return value


def route_of(location: str) -> str:
    path = urlsplit(decoded(location)).path.strip("/")
    if path == "index.html":
        return ""
    return path.removesuffix("/index.html").rstrip("/")


def read_asset(path: Path) -> bytes:
    if path.stat().st_size > MAX_ASSET_BYTES:
        raise ValueError("asset exceeds the inspection size bound")
    content = path.read_bytes()
    if path.suffix == ".gz":
        with gzip.GzipFile(fileobj=io.BytesIO(content)) as stream:
            content = stream.read(MAX_ASSET_BYTES + 1)
        if len(content) > MAX_ASSET_BYTES:
            raise ValueError("expanded asset exceeds the inspection size bound")
    elif path.suffix in {".br", ".zip", ".tar", ".tgz", ".zst", ".xz"}:
        raise ValueError("compressed asset format requires an explicit inspection implementation")
    return content


def inspect_site(site: Path, sentinel: str | None = None) -> list[str]:
    """Return artifact-relative findings without printing any private content."""
    failures: list[str] = []
    if not site.is_dir():
        return ["generated site directory is missing"]
    marker = sentinel.encode() if sentinel else None
    files = sorted(path for path in site.rglob("*") if path.is_file() or path.is_symlink())
    for path in files:
        name = path.relative_to(site).as_posix()
        if path.is_symlink():
            failures.append(f"{name}: symlink cannot be a publication asset")
            continue
        normalized = decoded(name)
        if any(part.split(".")[0] in PRIVATE_NAMES for part in normalized.split("/")):
            failures.append(f"{name}: private document path")
        suffix = Path(normalized).suffix.lower()
        if suffix == ".html" and name not in PUBLIC_HTML:
            failures.append(f"{name}: HTML page is not on the visitor allowlist")
        if suffix == ".md":
            failures.append(f"{name}: raw Markdown source must not be published")
        try:
            content = read_asset(path)
        except (OSError, ValueError, EOFError) as error:
            failures.append(f"{name}: inspection failed ({type(error).__name__})")
            continue
        if marker and marker in content:
            failures.append(f"{name}: private source sentinel leaked")
        text = decoded(content.decode("utf-8", errors="ignore"))
        if PRIVATE_REFERENCES.search(text):
            failures.append(f"{name}: reference to a private document route")

    for required in ("index.html", "search/search_index.json", "sitemap.xml"):
        if not (site / required).is_file():
            failures.append(f"{required}: required publication evidence is missing")
    search = site / "search/search_index.json"
    if search.is_file():
        try:
            entries = json.loads(read_asset(search))["docs"]
            if not isinstance(entries, list) or not entries:
                raise ValueError("empty search evidence")
            for entry in entries:
                location = entry["location"]
                if not isinstance(location, str) or route_of(location) not in PUBLIC_ROUTES:
                    failures.append("search/search_index.json: non-visitor route indexed")
        except (OSError, ValueError, TypeError, KeyError):
            failures.append("search/search_index.json: malformed search evidence")
    sitemap = site / "sitemap.xml"
    if sitemap.is_file():
        try:
            locations = ET.fromstring(read_asset(sitemap)).findall(".//{*}loc")
            if not locations:
                raise ValueError("empty sitemap evidence")
            if any(route_of(location.text or "") not in PUBLIC_ROUTES for location in locations):
                failures.append("sitemap.xml: non-visitor route indexed")
        except (OSError, ValueError, ET.ParseError):
            failures.append("sitemap.xml: malformed sitemap evidence")
    compressed_sitemap = site / "sitemap.xml.gz"
    if sitemap.is_file() and compressed_sitemap.is_file():
        try:
            if read_asset(compressed_sitemap) != read_asset(sitemap):
                failures.append("sitemap.xml.gz: compressed sitemap differs from the inspected sitemap")
        except (OSError, ValueError, EOFError):
            failures.append("sitemap.xml.gz: compressed sitemap cannot be inspected")
    return failures


def mark_private_sources(docs: Path, sentinel: str) -> int:
    private = docs / "product"
    private.mkdir(exist_ok=True)
    (private / "privacy-check.md").write_text("# Private build fixture\n", encoding="utf-8")
    (private / "privacy-check.txt").write_text(sentinel, encoding="utf-8")
    sources = list(private.rglob("*.md"))
    sources.extend(docs / f"{name}.md" for name in PRIVATE_NAMES - {"product"})
    sources.append(docs / "README.md")
    for source in sources:
        with source.open("a", encoding="utf-8") as stream:
            stream.write(f"\n\n{sentinel}\n")
    return len(sources) + 1


def build_and_inspect(repository: Path = ROOT) -> list[str]:
    with tempfile.TemporaryDirectory(prefix="opaque-site-privacy-") as temporary:
        fixture = Path(temporary)
        shutil.copytree(repository / "docs", fixture / "docs")
        shutil.copy2(repository / "mkdocs.yml", fixture / "mkdocs.yml")
        # The build hook publishes only the checked brand manifest. Copy its
        # source into the isolated fixture rather than using publication symlinks.
        (fixture / "scripts").mkdir()
        shutil.copy2(repository / "scripts/mkdocs_brand.py", fixture / "scripts/mkdocs_brand.py")
        shutil.copytree(repository / "assets/brand", fixture / "assets/brand")
        sentinel = "OPAQUEPRIVATE" + uuid.uuid4().hex.upper()
        marked = mark_private_sources(fixture / "docs", sentinel)
        site = fixture / "artifact"
        subprocess.run([
            sys.executable, "-m", "mkdocs", "build", "--strict", "--config-file",
            str(fixture / "mkdocs.yml"), "--site-dir", str(site),
        ], check=True, cwd=fixture, timeout=120)
        failures = inspect_site(site, sentinel)
        if not failures:
            print(f"Privacy check passed: {marked} private source fixtures excluded; HTML, assets, search and sitemap inspected.")
        return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--build", action="store_true")
    mode.add_argument("--site-dir", type=Path)
    arguments = parser.parse_args()
    try:
        failures = build_and_inspect() if arguments.build else inspect_site(arguments.site_dir)
    except (OSError, subprocess.SubprocessError) as error:
        print(f"Privacy build failed: {type(error).__name__}", file=sys.stderr)
        return 1
    for failure in failures:
        print(failure, file=sys.stderr)
    return int(bool(failures))


if __name__ == "__main__":
    raise SystemExit(main())
