#!/usr/bin/env python3
"""Bind release payloads to source and verify the complete archive before use.

This is a build/release gate. Archive hashes do not replace signature verification,
native review, real-provider acceptance, or an independently qualified fresh host.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import tarfile
import tempfile
import tomllib

BINS = ("opaqued", "opaque", "opaque-mcp", "opaque-mcp-contract",
        "opaque-approve-helper", "opaque-approver", "opaque-evidence", "opaque-web")
LICENSE_FILES = ("LICENSE", "LICENSE-DOCS", "NOTICE")
MANIFEST = "opaque-release.json"
APP = "Opaque Reviewer.app"
TARGETS = ("aarch64-apple-darwin", "x86_64-apple-darwin",
           "aarch64-unknown-linux-gnu", "x86_64-unknown-linux-gnu")
MAX_BYTES = 2 * 1024**3
MAX_FILES = 4096


def run(args, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, timeout=60, **kwargs)


def source_git_command(source, *args):
    # A contained installer may read a host-owned checkout. Trust only the
    # explicit canonical source root for this command, never global config.
    root = str(Path(source).resolve())
    return ["git", "-c", "safe.directory=" + root, "-C", root, *args]


def digest(data):
    return hashlib.sha256(data).hexdigest()


def valid_path(name):
    path = PurePosixPath(name)
    return (name == path.as_posix() and not path.is_absolute()
            and not any(part in ("", ".", "..") for part in path.parts)
            and "\\" not in name and not any(ord(c) < 32 for c in name))


def payload_path(name, target):
    return name in BINS + LICENSE_FILES or (target.endswith("apple-darwin") and name.startswith(APP + "/"))


def create_manifest(source, binary_dir, target, version, revision, allow_dirty=False):
    source, binary_dir = Path(source).resolve(), Path(binary_dir).resolve()
    if target not in TARGETS or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?", version):
        raise ValueError("unsupported target or invalid version")
    head = run(source_git_command(source, "rev-parse", "HEAD")).stdout.decode().strip()
    if head != revision or not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("expected revision does not match source HEAD")
    cargo = tomllib.loads((source / "Cargo.toml").read_text())
    if cargo["workspace"]["package"]["version"] != version:
        raise ValueError("release version does not match Cargo.toml")
    dirty = bool(run(source_git_command(source, "status", "--porcelain", "--untracked-files=all")).stdout)
    if dirty and not allow_dirty:
        raise ValueError("release source must be clean; --allow-dirty creates a local candidate only")
    source_names = run(source_git_command(source, "ls-files", "-z", "--cached", "--others", "--exclude-standard")).stdout
    source_hash = hashlib.sha256()
    for raw in sorted(set(source_names.split(b"\0")) - {b""}):
        name = os.fsdecode(raw)
        path = source / name
        source_hash.update(raw + b"\0")
        if path.is_symlink():
            source_hash.update(b"symlink\0" + os.fsencode(os.readlink(path)))
        elif path.is_file():
            source_hash.update(b"file\0" + bytes.fromhex(digest(path.read_bytes())))
        else:
            source_hash.update(b"absent\0")
    # Copy the exact source notices before hashing the distributable payload.
    for name in LICENSE_FILES:
        origin, destination = source / name, binary_dir / name
        if origin.is_symlink() or not origin.is_file() or destination.is_symlink():
            raise ValueError(f"missing or linked release license: {name}")
        destination.write_bytes(origin.read_bytes())
        destination.chmod(0o644)
    paths = [binary_dir / name for name in BINS + LICENSE_FILES]
    if target.endswith("apple-darwin"):
        app = binary_dir / APP
        if not (app / "Contents/Info.plist").is_file() or not (app / "Contents/MacOS/OpaqueReviewer").is_file():
            raise ValueError("macOS archive requires the complete reviewer app")
        paths.extend(p for p in app.rglob("*") if not p.is_dir())
    files = {}
    for path in paths:
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"missing or linked release payload: {path.name}")
        name = path.relative_to(binary_dir).as_posix()
        if not valid_path(name) or not payload_path(name, target):
            raise ValueError("invalid release payload path")
        content = path.read_bytes()
        files[name] = {"sha256": digest(content), "bytes": len(content),
                       "executable": bool(path.stat().st_mode & 0o111)}
    if any(not files[name]["executable"] for name in BINS):
        raise ValueError("release binaries must be executable")
    if len(files) > MAX_FILES or sum(entry["bytes"] for entry in files.values()) > MAX_BYTES:
        raise ValueError("release payload exceeds bounds")
    manifest = {"schema": "opaque.release.v1", "version": version, "target": target,
                "source_revision": revision, "source_tree_sha256": source_hash.hexdigest(),
                "source_dirty": dirty, "qualification": "local_candidate" if dirty else "build_candidate",
                "files": dict(sorted(files.items()))}
    (binary_dir / MANIFEST).write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n")
    return manifest


def verify_archive(archive, *, version, revision, target, allow_dirty=False, smoke=False):
    if target not in TARGETS:
        raise ValueError("unsupported target")
    with tarfile.open(archive, "r:gz") as stream:
        members = {}
        total = 0
        for member in stream:
            if len(members) >= MAX_FILES or member.name in members or not valid_path(member.name):
                raise ValueError("duplicate, invalid or excessive archive entries")
            if not (member.isfile() or member.isdir()) or member.mode & 0o7000:
                raise ValueError("links, special files and privileged modes are forbidden")
            if member.name != MANIFEST and not (payload_path(member.name, target) or member.name == APP):
                raise ValueError("unexpected archive payload")
            total += member.size
            if member.size < 0 or total > MAX_BYTES:
                raise ValueError("archive exceeds size bounds")
            members[member.name] = member
        manifest_entry = members.get(MANIFEST)
        if manifest_entry is None or not manifest_entry.isfile() or manifest_entry.size > 1024**2:
            raise ValueError("missing or oversized release manifest")
        manifest = json.load(stream.extractfile(manifest_entry))
        expected = {"schema": "opaque.release.v1", "version": version,
                    "source_revision": revision, "target": target}
        if any(manifest.get(key) != value for key, value in expected.items()):
            raise ValueError("release identity mismatch")
        if not re.fullmatch(r"[0-9a-f]{40}", revision) or not re.fullmatch(r"[0-9a-f]{64}", manifest.get("source_tree_sha256", "")):
            raise ValueError("invalid source identity")
        if type(manifest.get("source_dirty")) is not bool or (manifest["source_dirty"] and not allow_dirty):
            raise ValueError("dirty source is not a release")
        if manifest.get("qualification") != ("local_candidate" if manifest["source_dirty"] else "build_candidate"):
            raise ValueError("unsupported qualification claim")
        payload = {name for name, item in members.items() if item.isfile() and name != MANIFEST}
        files = manifest.get("files")
        if not isinstance(files, dict) or set(files) != payload or not set(BINS + LICENSE_FILES) <= payload:
            raise ValueError("archive and manifest payload sets differ or a required tool is missing")
        if target.endswith("apple-darwin") and not {APP + "/Contents/Info.plist", APP + "/Contents/MacOS/OpaqueReviewer"} <= payload:
            raise ValueError("macOS reviewer app is missing")
        with tempfile.TemporaryDirectory(prefix="opaque-release-smoke-") as temporary:
            root = Path(temporary)
            for name in sorted(payload):
                member = members[name]
                data = stream.extractfile(member).read()
                expected = {"sha256": digest(data), "bytes": len(data), "executable": bool(member.mode & 0o111)}
                if files[name] != expected or (name in BINS and not expected["executable"]):
                    raise ValueError(f"payload verification failed: {name}")
                if smoke:
                    path = root / name
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(data)
                    path.chmod(0o755 if expected["executable"] else 0o644)
            if smoke:
                # The caller has explicitly selected trusted build artifacts for
                # execution. No provider calls, daemon startup or native prompt.
                clean_home = root / "home"
                clean_home.mkdir(mode=0o700)
                environment = {"HOME": str(clean_home), "PATH": "/usr/bin:/bin", "TMPDIR": str(root)}
                for name in ("opaque", "opaqued", "opaque-mcp", "opaque-mcp-contract", "opaque-approver", "opaque-evidence", "opaque-web"):
                    run([str(root / name), "--help"], env=environment)
                for name in ("opaque", "opaqued"):
                    output = run([str(root / name), "--version"], env=environment).stdout.decode().strip()
                    compiled = re.fullmatch(re.escape(f"{name} {version}") + r"\+([0-9a-f]{7,40})", output)
                    if compiled is None or not revision.startswith(compiled[1]):
                        raise ValueError(f"installed binary version mismatch: {name}")
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    create = sub.add_parser("manifest")
    create.add_argument("--source", type=Path, default=Path.cwd())
    create.add_argument("--binary-dir", type=Path, required=True)
    verify = sub.add_parser("verify")
    verify.add_argument("--archive", type=Path, required=True)
    verify.add_argument("--smoke", action="store_true", help="execute selected trusted archive CLIs in an isolated home")
    for command in (create, verify):
        command.add_argument("--version", required=True)
        command.add_argument("--revision", required=True)
        command.add_argument("--target", choices=TARGETS, required=True)
        command.add_argument("--allow-dirty", action="store_true")
    args = parser.parse_args()
    try:
        if args.command == "manifest":
            result = create_manifest(args.source, args.binary_dir, args.target, args.version, args.revision, args.allow_dirty)
        else:
            result = verify_archive(args.archive, version=args.version, revision=args.revision,
                                    target=args.target, allow_dirty=args.allow_dirty, smoke=args.smoke)
        print(json.dumps({key: result[key] for key in ("schema", "version", "target", "source_revision", "qualification")}, sort_keys=True))
    except (ValueError, OSError, subprocess.SubprocessError, tarfile.TarError) as error:
        parser.exit(1, f"release artifact gate: {error}\n")


if __name__ == "__main__":
    main()
