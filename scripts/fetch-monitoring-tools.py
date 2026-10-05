#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Fetch verified official portable Windows monitoring tools into ignored target only."""
import argparse
import hashlib
import json
from pathlib import Path
import stat
import urllib.request
import zipfile


PINNED = {
    "prometheus": {
        "version": "3.15.0", "archive": "prometheus-3.15.0.windows-amd64.zip", "size": 114650144,
        "sha256": "5d333b385557d9adc2ff015d13da9809baccc52fb800a82d1e5c94b79258f87e",
        "checksums_sha256": "023cab1e6b275ee1b8f5f64215a01d74bbb1b19c45183b7296ced4aa4532707b",
        "executables": ["prometheus.exe", "promtool.exe"],
    },
    "alertmanager": {
        "version": "0.34.1", "archive": "alertmanager-0.34.1.windows-amd64.zip", "size": 40131065,
        "sha256": "69624d6ce3674dbcf8cefc5a93d7028d00bbd5e0196a8384907f51593a495fef",
        "checksums_sha256": "0872f3f38d4688872dd9064243d09006ead668690585522e366e624f23931778",
        "executables": ["alertmanager.exe", "amtool.exe"],
    },
}


def file_hash(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def stream_hash(source):
    digest = hashlib.sha256()
    for chunk in iter(lambda: source.read(1024 * 1024), b""):
        digest.update(chunk)
    return digest.hexdigest()


def fetch(url, destination, expected, size=None):
    if destination.exists():
        if file_hash(destination) != expected:
            raise RuntimeError("An existing download differs from the official checksum; refusing overwrite")
        return
    transport = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with transport.open(url, timeout=60) as response, destination.open("xb") as output:
        for chunk in iter(lambda: response.read(1024 * 1024), b""):
            output.write(chunk)
    if file_hash(destination) != expected or (size is not None and destination.stat().st_size != size):
        raise RuntimeError("Official monitoring archive/checksum verification failed; no executable was run")


def checked_destination(repo, requested):
    base = repo.resolve() / "target"
    directory = requested.absolute()
    if (base.is_symlink() or (hasattr(base, "is_junction") and base.is_junction())
            or base.resolve() != base or not directory.is_relative_to(base)):
        raise RuntimeError("Downloads require this checkout's unlinked target directory")
    for ancestor in [directory, *directory.parents]:
        if ancestor == base.parent:
            break
        if ancestor.is_symlink() or (hasattr(ancestor, "is_junction") and ancestor.is_junction()):
            raise RuntimeError("Download paths must not traverse symlinks or junctions")
    if directory.resolve() != directory:
        raise RuntimeError("Downloads must remain beneath this checkout's canonical target directory")
    return directory


def main():
    repo = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--destination", type=Path, default=repo / "target/monitoring-tools")
    args = parser.parse_args()
    directory = checked_destination(repo, args.destination)
    directory.mkdir(parents=True, exist_ok=True)
    manifest = {"schema_version": 1, "platform": "windows-amd64", "tools": {}}
    for name, pin in PINNED.items():
        url = f"https://github.com/prometheus/{name}/releases/download/v{pin['version']}/"
        archive = checked_destination(repo, directory / pin["archive"])
        checksums = checked_destination(repo, directory / f"{name}-{pin['version']}-sha256sums.txt")
        fetch(url + "sha256sums.txt", checksums, pin["checksums_sha256"])
        if f"{pin['sha256']}  {pin['archive']}" not in checksums.read_text().splitlines():
            raise RuntimeError("The official checksum inventory does not bind the selected archive")
        print(f"Fetching verified {name} {pin['version']} ({pin['size']} bytes)", flush=True)
        fetch(url + pin["archive"], archive, pin["sha256"], pin["size"])
        root = checked_destination(repo, directory / archive.stem)
        with zipfile.ZipFile(archive) as bundle:
            for entry in bundle.infolist():
                relative = Path(entry.filename)
                if (relative.is_absolute() or ".." in relative.parts or ":" in entry.filename
                        or stat.S_ISLNK(entry.external_attr >> 16)
                        or not (directory / relative).resolve().is_relative_to(directory)):
                    raise RuntimeError("Archive contains an unsafe path")
                checked_destination(repo, directory / relative)
            if not root.exists():
                bundle.extractall(directory)
            # Existing extracted executables must still equal the verified archive,
            # rather than gaining a new trusted hash merely because they were edited.
            for filename in [*pin["executables"], "LICENSE", "NOTICE"]:
                member = f"{root.name}/{filename}"
                if member in bundle.namelist():
                    with bundle.open(member) as source:
                        if file_hash(root / filename) != stream_hash(source):
                            raise RuntimeError("Extracted executable/license differs from the verified official archive")
        licenses = {path.name: file_hash(path) for path in [root / "LICENSE", root / "NOTICE"] if path.is_file()}
        if "LICENSE" not in licenses:
            raise RuntimeError("Official archive license is missing")
        executables = {binary: file_hash(root / binary) for binary in pin["executables"]}
        manifest["tools"][name] = {"version": pin["version"], "archive": pin["archive"],
            "archive_sha256": pin["sha256"], "checksums_sha256": pin["checksums_sha256"],
            "official_release": url, "licenses_sha256": licenses, "executables_sha256": executables}
    checked_destination(repo, directory / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print("Verified portable tools and licenses retained under ignored target; no global installation.")


if __name__ == "__main__":
    main()
