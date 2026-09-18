"""Check built distributions for required and prohibited release content."""

from __future__ import annotations

import argparse
import tarfile
import zipfile
from collections.abc import Iterable
from pathlib import Path, PurePosixPath

_REQUIRED_PACKAGE_ASSET = PurePosixPath(
    "nest_authz/integrations/nandatown/delegated_authority.yaml"
)
_FORBIDDEN_PARTS = {
    ".coverage",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "__pycache__",
}
_FORBIDDEN_SUFFIXES = {
    ".db",
    ".key",
    ".pem",
    ".pyc",
    ".pyo",
    ".sqlite",
    ".sqlite3",
}
_PRIVATE_KEY_MARKERS = (
    b"-----BEGIN " + b"PRIVATE KEY-----",
    b"-----BEGIN OPENSSH " + b"PRIVATE KEY-----",
)


def _check_names(names: Iterable[str], *, artifact: Path) -> tuple[str, ...]:
    normalized = tuple(name.replace("\\", "/") for name in names)
    failures: list[str] = []
    for name in normalized:
        path = PurePosixPath(name)
        if any(part in _FORBIDDEN_PARTS for part in path.parts):
            failures.append(f"{artifact.name}: cache path packaged: {name}")
        if path.suffix.lower() in _FORBIDDEN_SUFFIXES:
            failures.append(f"{artifact.name}: prohibited file packaged: {name}")
    return tuple(failures)


def _inspect_wheel(path: Path) -> tuple[str, ...]:
    failures: list[str] = []
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        failures.extend(_check_names(names, artifact=path))
        if str(_REQUIRED_PACKAGE_ASSET) not in names:
            failures.append(
                f"{path.name}: missing packaged scenario {_REQUIRED_PACKAGE_ASSET}"
            )
        for info in archive.infolist():
            if info.is_dir():
                continue
            payload = archive.read(info)
            if any(marker in payload for marker in _PRIVATE_KEY_MARKERS):
                failures.append(
                    f"{path.name}: PEM private-key marker in {info.filename}"
                )
    return tuple(failures)


def _inspect_sdist(path: Path) -> tuple[str, ...]:
    failures: list[str] = []
    with tarfile.open(path, mode="r:gz") as archive:
        members = tuple(item for item in archive.getmembers() if item.isfile())
        names = tuple(item.name for item in members)
        failures.extend(_check_names(names, artifact=path))
        stripped = tuple("/".join(name.split("/")[1:]) for name in names)
        required = {
            "README.md",
            "docs/adr/0014-v1-release-readiness.md",
            "docs/nandatown-demo.md",
            "docs/release-evidence.md",
            "src/nest_authz/integrations/nandatown/delegated_authority.yaml",
        }
        for required_name in sorted(required):
            if required_name not in stripped:
                failures.append(f"{path.name}: missing {required_name}")
        for member in members:
            stream = archive.extractfile(member)
            if stream is None:
                continue
            payload = stream.read()
            if any(marker in payload for marker in _PRIVATE_KEY_MARKERS):
                failures.append(f"{path.name}: PEM private-key marker in {member.name}")
    return tuple(failures)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("dist", nargs="?", default="dist", type=Path)
    args = parser.parse_args()

    wheels = sorted(args.dist.glob("*.whl"))
    sdists = sorted(args.dist.glob("*.tar.gz"))
    if len(wheels) != 1 or len(sdists) != 1:
        print(
            "expected exactly one wheel and one source distribution; "
            f"found {len(wheels)} wheel(s) and {len(sdists)} sdist(s)"
        )
        return 1

    failures = [*_inspect_wheel(wheels[0]), *_inspect_sdist(sdists[0])]
    if failures:
        for failure in failures:
            print(f"FAIL: {failure}")
        return 1

    print(f"OK: inspected {wheels[0].name}")
    print(f"OK: inspected {sdists[0].name}")
    print(f"OK: wheel includes {_REQUIRED_PACKAGE_ASSET}")
    print("OK: no caches, SQLite files, private-key files, or PEM private keys")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
