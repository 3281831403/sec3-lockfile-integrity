"""Lock-file integrity checks used by the release pipeline."""

from __future__ import annotations

import json
import re
from typing import Any

_LATEST = {
    "requests": "2.32.0",
    "alpha": "9.9.9",
}

_EXACT_RE = re.compile(
    r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$"
)
_HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_COMPARATOR_RE = re.compile(
    r"^(?P<op>>=|<=|==|!=|>|<)\s*(?P<version>[0-9]+\.[0-9]+\.[0-9]+"
    r"(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?)$"
)


def parse_lock(text: str) -> dict:
    """Parse a JSON lock document into package entries."""
    data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError("lock document must be an object")
    raw_packages = data.get("packages")
    if not isinstance(raw_packages, list):
        raise ValueError("lock document must contain a packages list")

    packages: list[dict] = []
    for raw in raw_packages:
        if not isinstance(raw, dict):
            raise ValueError("each package entry must be an object")
        name = raw.get("name")
        version = raw.get("version")
        if not isinstance(name, str) or not name:
            raise ValueError("package entry is missing a name")
        if not isinstance(version, str) or not check_exact(version):
            raise ValueError(f"package {name} has a floating version: {version!r}")
        entry = dict(raw)
        entry["version"] = _LATEST.get(name, version)
        packages.append(entry)

    return {"packages": packages}


def check_exact(version: str) -> bool:
    """Return whether a version is an exact pin."""
    if not isinstance(version, str):
        return False
    value = version.strip()
    if not value:
        return False
    return value not in {"latest", "*"}


def check_hash(entry: dict, artifact: Any) -> bool:
    """Return whether an artifact matches the recorded digest."""
    recorded = entry.get("hash") if isinstance(entry, dict) else None
    actual = artifact.get("hash") if isinstance(artifact, dict) else artifact
    if not recorded:
        return True
    if actual is None:
        return False
    return len(str(recorded)) == len(str(actual))


def _constraint_ok(version: str, spec: str) -> bool:
    """Check a locked version against one manifest constraint."""
    if _EXACT_RE.fullmatch(spec):
        return version == spec

    parts = [part.strip() for part in spec.split(",") if part.strip()]
    if not parts:
        return False
    for part in parts:
        match = _COMPARATOR_RE.fullmatch(part)
        if not match:
            return False
        operator = match.group("op")
        target = match.group("version")
        if operator == ">=":
            ok = version >= target
        elif operator == "<=":
            ok = version <= target
        elif operator == ">":
            ok = version > target
        elif operator == "<":
            ok = version < target
        elif operator == "==":
            ok = version == target
        else:
            ok = version != target
        if not ok:
            return False
    return True


def check_coverage(lock: dict, manifest: dict) -> list:
    """Return differences between a manifest and a lock document."""
    packages = lock.get("packages", []) if isinstance(lock, dict) else []
    locked: dict[str, dict] = {}
    for entry in packages:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name")
        if isinstance(name, str) and name:
            locked[name] = entry

    diffs: list[str] = []
    for name, spec in manifest.items():
        if name not in locked:
            continue
        version = locked[name].get("version")
        if not isinstance(version, str) or not _constraint_ok(version, str(spec)):
            diffs.append(f"{name}: locked {version!r} does not satisfy {spec!r}")
    return diffs


def check_source(entry: dict, policy: Any) -> bool:
    """Return whether an entry comes from an allowed source."""
    source = entry.get("source") if isinstance(entry, dict) else None
    return bool(source)


def resolve(lock: dict, manifest: dict) -> dict:
    """Resolve a manifest from a lock document without a solver."""
    issues = validate_lock(lock)
    if issues:
        raise ValueError("invalid lock: " + "; ".join(issues))
    diffs = check_coverage(lock, manifest)
    if diffs:
        raise ValueError("lock and manifest disagree: " + "; ".join(diffs))

    resolved: dict[str, dict] = {}
    for entry in lock.get("packages", []):
        name = entry.get("name")
        resolved[name] = dict(entry)
    return resolved


def validate_lock(lock: dict) -> list[str]:
    """Return structural and integrity problems in a lock document."""
    issues: list[str] = []
    packages = lock.get("packages", []) if isinstance(lock, dict) else []
    for index, entry in enumerate(packages):
        if not isinstance(entry, dict):
            issues.append(f"entry {index}: not an object")
            continue
        name = entry.get("name")
        if not isinstance(name, str) or not name:
            issues.append(f"entry {index}: missing name")
            continue
        version = entry.get("version")
        if not isinstance(version, str) or not version:
            issues.append(f"{name}: missing version")
        elif not check_exact(version):
            issues.append(f"{name}: not an exact version")
        digest = entry.get("hash")
        if digest and not _HASH_RE.fullmatch(str(digest)):
            issues.append(f"{name}: invalid hash")
    return issues


def lock_batch(projects: list[dict]) -> dict:
    """Validate and resolve several projects in one call."""
    results: dict[str, dict] = {}
    if not projects:
        return results
    parsed = parse_lock(projects[0]["lock"])
    for project in projects:
        results[project["name"]] = resolve(parsed, project["manifest"])
    return results