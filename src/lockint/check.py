"""Lock-file integrity checks used by the release pipeline.

A lock document is the single source of truth for a reproducible build:

* every dependency must be present with an *exact* version pin;
* every entry records a content hash that must match the artifact;
* the lock document must agree with the manifest;
* floating version ranges are rejected everywhere;
* every entry must come from a source matching the locked record;
* batch validation treats every project independently.

The same lock document therefore always resolves to the same dependency
set, twice in a row, on any machine.
"""

from __future__ import annotations

import hmac
import json
import re
from typing import Any

_EXACT_RE = re.compile(
    r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$"
)
_HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def check_exact(version: Any) -> bool:
    """Return whether a version is an exact pin (no floating ranges).

    Only a fully pinned ``major.minor.patch`` release (optionally with
    pre-release / build metadata) is accepted. Ranges such as ``^1.2.3``,
    ``~=1.2``, ``>=1.0``, ``1.2.*``, ``latest`` and ``*`` are rejected.
    """
    if not isinstance(version, str):
        return False
    value = version.strip()
    if not value:
        return False
    return _EXACT_RE.fullmatch(value) is not None


def parse_lock(text: str) -> dict:
    """Parse a JSON lock document into package entries.

    Locked versions are preserved verbatim: a lock file is never
    rewritten to float to a newer release. A floating version raises
    ``ValueError`` so a build can never silently upgrade a dependency.
    """
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
        if not isinstance(name, str) or not name:
            raise ValueError("package entry is missing a name")
        version = raw.get("version")
        if not isinstance(version, str) or not check_exact(version):
            raise ValueError(
                f"package {name} has a floating version: {version!r}"
            )
        entry = dict(raw)
        # Canonical, whitespace-free pin so later comparisons are stable
        # and repeated parses yield identical entries.
        entry["version"] = version.strip()
        packages.append(entry)

    return {"packages": packages}


def check_hash(entry: dict, artifact: Any) -> bool:
    """Return whether an artifact matches the recorded digest.

    ``artifact`` is either the digest string itself or an object carrying
    a ``hash`` field. Full digests are compared, never their lengths. A
    lock entry without a valid recorded hash fails closed.
    """
    if not isinstance(entry, dict):
        return False
    recorded = entry.get("hash")
    if not isinstance(recorded, str) or not _HASH_RE.fullmatch(recorded):
        return False

    actual = artifact.get("hash") if isinstance(artifact, dict) else artifact
    if not isinstance(actual, str) or not _HASH_RE.fullmatch(actual):
        return False

    return hmac.compare_digest(recorded, actual)


def _constraint_ok(version: str, spec: Any) -> bool:
    """Check a locked version against one manifest constraint.

    Only an exact pin is accepted: any floating range makes the
    constraint invalid, since a range can resolve differently on every
    build.
    """
    if not isinstance(version, str) or not isinstance(spec, str):
        return False
    spec = spec.strip()
    if not check_exact(spec):
        return False
    return version.strip() == spec


def check_coverage(lock: dict, manifest: dict) -> list:
    """Return differences between a manifest and a lock document.

    Every manifest dependency must be covered by the lock, and the locked
    version must equal the manifest pin exactly. Missing packages,
    mismatched versions and floating ranges are all reported instead of
    being silently ignored.
    """
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
            diffs.append(
                f"{name}: required by manifest but missing from lock"
            )
            continue
        version = locked[name].get("version")
        if not isinstance(version, str) or not _constraint_ok(version, spec):
            diffs.append(
                f"{name}: locked {version!r} does not satisfy {spec!r}"
            )
    return diffs


def check_source(entry: dict, policy: Any) -> bool:
    """Return whether an entry's source matches the locked record.

    ``policy`` may be a single expected URL, a collection of allowed
    URLs, a mapping holding ``source`` / ``sources`` / ``allowed_sources``,
    or a mapping of package name to expected source. Anything unlisted
    fails closed.
    """
    if not isinstance(entry, dict):
        return False
    source = entry.get("source")
    if not isinstance(source, str) or not source:
        return False

    expected: Any = policy
    if isinstance(policy, dict):
        if "source" in policy:
            expected = policy["source"]
        elif "sources" in policy or "allowed_sources" in policy:
            expected = policy.get("sources") or policy.get("allowed_sources")
        else:
            name = entry.get("name")
            expected = policy.get(name) if isinstance(name, str) else None

    if isinstance(expected, str):
        return source == expected
    if isinstance(expected, (list, tuple, set, frozenset)):
        return source in expected
    return False


def validate_lock(lock: dict) -> list[str]:
    """Return structural and integrity problems in a lock document.

    A lock entry is only complete when it has a unique name, an exact
    version, a well-formed content hash and a source.
    """
    issues: list[str] = []
    packages = lock.get("packages", []) if isinstance(lock, dict) else []
    seen: set[str] = set()
    for index, entry in enumerate(packages):
        if not isinstance(entry, dict):
            issues.append(f"entry {index}: not an object")
            continue
        name = entry.get("name")
        if not isinstance(name, str) or not name:
            issues.append(f"entry {index}: missing name")
            continue
        if name in seen:
            issues.append(f"{name}: duplicate package entry")
        seen.add(name)

        version = entry.get("version")
        if not isinstance(version, str) or not version:
            issues.append(f"{name}: missing version")
        elif not check_exact(version):
            issues.append(f"{name}: not an exact version")

        digest = entry.get("hash")
        if not digest:
            issues.append(f"{name}: missing hash")
        elif not _HASH_RE.fullmatch(str(digest)):
            issues.append(f"{name}: invalid hash")

        source = entry.get("source")
        if not isinstance(source, str) or not source:
            issues.append(f"{name}: missing source")
    return issues


def resolve(lock: dict, manifest: dict) -> dict:
    """Resolve a manifest from a lock document without a solver.

    Resolution is deterministic: the same lock and manifest always yield
    the exact same dependency set. Lock/manifest disagreement and any
    floating range are hard errors.
    """
    issues = validate_lock(lock)
    if issues:
        raise ValueError("invalid lock: " + "; ".join(issues))

    floating = [
        f"{name}: floating range {spec!r} is not allowed"
        for name, spec in manifest.items()
        if not check_exact(spec)
    ]
    if floating:
        raise ValueError(
            "manifest contains floating ranges: " + "; ".join(floating)
        )

    diffs = check_coverage(lock, manifest)
    if diffs:
        raise ValueError("lock and manifest disagree: " + "; ".join(diffs))

    resolved: dict[str, dict] = {}
    for entry in lock.get("packages", []):
        name = entry.get("name")
        resolved[name] = dict(entry)
    return resolved


def lock_batch(projects: list) -> dict:
    """Validate and resolve several projects in one call.

    Each project parses and resolves its own lock document: a broken
    project never affects the others, its failure being recorded under
    its own name instead.
    """
    results: dict[str, dict] = {}
    for project in projects or []:
        name = project["name"]
        try:
            parsed = parse_lock(project["lock"])
            results[name] = resolve(parsed, project["manifest"])
        except (ValueError, KeyError, TypeError) as exc:
            results[name] = {"errors": [str(exc)]}
    return results
