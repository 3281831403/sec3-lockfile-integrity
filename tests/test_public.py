import json

from lockint.check import (
    check_coverage,
    check_exact,
    check_hash,
    lock_batch,
    parse_lock,
)


def _entry(name, version, digest="a" * 64, source="https://pypi.org/simple"):
    return {
        "name": name,
        "version": version,
        "hash": "sha256:" + digest,
        "source": source,
    }


def _lock_text(*entries):
    return json.dumps({"packages": list(entries)})


def test_public_parse_lock_preserves_exact_pins():
    lock = parse_lock(_lock_text(_entry("requests", "2.31.0")))

    assert len(lock["packages"]) == 1
    assert lock["packages"][0]["name"] == "requests"
    assert lock["packages"][0]["version"] == "2.31.0"


def test_public_exact_version_rejects_floating_range():
    assert check_exact("1.2.3") is True
    assert check_exact("^1.2.3") is False


def test_public_hash_rejects_same_length_mismatch():
    entry = _entry("alpha", "1.0.0", digest="a" * 64)
    artifact = "sha256:" + "b" * 64

    assert check_hash(entry, artifact) is False


def test_public_coverage_reports_package_missing_from_lock():
    lock = {"packages": [_entry("alpha", "1.0.0")]}
    manifest = {"alpha": "1.0.0", "beta": "2.0.0"}

    diffs = check_coverage(lock, manifest)

    assert any("beta" in diff for diff in diffs)


def test_public_batch_keeps_projects_independent():
    projects = [
        {
            "name": "first",
            "lock": _lock_text(_entry("red", "1.0.0", digest="1" * 64)),
            "manifest": {"red": "1.0.0"},
        },
        {
            "name": "second",
            "lock": _lock_text(_entry("blue", "2.0.0", digest="2" * 64)),
            "manifest": {"blue": "2.0.0"},
        },
    ]

    result = lock_batch(projects)

    assert set(result) == {"first", "second"}
    assert set(result["second"]) == {"blue"}