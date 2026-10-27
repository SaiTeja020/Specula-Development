"""Verify requirements, requested extras, dependency consistency, and key imports."""

from importlib import import_module, metadata
from pathlib import Path
import subprocess
import sys

from packaging.markers import default_environment
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name


def main() -> int:
    path = Path(__file__).resolve().parents[1] / "requirements.txt"
    roots = [
        Requirement(line.split("#", 1)[0].strip())
        for line in path.read_text(encoding="utf-8-sig").splitlines()
        if line.split("#", 1)[0].strip()
    ]
    environment = default_environment()
    queue = [req for req in roots if not req.marker or req.marker.evaluate(environment)]
    seen = set()
    failures = []
    versions = {}
    while queue:
        req = queue.pop()
        key = (canonicalize_name(req.name), str(req.specifier), tuple(sorted(req.extras)))
        if key in seen:
            continue
        seen.add(key)
        try:
            version = metadata.version(req.name)
        except metadata.PackageNotFoundError:
            failures.append(f"Missing {req}")
            continue
        versions[key[0]] = version
        if not req.specifier.contains(version, prereleases=True):
            failures.append(f"{req.name} {version} does not satisfy {req.specifier}")
        for raw_dependency in metadata.requires(req.name) or []:
            dependency = Requirement(raw_dependency)
            if not dependency.marker or any(
                dependency.marker.evaluate({**environment, "extra": extra})
                for extra in {"", *req.extras}
            ):
                queue.append(dependency)

    print(f"Python {sys.version.split()[0]}: {sys.executable}")
    for req in roots:
        print(f"{req}: {versions.get(canonicalize_name(req.name), 'NOT INSTALLED')}")
    for module in ("dateutil.parser", "google.cloud.logging"):
        try:
            import_module(module)
            print(f"Import {module}: OK")
        except Exception as exc:
            failures.append(f"Import {module} failed: {type(exc).__name__}: {exc}")

    pip_check = subprocess.run(
        [sys.executable, "-m", "pip", "check"], capture_output=True, text=True
    )
    print(pip_check.stdout.strip())
    if pip_check.returncode:
        failures.append(pip_check.stderr.strip() or "pip check returned nonzero")
    if failures:
        for failure in sorted(set(failures)):
            print(f"FAIL: {failure}")
        return 1
    print(f"Verified {len(roots)} requirements and {len(seen)} dependency constraints, including requested extras")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
