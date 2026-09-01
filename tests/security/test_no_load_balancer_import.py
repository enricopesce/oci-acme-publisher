from __future__ import annotations

from pathlib import Path


def test_application_package_never_imports_oci_load_balancer() -> None:
    package = Path("src/oci_acme_publisher")
    forbidden = "oci" + ".load_balancer"
    violations = [
        path for path in package.rglob("*.py") if forbidden in path.read_text(encoding="utf-8")
    ]
    assert violations == []
