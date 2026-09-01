.PHONY: test lint typecheck format-check audit audit-release sbom build quality release-verify rpm-payload-test

test:
	uv run --extra dev coverage run -m pytest
	uv run --extra dev coverage report -m

lint:
	uv run --extra dev ruff check .

typecheck:
	uv run --extra dev mypy --strict src

format-check:
	uv run --extra dev ruff format --check .

audit:
	uv run --extra dev pip-audit --local

# The accepted exception is deliberately scoped to the OCI SDK's current
# cryptography upper bound. See docs/adr/0002-dependency-audit-exceptions.md.
audit-release:
	uv run --extra dev pip-audit --local --ignore-vuln PYSEC-2026-3552

sbom:
	uv run --extra dev cyclonedx-py environment --output-file sbom.json

build:
	uv build

quality: test lint typecheck format-check sbom audit-release build

release-verify:
	scripts/verify-release.sh

rpm-payload-test:
	scripts/test-rpm-payload.sh --package $(RPM)
