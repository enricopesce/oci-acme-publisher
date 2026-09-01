from __future__ import annotations

import json
import logging
import sys

from oci_acme_publisher.logging_config import JsonFormatter, configure_json_logging, log_event


def test_json_logging_redacts_pem_and_webhook_url() -> None:
    logger = logging.getLogger("test-logging")
    record = logger.makeRecord(
        logger.name,
        logging.INFO,
        "",
        0,
        "event",
        (),
        None,
        extra={
            "event": "OCI_PROMOTED",
            "event_fields": {
                "detail": "-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----",
                "webhook": "https://hooks.example.invalid/secret",
            },
        },
    )
    rendered = JsonFormatter().format(record)
    payload = json.loads(rendered)
    assert payload["event"] == "OCI_PROMOTED"
    assert "secret" not in rendered
    assert "hooks.example.invalid" not in rendered


def test_json_logging_redacts_nested_fields_and_unsupported_values() -> None:
    logger = logging.getLogger("test-nested-logging")
    record = logger.makeRecord(
        logger.name,
        logging.INFO,
        "",
        0,
        "event",
        (),
        None,
        extra={
            "event": "OCI_PROMOTED",
            "event_fields": {
                "nested": {
                    "certificate": (
                        "-----BEGIN CERTIFICATE-----\\nsecret\\n-----END CERTIFICATE-----"
                    ),
                    "urls": ["https://hooks.example.invalid/secret"],
                },
                "opaque": object(),
            },
        },
    )

    rendered = JsonFormatter().format(record)
    payload = json.loads(rendered)

    assert "secret" not in rendered
    assert "hooks.example.invalid" not in rendered
    assert payload["nested"]["certificate"] == "[REDACTED_PEM]"
    assert payload["opaque"] == "[REDACTED_UNSUPPORTED_VALUE]"


def test_log_event_preserves_operational_fields() -> None:
    logger = logging.getLogger("test-log-event")
    captured: list[logging.LogRecord] = []

    class Capture(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            captured.append(record)

    handler = Capture()
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    try:
        log_event(logger, logging.INFO, "CONFIG_VALIDATED", certificate_id="main-site")
    finally:
        logger.removeHandler(handler)
    assert captured[0].event == "CONFIG_VALIDATED"
    assert captured[0].event_fields == {"certificate_id": "main-site"}


def test_json_formatter_omits_reserved_fields_and_classifies_exception() -> None:
    logger = logging.getLogger("test-log-exception")
    try:
        raise ValueError("untrusted details")
    except ValueError:
        record = logger.makeRecord(
            logger.name,
            logging.ERROR,
            "",
            0,
            "event",
            (),
            sys.exc_info(),
            extra={"event_fields": {"event": "override", "safe": "yes"}},
        )
    payload = json.loads(JsonFormatter().format(record))
    assert payload["error_class"] == "ValueError"
    assert payload["event"] == "test-log-exception"
    assert payload["safe"] == "yes"


def test_configure_json_logging_replaces_existing_root_handlers() -> None:
    root = logging.getLogger()
    original = root.handlers[:]
    try:
        root.addHandler(logging.NullHandler())
        configure_json_logging("WARNING")
        assert len(root.handlers) == 1
        assert isinstance(root.handlers[0].formatter, JsonFormatter)
        assert root.level == logging.WARNING
    finally:
        root.handlers.clear()
        for handler in original:
            root.addHandler(handler)
