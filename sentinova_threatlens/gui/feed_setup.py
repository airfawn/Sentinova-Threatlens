from __future__ import annotations

import logging
from dataclasses import replace
from typing import Callable

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
)

from sentinova_threatlens.config import AppConfig, SourceConfig, save_env_values
from sentinova_threatlens.gui import theme

logger = logging.getLogger(__name__)


class FeedSetupDialog(QDialog):
    """Startup feed setup and credential preflight for the current launch."""

    def __init__(self, config: AppConfig, parent: QDialog | None = None) -> None:
        super().__init__(parent)
        self._config = config
        self._fields: dict[str, QLineEdit] = {}
        self._checks: dict[str, QCheckBox] = {}
        self._status: dict[str, QLabel] = {}
        self._tests: dict[str, Callable[[str], tuple[bool, str]]] = {
            "abusech_api_key": self._test_abusech,
            "abuseipdb_api_key": self._test_abuseipdb,
            "greynoise_api_key": self._test_greynoise,
        }
        self.setWindowTitle("Threat feed setup")
        self.setModal(True)
        self.setMinimumWidth(620)
        self._build()

    def _build(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 22, 24, 20)
        root.setSpacing(14)

        title = QLabel("Connect threat intelligence feeds")
        title.setObjectName("PageTitle")
        root.addWidget(title)
        subtitle = QLabel("Configured feeds are checked before ingestion. Missing or failed feeds can be skipped for this launch.")
        subtitle.setObjectName("PageSubtitle")
        subtitle.setWordWrap(True)
        root.addWidget(subtitle)

        group = QGroupBox("Optional provider credentials")
        form = QFormLayout(group)
        form.setContentsMargins(16, 18, 16, 16)
        form.setVerticalSpacing(12)
        self._add_key(form, "abusech_api_key", "Abuse.ch", self._config.sources.abusech_api_key)
        self._add_key(form, "abuseipdb_api_key", "AbuseIPDB", self._config.sources.abuseipdb_api_key)
        self._add_key(form, "greynoise_api_key", "GreyNoise", self._config.sources.greynoise_api_key)
        self._add_key(form, "virustotal_api_key", "VirusTotal enrichment", self._config.sources.virustotal_api_key, required=False)
        root.addWidget(group)

        public = QLabel("Always available when reachable: CISA KEV and OpenPhish. No API key is required.")
        public.setObjectName("CardCaption")
        public.setWordWrap(True)
        root.addWidget(public)

        self._overall = QLabel("Ready to check configured feeds.")
        self._overall.setObjectName("CardCaption")
        root.addWidget(self._overall)

        buttons = QDialogButtonBox()
        test_button = buttons.addButton("Test configured keys", QDialogButtonBox.ActionRole)
        test_button.setProperty("class", "Secondary")
        test_button.clicked.connect(self._test_configured)
        continue_button = buttons.addButton("Continue", QDialogButtonBox.AcceptRole)
        continue_button.setProperty("class", "Primary")
        buttons.rejected.connect(self.reject)
        continue_button.clicked.connect(self._check_and_accept)
        root.addWidget(buttons)

    def _add_key(self, form: QFormLayout, key: str, label: str, value: str, required: bool = True) -> None:
        row = QHBoxLayout()
        field = QLineEdit(value)
        field.setEchoMode(QLineEdit.Password)
        field.setPlaceholderText("Paste API key" if required else "Optional")
        row.addWidget(field, 1)
        status = QLabel("Not checked")
        status.setMinimumWidth(110)
        status.setObjectName("CardCaption")
        row.addWidget(status)
        skip = QCheckBox("Skip")
        row.addWidget(skip)
        form.addRow(label, row)
        self._fields[key] = field
        self._checks[key] = skip
        self._status[key] = status
        field.textChanged.connect(lambda text, field_key=key: self._on_key_changed(field_key, text))
        if not value and required:
            skip.setChecked(True)
            status.setText("Skipped by default")
            status.setStyleSheet(f"color: {theme.WARNING};")

    def _on_key_changed(self, key: str, value: str) -> None:
        if value.strip():
            self._checks[key].setChecked(False)
            self._status[key].setText("Ready to test")
            self._status[key].setStyleSheet(f"color: {theme.ACCENT};")

    def _check_and_accept(self) -> None:
        skipped: list[str] = []
        sources = self._config.sources
        values = {key: field.text().strip() for key, field in self._fields.items()}
        for key in self._tests:
            if self._checks[key].isChecked() or not values[key]:
                skipped.extend(self._source_names(key))
                self._status[key].setText("Skipped")
                self._status[key].setStyleSheet(f"color: {theme.WARNING};")
            save_env_values({
                "ABUSE_CH_API_KEY": values["abusech_api_key"],
                "ABUSEIPDB_API_KEY": values["abuseipdb_api_key"],
                "GREYNOISE_API_KEY": values["greynoise_api_key"],
                "VIRUSTOTAL_API_KEY": values["virustotal_api_key"],
            })
        self._result = replace(self._config, sources=replace(sources, **values), disabled_sources=tuple(sorted(set(skipped))))
        self.accept()

    def _test_configured(self) -> None:
        """Run provider checks only when explicitly requested by the user."""
        values = {key: field.text().strip() for key, field in self._fields.items()}
        checked = 0
        for key, test in self._tests.items():
            if self._checks[key].isChecked() or not values[key]:
                continue
            checked += 1
            fingerprint = values[key][-4:] if len(values[key]) >= 4 else "****"
            self._status[key].setText(f"Testing ···{fingerprint}")
            ok, detail = test(values[key])
            self._status[key].setText("Connected" if ok else f"Failed ({detail})")
            self._status[key].setStyleSheet(f"color: {theme.ONLINE if ok else theme.SEVERITY_CRIT};")
            if not ok:
                self._checks[key].setChecked(True)
        self._overall.setText("No configured keys to test." if not checked else "Test complete. Failed keys were selected to skip.")

    def _source_names(self, key: str) -> list[str]:
        return {
            "abusech_api_key": ["MalwareBazaar", "ThreatFox"],
            "abuseipdb_api_key": ["AbuseIPDB"],
            "greynoise_api_key": ["GreyNoise"],
        }.get(key, [])

    @property
    def result_config(self) -> AppConfig:
        return getattr(self, "_result", self._config)

    @staticmethod
    def _test_abusech(key: str) -> tuple[bool, str]:
        try:
            import requests
            response = requests.post("https://mb-api.abuse.ch/api/v1/", json={"query": "get_recent", "selector": "1", "auth_key": key}, timeout=6)
            data = response.json()
            return data.get("query_status") in {"ok", "no_results"}, f"HTTP {response.status_code}"
        except Exception as exc:
            logger.info("Abuse.ch preflight failed: %s", exc)
            return False, "network or response error"

    @staticmethod
    def _test_abuseipdb(key: str) -> tuple[bool, str]:
        try:
            import requests
            response = requests.get("https://api.abuseipdb.com/api/v2/check", params={"ipAddress": "8.8.8.8", "maxAgeInDays": "90"}, headers={"Key": key, "Accept": "application/json"}, timeout=6)
            return response.status_code == 200, f"HTTP {response.status_code}"
        except Exception as exc:
            logger.info("AbuseIPDB preflight failed: %s", exc)
            return False, "network or response error"

    @staticmethod
    def _test_greynoise(key: str) -> tuple[bool, str]:
        try:
            import requests
            response = requests.get("https://api.greynoise.io/v3/community/8.8.8.8", headers={"key": key, "Accept": "application/json"}, timeout=6)
            return response.status_code == 200, f"HTTP {response.status_code}"
        except Exception as exc:
            logger.info("GreyNoise preflight failed: %s", exc)
            return False, "network or response error"