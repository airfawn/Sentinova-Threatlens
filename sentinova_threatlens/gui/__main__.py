from __future__ import annotations

import logging
import platform
import sys

from PySide6.QtCore import Qt
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import QApplication

from sentinova_threatlens.config import AppConfig
from sentinova_threatlens.gui import theme
from sentinova_threatlens.gui.main_window import MainWindow
from sentinova_threatlens.gui.splash import SplashWindow
from sentinova_threatlens.gui.widgets.sidebar import logo_pixmap


def _activate_macos(app: QApplication) -> None:
    """Give the app a real Dock identity so its window comes to the foreground."""
    if platform.system() != "Darwin":
        return
    try:
        app.setActivationPolicy(Qt.ApplicationActivationPolicy.Regular)
    except Exception:
        pass


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)-7s %(name)s — %(message)s")

    app = QApplication(sys.argv)
    app.setApplicationName("Sentinova Threatlens")
    app.setOrganizationName("Sentinova")
    app.setWindowIcon(QIcon(logo_pixmap(64)))
    _activate_macos(app)
    theme.apply(app)

    config = AppConfig()
    splash = SplashWindow(config)
    window_holder: list[MainWindow | None] = [None]

    def open_main(stats: dict) -> None:
        window_holder[0] = MainWindow(config, stats)
        window_holder[0].show()
        window_holder[0].raise_()
        window_holder[0].activateWindow()
        splash.close()

    splash.opened.connect(open_main)
    splash.start()
    splash.show()
    splash.raise_()
    splash.activateWindow()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()